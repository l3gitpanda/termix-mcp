import { z } from 'zod';
import path from 'node:path';
import { runScript } from './exec.mjs';
import { hostArg } from './host-arg.mjs';

// Line window for read_file. Applied here rather than on the host because
// Termix's readFile takes no range, so this saves context rather than transfer
// -- which is the point: a read-only profile has no other way to narrow a large
// file, since grep/tail would need run_command, a mutating tool it lacks.
//
// offset is 1-based to match how anyone talks about line numbers; a negative
// offset counts from the end so offset:-50 is a tail.
export function windowLines(content, { offset, limit } = {}) {
  const lines = String(content).split('\n');
  // A file ending in a newline splits to a trailing empty element that is not a
  // line -- `wc -l` does not count it either. Left in, totalLines was one too
  // high and every negative-offset tail spent one of its lines on the phantom,
  // so `offset:-3` returned two real lines.
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop();
  const totalLines = lines.length;
  const start = offset === undefined
    ? 0
    : (offset < 0 ? Math.max(0, totalLines + offset) : Math.max(0, offset - 1));
  const end = limit === undefined ? totalLines : Math.min(totalLines, start + limit);
  return {
    content: lines.slice(start, end).join('\n'),
    windowed: true,
    firstLine: Math.min(start + 1, totalLines),
    lastLine: end,
    totalLines,
  };
}

// A file operation always runs inside the host's file-manager session, so each
// handler is `sessions.withFileSession(host, ...)`. Reads are allowed with
// mutations off; writes are gated.
export function fileTools() {
  return [
    {
      name: 'read_file',
      title: 'Read a file',
      description:
        'Read a file from a Termix host. Returns content, path, and encoding (utf8 or base64 for '
        + 'binary). Use offset/limit to read a window of a large text file instead of the whole '
        + 'thing -- negative offset counts from the end, so offset:-50 is a tail.',
      mutating: false,
      hostArg: 'host',
      pathArgs: ['path'],
      inputSchema: {
        host: hostArg,
        path: z.string().describe('Absolute path on the host'),
        // Windowing is applied here rather than on the host because Termix's
        // readFile has no range parameter. It does not save transfer, but it is
        // the only way a read-only profile can narrow a large file at all: the
        // alternative the truncation footer used to suggest -- grep or tail via
        // run_command -- is a MUTATING tool such a profile does not have.
        offset: z.number().int().optional()
          .describe('First line to return, 1-based. Negative counts from the end (tail).'),
        limit: z.number().int().positive().optional()
          .describe('Maximum number of lines to return, starting at offset.'),
      },
      handler: async (args, ctx) => {
        const result = await ctx.sessions.withFileSession(ctx.host, (s) =>
          ctx.client.get('/ssh/file_manager/ssh/readFile', { sessionId: s.sessionId, path: args.path }));

        if (args.offset === undefined && args.limit === undefined) return result;
        if (!result || typeof result.content !== 'string' || result.encoding === 'base64') {
          // Slicing base64 by line is meaningless; hand back the whole thing
          // rather than a corrupt window.
          return { ...result, windowed: false, note: 'offset/limit ignored: not a text file' };
        }

        return { ...result, ...windowLines(result.content, args) };
      },
    },
    {
      name: 'list_files',
      title: 'List a directory',
      description: 'List files and directories at a path on a Termix host, with type, size, permissions, and owner.',
      mutating: false,
      hostArg: 'host',
      pathArgs: ['path'],
      inputSchema: { host: hostArg, path: z.string().default('.').describe('Directory path on the host') },
      handler: (args, ctx) => ctx.sessions.withFileSession(ctx.host, (s) =>
        ctx.client.get('/ssh/file_manager/ssh/listFiles', { sessionId: s.sessionId, path: args.path })),
    },
    {
      name: 'get_file_info',
      title: 'Stat a path',
      description:
        'Return metadata for a single path (type, size, permissions, owner, symlink target) by listing its '
        + 'parent directory. Read-only.',
      mutating: false,
      hostArg: 'host',
      pathArgs: ['path'],
      inputSchema: { host: hostArg, path: z.string().describe('Absolute path on the host') },
      handler: async (args, ctx) => ctx.sessions.withFileSession(ctx.host, async (s) => {
        const target = args.path.replace(/\/+$/, '') || '/';
        const parent = path.posix.dirname(target);
        const base = path.posix.basename(target);
        const listing = await ctx.client.get('/ssh/file_manager/ssh/listFiles', {
          sessionId: s.sessionId,
          path: parent,
        });
        const entry = (listing?.files ?? []).find((f) => f.name === base);
        if (!entry) throw new Error(`no such path: ${args.path}`);
        return entry;
      }),
    },
    {
      name: 'find_file',
      title: 'Find files by name',
      description:
        'Search for files under a directory on a Termix host using the shell `find` command. Returns matching '
        + 'paths. Counts as a mutating tool despite only searching, because it is implemented over the '
        + 'command-execution path: it writes a temporary script to the host, runs it, and deletes it.',
      // NOT read-only. The search itself changes nothing, but reaching it means
      // writing and executing a file on the host -- so classifying this false
      // would let it through the gate with writes disabled AND stamp the audit
      // record `mutating:false` for a call that did write to the host.
      mutating: true,
      hostArg: 'host',
      pathArgs: ['root'],
      inputSchema: {
        host: hostArg,
        root: z.string().default('.').describe('Directory to search under'),
        name: z.string().describe('Filename glob to match, e.g. "*.conf"'),
        maxDepth: z.number().int().positive().max(20).default(6).describe('Maximum recursion depth'),
      },
      handler: async (args, ctx) => {
        // Single-quote the inputs so a name or root cannot break out of the find
        // invocation. Embedded single quotes are escaped the POSIX way.
        const q = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
        const cmd = `find ${q(args.root)} -maxdepth ${args.maxDepth} -name ${q(args.name)} 2>/dev/null`;
        const result = await runScript(ctx, ctx.host, cmd);
        const matches = result.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
        return { matches, count: matches.length, exitCode: result.exitCode };
      },
    },
    {
      name: 'write_file',
      title: 'Write a file',
      description:
        'Write (create or overwrite) a file on a Termix host. An EXISTING file keeps its '
        + 'permissions (verified: a 0600 file stays 0600 through a rewrite). A NEW file is '
        + 'created by Termix as 0666 regardless of the host umask, which is world-writable -- '
        + 'so for anything sensitive, follow the write with change_permissions, or use '
        + 'create_file, which lands at 0644.',
      mutating: true,
      hostArg: 'host',
      pathArgs: ['path'],
      inputSchema: { host: hostArg, path: z.string(), content: z.string() },
      handler: (args, ctx) => ctx.sessions.withFileSession(ctx.host, (s) =>
        ctx.client.post('/ssh/file_manager/ssh/writeFile', {
          sessionId: s.sessionId, path: args.path, content: args.content,
        })),
    },
    {
      name: 'create_file',
      title: 'Create an empty file',
      description: 'Create a new empty file in a directory on a Termix host.',
      mutating: true,
      hostArg: 'host',
      pathArgs: ['path'],
      inputSchema: {
        host: hostArg,
        path: z.string().describe('Directory to create the file in'),
        fileName: z.string().describe('Name of the new file'),
      },
      handler: (args, ctx) => ctx.sessions.withFileSession(ctx.host, (s) =>
        ctx.client.post('/ssh/file_manager/ssh/createFile', {
          sessionId: s.sessionId, path: args.path, fileName: args.fileName,
        })),
    },
    {
      name: 'create_directory',
      title: 'Create a directory',
      description: 'Create a new folder in a directory on a Termix host.',
      mutating: true,
      hostArg: 'host',
      pathArgs: ['path'],
      inputSchema: {
        host: hostArg,
        path: z.string().describe('Parent directory'),
        folderName: z.string().describe('Name of the new folder'),
      },
      handler: (args, ctx) => ctx.sessions.withFileSession(ctx.host, (s) =>
        ctx.client.post('/ssh/file_manager/ssh/createFolder', {
          sessionId: s.sessionId, path: args.path, folderName: args.folderName,
        })),
    },
    {
      name: 'delete_item',
      title: 'Delete a file or directory',
      description:
        'Delete a file or directory on a Termix host. Set isDirectory true to remove a directory '
        + '-- which removes EVERYTHING INSIDE IT, recursively and without confirmation, like '
        + '`rm -rf`. It does not fail on a non-empty directory. Verify the contents with '
        + 'list_files first if you did not create the directory yourself. Deletion is permanent '
        + 'by default; pass permanent false to move the item to Termix\'s trash instead, where it '
        + 'can be restored until the retention window expires.',
      mutating: true,
      hostArg: 'host',
      pathArgs: ['path'],
      inputSchema: {
        host: hostArg,
        path: z.string(),
        isDirectory: z.boolean().default(false),
        // Defaulted true to keep this tool meaning what its name and every
        // prior release said it means. Termix 2.7.0 flipped the server-side
        // default the other way: an omitted `permanent` now moves the item to
        // ~/.termix-trash rather than deleting it, so leaving this unset would
        // have silently turned delete_item into "move to trash" -- freeing no
        // space, and erroring outright (409 trashUnavailable) on hosts where
        // the trash directory cannot be created or the rename crosses a
        // filesystem. Ignored by 2.6.x, which never reads the field.
        permanent: z.boolean().default(true).describe(
          'Delete outright (default). False moves the item to Termix\'s trash on hosts '
          + 'running 2.7.0 or later, and is ignored by older versions, which always delete.',
        ),
      },
      handler: (args, ctx) => ctx.sessions.withFileSession(ctx.host, (s) =>
        ctx.client.del('/ssh/file_manager/ssh/deleteItem', {
          sessionId: s.sessionId,
          path: args.path,
          isDirectory: args.isDirectory,
          permanent: args.permanent,
        })),
    },
    {
      name: 'move_item',
      title: 'Move or rename',
      description: 'Move or rename a file or directory on a Termix host by giving its old and new absolute paths.',
      mutating: true,
      hostArg: 'host',
      pathArgs: ['oldPath', 'newPath'],
      inputSchema: { host: hostArg, oldPath: z.string(), newPath: z.string() },
      handler: (args, ctx) => ctx.sessions.withFileSession(ctx.host, (s) =>
        ctx.client.put('/ssh/file_manager/ssh/moveItem', {
          sessionId: s.sessionId, oldPath: args.oldPath, newPath: args.newPath,
        })),
    },
    {
      name: 'copy_item',
      title: 'Copy a file or directory',
      description:
        'Copy a file or directory on a Termix host into a target directory. Termix names the copy '
        + 'itself and ALWAYS suffixes it ("notes.txt" becomes "notes.txt_copy_34176704") even when '
        + 'nothing collides, so read the destination out of the result rather than predicting it -- '
        + 'a follow-up call assuming the original name will not find the file.',
      mutating: true,
      hostArg: 'host',
      pathArgs: ['sourcePath', 'targetDir'],
      inputSchema: {
        host: hostArg,
        sourcePath: z.string(),
        targetDir: z.string().describe('Directory to copy into'),
      },
      handler: (args, ctx) => ctx.sessions.withFileSession(ctx.host, (s) =>
        ctx.client.post('/ssh/file_manager/ssh/copyItem', {
          sessionId: s.sessionId, sourcePath: args.sourcePath, targetDir: args.targetDir, hostId: ctx.host.id,
        })),
    },
    {
      name: 'change_permissions',
      title: 'Change permissions',
      description: 'Change the mode of a file or directory on a Termix host, e.g. "644" or "755".',
      mutating: true,
      hostArg: 'host',
      pathArgs: ['path'],
      inputSchema: {
        host: hostArg,
        path: z.string(),
        permissions: z.string().regex(/^[0-7]{3,4}$/).describe('Octal mode, e.g. 644'),
      },
      handler: (args, ctx) => ctx.sessions.withFileSession(ctx.host, (s) =>
        ctx.client.post('/ssh/file_manager/ssh/changePermissions', {
          sessionId: s.sessionId, path: args.path, permissions: args.permissions,
        })),
    },
  ];
}
