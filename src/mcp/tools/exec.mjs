import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { hostArg } from './host-arg.mjs';

// run_command has no native endpoint in Termix: the file manager can write,
// chmod, and execute a file and it DOES return the captured output, so a
// command becomes a temporary script that is written, made executable
// (executeFile runs `test -x` first and 400s otherwise), executed, and deleted.
//
// Exported so find_file can reuse the exact same mechanism.
// Termix's executeFile does not report the SCRIPT's exit status. It returns
// exitCode 0 for the API call itself, merges the script's stderr into `output`,
// and appends the script's real status as a trailing "EXIT_CODE:N" line. Taken
// at face value every failed command reads as a success -- which fails in the
// unsafe direction -- stderr is always empty, and find_file, which splits
// stdout into matches, collected "EXIT_CODE:0" as a filesystem path.
//
// So the wrapper redirects the two streams to files and prints the status and
// both streams back with delimiters. The delimiter carries a per-invocation
// nonce, so a command whose own output contains a marker cannot forge one.
export function buildWrappedScript({ script, shebang, outPath, errPath, nonce }) {
  // pipefail is a bash/ksh/zsh feature -- dash, which is /bin/sh on Debian,
  // exits immediately on `set -o pipefail`, which would fail every command.
  const wantsPipefail = /bash|zsh|ksh/.test(shebang);
  return [
    shebang,
    ...(wantsPipefail ? ['set -o pipefail'] : []),
    // The capture files hold whatever the command printed, which may be a
    // secret, and /tmp is world-readable -- the same reasoning that puts the
    // script itself at 700. Create them under a tightened umask, then restore
    // it so files the COMMAND creates keep the host's normal permissions.
    '__tmcp_um=$(umask)',
    'umask 077',
    `: > '${outPath}'`,
    `: > '${errPath}'`,
    'umask "$__tmcp_um"',
    // KNOWN GAP: TERMIX_EXEC_TIMEOUT_MS bounds the HTTP call, not the remote
    // process. A command that outlives the request keeps running on the host,
    // unreaped, with its output discarded. Wrapping the body in `timeout` is
    // the fix, but it means re-invoking the script through another shell to
    // give `timeout` a command to hold -- which changes what interpreter the
    // body runs under and how pipefail applies. Not attempted blind; it wants a
    // live test. Temp-file cleanup on the timeout path is already correct.
    //
    // A SUBSHELL, not a brace group. A brace group runs in the current shell,
    // so an explicit `exit N` anywhere in the command terminated the whole
    // script before the trailer -- and since both streams were already
    // redirected into the capture files, every byte the command printed was
    // lost and the status came back null. In a subshell, `exit` leaves only
    // the subshell and $? picks it up.
    '(',
    script,
    `) > '${outPath}' 2> '${errPath}'`,
    '__tmcp_rc=$?',
    // rc first: if the shell dies partway through the trailer, it still arrived.
    `printf '%s\\n' "${nonce} rc=$__tmcp_rc"`,
    `printf '%s\\n' '${nonce} stdout'`,
    `cat '${outPath}'`,
    // Leading newline on the closing marker so a stream that does not end in a
    // newline cannot glue its last line onto the delimiter. The parser strips
    // the one newline this adds.
    `printf '\\n%s\\n' '${nonce} stderr'`,
    `cat '${errPath}'`,
    // A closing delimiter, so the end of stderr is MARKED rather than inferred.
    // Without it the parser had to strip Termix's trailing EXIT_CODE line off
    // the tail of stderr, and the newline before that line is only present when
    // stderr is non-empty -- so a pattern loose enough for the empty case ate a
    // real trailing newline the command had written. Now the trailer falls
    // outside the captured region entirely and nothing needs stripping.
    `printf '\\n%s\\n' '${nonce} end'`,
    // No `rm` here: cleanup belongs in the caller's finally, which runs however
    // the script ended. An in-script rm is skipped by exactly the paths that
    // leave secret-bearing files behind.
    '',
  ].join('\n');
}

// Returns null when the markers are absent -- a shell too broken to reach the
// trailer, say -- so the caller can fall back rather than fail the whole tool.
export function parseWrappedOutput(raw, nonce) {
  const text = String(raw ?? '');
  const rc = text.match(new RegExp(`^${nonce} rc=(-?\\d+)$`, 'm'));
  const outMark = `${nonce} stdout\n`;
  const errMark = `\n${nonce} stderr\n`;
  const endMark = `\n${nonce} end\n`;
  const outAt = text.indexOf(outMark);
  const errAt = text.indexOf(errMark);
  const endAt = text.indexOf(endMark);
  if (!rc || outAt === -1 || errAt === -1 || errAt < outAt) return null;

  // Both streams are bounded by markers the wrapper printed, so each slice is
  // exact and Termix's trailing EXIT_CODE line falls outside the captured
  // region. Nothing is stripped, which is what matters: the previous version
  // inferred the end of stderr and had to guess whether a trailing newline
  // belonged to the command or to the trailer -- and guessed wrong in the
  // common case, silently eating a newline the command really wrote.
  //
  // endAt === -1 means an older wrapper (a script written before this change,
  // still executing) or a shell that died before the last printf; fall back to
  // the end of the text rather than losing stderr altogether.
  const stderrEnd = endAt === -1 ? undefined : endAt;
  const stderrRaw = text.slice(errAt + errMark.length, stderrEnd);
  return {
    exitCode: Number(rc[1]),
    stdout: text.slice(outAt + outMark.length, errAt),
    stderr: endAt === -1
      ? stderrRaw.replace(/(?:\r?\n)?EXIT_CODE:-?\d+\s*$/, '')
      : stderrRaw,
  };
}

export async function runScript(ctx, host, script) {
  const { client, sessions, config } = ctx;
  const id = randomUUID();
  const remotePath = `${config.tmpDir}/.termix-mcp-${id}.sh`;
  const outPath = `${config.tmpDir}/.termix-mcp-${id}.out`;
  const errPath = `${config.tmpDir}/.termix-mcp-${id}.err`;
  const nonce = `__TERMIX_MCP_${id.replace(/-/g, '')}__`;
  const body = buildWrappedScript({
    script, shebang: config.execShebang, outPath, errPath, nonce,
  });

  return sessions.withFileSession(host, async (session) => {
    const { sessionId } = session;
    // Recorded as it is used, not read back afterwards: on the reconnect path
    // the first session is gone by the time the record is written, and it is
    // the one that actually ran against the host.
    ctx.noteSession?.('file', sessionId);
    try {
      await client.post('/ssh/file_manager/ssh/writeFile', {
        sessionId,
        path: remotePath,
        content: body,
      });
      // 700, not 755: the script body is the command, which may carry a secret,
      // and /tmp is world-readable. executeFile only needs the owner's x bit.
      await client.post('/ssh/file_manager/ssh/changePermissions', {
        sessionId,
        path: remotePath,
        permissions: '700',
      });
      // The only call in the server that gets the long timeout: this one waits
      // on the command itself, while writeFile and changePermissions above are
      // ordinary metadata round trips.
      const result = await client.post('/ssh/file_manager/ssh/executeFile', {
        sessionId,
        filePath: remotePath,
      }, { timeoutMs: config.execTimeoutMs });
      const parsed = parseWrappedOutput(result?.output, nonce);
      if (parsed) return parsed;

      // No markers: the wrapper did not reach its trailer. Report what Termix
      // gave us, but with a null exitCode rather than its meaningless 0 -- an
      // unknown status must not read as success.
      ctx.logger?.warn(
        { host: host?.name ?? host?.id },
        'run_command trailer missing; exit status unavailable',
      );
      return {
        exitCode: null,
        stdout: String(result?.output ?? '').replace(/(?:\r?\n)?EXIT_CODE:-?\d+\s*$/, ''),
        stderr: result?.error ?? '',
        note: 'exit status could not be determined; treat a null exitCode as unknown, not success',
      };
    } finally {
      // The script AND both capture files, however the script ended -- the
      // capture files hold the command's output, so leaving them behind leaves
      // whatever it printed sitting in /tmp. Concurrent so three deletes cost
      // one round trip, and best-effort: a leaked temp file is noise, not a
      // failure, and one already removed by a retry must not mask the others.
      //
      // `permanent` is REQUIRED, not cosmetic. From Termix 2.7.0 deleteItem
      // defaults to moving the item to ~/.termix-trash instead of removing it,
      // which would park the command's captured output -- the thing the umask
      // 077 above exists to protect -- in the SSH user's home for the trash
      // retention window (7 days by default), on every host, for every command.
      // Where /tmp is a tmpfs the trash move is a cross-device rename that
      // fails outright, so the files would simply never be cleaned up at all.
      // Harmless on 2.6.x, which destructures only sessionId/path/isDirectory
      // and ignores the field.
      await Promise.allSettled(
        [remotePath, outPath, errPath].map((p) => client
          .del('/ssh/file_manager/ssh/deleteItem', {
            sessionId, path: p, isDirectory: false, permanent: true,
          })
          .catch((error) => {
            ctx.logger.debug({ path: p, err: error.message }, 'temp file cleanup failed');
          })),
      );
    }
  });
}

export function execTools() {
  return [
    {
      name: 'run_command',
      title: 'Run a shell command',
      description:
        'Run a shell command on a Termix host and return its exit code, stdout, and stderr. '
        + 'Implemented by writing a temporary script to the host, executing it, and deleting it, '
        + 'so it runs in a non-login shell with a minimal environment -- set any needed variables '
        + 'explicitly. The host is identified by numeric id or by name.',
      mutating: true,
      hostArg: 'host',
      inputSchema: {
        host: hostArg,
        command: z.string().describe('The shell command to run'),
      },
      handler: async (args, ctx) => {
        const result = await runScript(ctx, ctx.host, args.command);
        return { host: ctx.host.name || String(ctx.host.id), ...result };
      },
    },
    {
      name: 'run_snippet',
      title: 'Run a saved snippet',
      description:
        'Execute a saved Termix snippet on a host. Fire-and-forget: Termix runs the snippet in a '
        + 'terminal session and does NOT return its output. Use run_command when you need the output.',
      mutating: true,
      hostArg: 'host',
      inputSchema: {
        host: hostArg,
        snippetId: z.number().describe('Snippet id (from list_snippets)'),
      },
      handler: async (args, ctx) => {
        await ctx.client.post('/snippets/execute', {
          snippetId: args.snippetId,
          hostId: ctx.host.id,
        });
        return { ok: true, note: 'snippet dispatched; Termix does not return snippet output' };
      },
    },
  ];
}
