import fs from 'node:fs';
import path from 'node:path';

// Append-only JSONL record of every tool call, independent of Termix's own
// audit log. One line per call, rotated by size so the file never grows without
// bound and the deploy needs no external logrotate.
export function createAuditLog({ filePath, maxBytes, maxFiles, maxLineBytes }, logger) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });

  // 0600 from the outset: this file is a transcript of every command the agent
  // ran and every path it touched, so it must not be world-readable. Created
  // explicitly rather than left to the umask, and re-asserted on an existing
  // file so an older permissive log gets tightened on the next start.
  function ensurePrivate() {
    try {
      if (!fs.existsSync(filePath)) {
        fs.closeSync(fs.openSync(filePath, 'a', 0o600));
      }
      const mode = fs.statSync(filePath).mode & 0o777;
      if (mode & 0o077) fs.chmodSync(filePath, 0o600);
    } catch (error) {
      // Windows and some mounted filesystems do not implement POSIX modes;
      // failing to tighten them must not stop the server from auditing.
      logger?.debug({ err: error.message }, 'could not enforce audit log permissions');
    }
  }
  ensurePrivate();

  function rotateIfNeeded() {
    let size = 0;
    try {
      size = fs.statSync(filePath).size;
    } catch {
      return; // no file yet
    }
    if (size < maxBytes) return;
    // audit.jsonl.(n-1) -> audit.jsonl.n, oldest dropped, then current -> .1
    for (let i = maxFiles - 1; i >= 1; i -= 1) {
      const from = i === 1 ? filePath : `${filePath}.${i - 1}`;
      const to = `${filePath}.${i}`;
      try {
        if (fs.existsSync(from)) fs.renameSync(from, to);
      } catch (error) {
        logger?.warn({ from, to, err: error.message }, 'audit rotation step failed');
      }
    }
    ensurePrivate();
  }

  // A single record must never be big enough to matter for rotation: without a
  // ceiling, an agent could push a few oversized call_api bodies through and
  // roll the entire history out of the retained generations -- destroying the
  // trail using nothing but a permitted tool.
  // Overridable because the output log's whole purpose is to carry content, so
  // its ceiling is set from AUDIT_OUTPUT_MAX_RECORD_BYTES instead. The default
  // is what the command trail uses.
  const MAX_LINE_BYTES = maxLineBytes ?? 64 * 1024;

  function serialize(entry) {
    // JSON.stringify escapes newlines, so an agent-supplied filename or command
    // cannot inject a second line and forge a record.
    let line = JSON.stringify(entry);
    if (Buffer.byteLength(line, 'utf8') > MAX_LINE_BYTES) {
      line = JSON.stringify({
        ...entry,
        args: '[dropped: record exceeded the size limit]',
        result: typeof entry.result === 'string' ? entry.result : null,
        oversized: true,
      });
      // Even the reduced form is capped, so a pathological tool name or error
      // string cannot get through either.
      if (Buffer.byteLength(line, 'utf8') > MAX_LINE_BYTES) {
        line = JSON.stringify({
          ts: entry.ts, id: entry.id, tool: entry.tool, ok: entry.ok, oversized: true,
        });
      }
    }
    return line;
  }

  // Never throws: a failed audit write must not take down a tool call, but it
  // must be visible in the app log.
  function record(entry) {
    try {
      rotateIfNeeded();
      // Opened and fsynced per record rather than appendFileSync'd: one line per
      // tool call makes the cost irrelevant, and the record most worth having is
      // the one written immediately before the host reboots or the container is
      // killed -- exactly the one a page cache loses.
      const fd = fs.openSync(filePath, 'a', 0o600);
      try {
        fs.writeSync(fd, `${serialize(entry)}\n`);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
    } catch (error) {
      logger?.error({ err: error.message }, 'failed to write audit record');
    }
  }

  return { record, filePath };
}
