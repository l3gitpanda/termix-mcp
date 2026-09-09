import { createHash } from 'node:crypto';
import { auditId } from '../util/ids.mjs';
import { redactArgs, scrubValue } from '../util/redact.mjs';
import { TermixError } from '../termix/client.mjs';

// The one wrapper every tool passes through. In order it: resolves+blocklist-
// checks the target host, enforces the mutation gate, serializes per host, runs
// the handler, and writes an audit record no matter how the call ends. A new
// tool cannot bypass any of this because registration only happens through here.

// Tool results are unbounded by nature -- a journal, a big directory, a docker
// log tail. Returning all of it can exhaust the model's context with no way for
// it to ask for less, so results are capped and the footer says exactly how to
// get the rest.
function toText(value, maxBytes) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  const limit = Number.isFinite(maxBytes) && maxBytes > 0 ? maxBytes : Infinity;
  if (Buffer.byteLength(text, 'utf8') <= limit) return text;
  // Slice on a character boundary, then report the true byte sizes.
  const kept = Buffer.from(text, 'utf8').subarray(0, limit).toString('utf8');
  const total = Buffer.byteLength(text, 'utf8');
  // Lead with read_file's own offset/limit: it is the only narrowing available
  // to a read-only profile. The advice used to be "grep/tail with run_command",
  // which is a mutating tool such a profile does not have -- so the guidance
  // was unusable by exactly the caller most likely to hit the cap.
  return `${kept}\n\n[truncated: showing ${Buffer.byteLength(kept, 'utf8')} of ${total} bytes. `
    + 'Narrow the request rather than re-running this call -- read_file takes offset/limit '
    + '(negative offset tails), list a deeper path, or lower the log tail. grep/tail via '
    + 'run_command also works where writes are enabled.]';
}

// A compact, secret-free description of what a call did, for the audit log.
function summarize(value) {
  if (value === undefined || value === null) return 'ok';
  if (typeof value === 'string') return `${Buffer.byteLength(value)}B`;
  if (Array.isArray(value)) return `${value.length} items`;
  if (typeof value === 'object') {
    const parts = [];
    if (typeof value.exitCode === 'number') parts.push(`exit=${value.exitCode}`);
    if (Array.isArray(value.files)) parts.push(`${value.files.length} files`);
    if (Array.isArray(value.hosts)) parts.push(`${value.hosts.length} hosts`);
    if (Array.isArray(value.containers)) parts.push(`${value.containers.length} containers`);
    parts.push(`${Buffer.byteLength(JSON.stringify(value))}B`);
    return parts.join(' ');
  }
  return String(value);
}

// For a command result, the audit keeps proof of the output without keeping the
// output: sizes plus a hash, so a transcript can be checked against the record
// later even though the log never becomes a copy of everything the agent read.
function outputDigest(value) {
  if (!value || typeof value !== 'object') return undefined;
  const { stdout, stderr } = value;
  if (typeof stdout !== 'string' && typeof stderr !== 'string') return undefined;
  const digest = (text) => (typeof text === 'string' && text.length
    ? { bytes: Buffer.byteLength(text, 'utf8'), sha256: createHash('sha256').update(text).digest('hex') }
    : null);
  return { stdout: digest(stdout), stderr: digest(stderr) };
}

export function createGate(deps) {
  const {
    hosts, sessions, mutex, audit, outputAudit, wazuh, state, logger, config, transport, profile,
    peer,
  } = deps;

  // The companion record for AUDIT_CAPTURE_OUTPUT. Keyed by the same call id as
  // the main entry, so the two join, and carrying the digest too -- the main
  // log's bytes+sha256 then proves whether this copy was altered afterwards.
  // Deliberately NOT scrubbed: the point is a faithful record of what the agent
  // saw, and a redacted transcript answers "did it read the key?" with a maybe.
  // That is the whole tradeoff -- see config.mjs.
  function recordOutput(entry, value) {
    if (!outputAudit) return;
    const cap = config.auditOutputMaxRecordBytes;
    const clip = (text) => {
      if (typeof text !== 'string' || !text.length) return undefined;
      const bytes = Buffer.byteLength(text, 'utf8');
      if (bytes <= cap) return text;
      return `${Buffer.from(text, 'utf8').subarray(0, cap).toString('utf8')}`
        + `\n[clipped: ${bytes} bytes total, ${cap} recorded]`;
    };

    // stdout/stderr for exec, `content` for a file read, and the serialized
    // result for everything else -- "everything they did", not just commands.
    const payload = {};
    if (value && typeof value === 'object') {
      payload.stdout = clip(value.stdout);
      payload.stderr = clip(value.stderr);
      payload.content = clip(value.content);
      if (!payload.stdout && !payload.stderr && !payload.content) {
        try {
          payload.result = clip(JSON.stringify(value));
        } catch {
          payload.result = '[unserializable]';
        }
      }
    } else if (value !== undefined && value !== null) {
      payload.result = clip(String(value));
    }
    if (!Object.values(payload).some(Boolean)) return;

    outputAudit.record({
      ts: entry.ts,
      id: entry.id,
      tool: entry.tool,
      profile: entry.profile,
      host: entry.host,
      target: entry.target,
      args: entry.args,
      exitCode: entry.exitCode ?? null,
      // Same hashes as the command trail: if this file is edited, they diverge.
      digest: entry.output,
      ...payload,
    });
  }

  function wrap(spec) {
    const {
      name,
      title,
      description,
      inputSchema = {},
      mutating = false,
      hostArg = null,
      // Set when the host argument may be omitted (host_status with no argument
      // reports on everything). The tool still declares hostArg, so a supplied
      // host is resolved and enforced by the gate and lands in the audit record
      // as `target` -- resolving inside the handler instead meant a refused
      // attempt logged target:null and host:null, so a SIEM rule keyed on the
      // host missed exactly the denials worth alerting on.
      hostArgOptional = false,
      // Argument names carrying a remote path, checked against the profile's
      // path rules. Declared per tool so the check lives in the gate rather
      // than being reimplemented (and forgotten) in each file tool.
      pathArgs = [],
      handler,
    } = spec;

    async function wrapped(args = {}) {
      const started = Date.now();
      const id = auditId();
      let host = null;
      let ok = false;
      let errorMessage = null;
      let value;
      let written = false;

      // `mutating` may be a predicate, because a tool like call_api only writes
      // for some arguments. Evaluated once so the gate decision and the audit
      // record can never disagree about what this call was.
      let isMutating;
      try {
        isMutating = typeof mutating === 'function' ? !!mutating(args) : !!mutating;
      } catch {
        isMutating = true; // an unclassifiable call is treated as a write
      }

      // Handlers annotate the record with what they actually touched, so a tool
      // whose host arrives inside the body (call_api) is still attributable.
      const touchedHosts = [];
      const touchedSessions = [];

      const finish = () => {
        // Idempotent: a throw after a successful write must not emit a second,
        // contradictory line under the same id.
        if (written) return;
        written = true;

        // Every read of the handler's return value can throw -- a getter, a
        // custom toJSON, a value too large to stringify. A record is the one
        // thing that must survive that, so the whole build is guarded and falls
        // back to a minimal entry rather than losing the call entirely.
        let entry;
        try {
          const primary = host ?? touchedHosts[0] ?? null;
          entry = {
            ts: new Date(started).toISOString(),
            id,
            transport,
            // Which access profile the call ran under, so the trail answers
            // "who did this", not just "what happened".
            profile: profile?.name ?? null,
            // WHERE it came from. The profile alone cannot separate two holders
            // of one token, so a stolen credential used to read as ordinary
            // activity by its rightful owner. Null on stdio, which has no peer.
            peer: peer?.address ?? null,
            tool: name,
            mutating: isMutating,
            host: primary ? { id: primary.id, name: primary.name, ip: primary.ip } : null,
            // Every host this call touched, for tools that reach more than one
            // or whose host is buried in the body rather than named by hostArg.
            hosts: touchedHosts.length
              ? touchedHosts.map((h) => ({ id: h.id, name: h.name, ip: h.ip }))
              : undefined,
            // What the caller ASKED for, kept even when host resolution failed
            // or the call was refused -- otherwise a denied attempt on a
            // blocklisted host would leave no record of which host was tried.
            target: hostArg ? (args[hostArg] ?? null) : null,
            // The sessions actually used, captured as they were used: reading
            // this afterwards would miss one torn down mid-call, and would
            // record only the second id on the reconnect path.
            usedSessions: touchedSessions.length ? touchedSessions : undefined,
            args: redactArgs(args, config.auditArgMax),
            ok,
            error: errorMessage,
            exitCode: ok && value && typeof value === 'object' ? value.exitCode ?? null : null,
            result: ok ? summarize(value) : null,
            output: ok ? outputDigest(value) : undefined,
            durationMs: Date.now() - started,
            mutationsEnabled: state.mutationsEnabled,
          };
        } catch (error) {
          entry = {
            ts: new Date(started).toISOString(),
            id,
            transport,
            // Which access profile the call ran under, so the trail answers
            // "who did this", not just "what happened".
            profile: profile?.name ?? null,
            peer: peer?.address ?? null,
            tool: name,
            mutating: isMutating,
            host: host ? { id: host.id, name: host.name, ip: host.ip } : null,
            target: hostArg ? String(args[hostArg] ?? '') : null,
            ok,
            error: errorMessage,
            durationMs: Date.now() - started,
            mutationsEnabled: state.mutationsEnabled,
            // The call happened; only the description of it could not be built.
            degraded: `could not summarize result: ${error.message}`,
          };
        }
        audit.record(entry);
        // The command trail first, always. If output capture throws or its file
        // is unwritable, the record of WHAT happened is already durable.
        if (ok) {
          try {
            recordOutput(entry, value);
          } catch (error) {
            logger.error({ tool: name, err: error.message }, 'output audit record failed');
          }
        }
        wazuh?.emit(entry);
      };

      const fail = (message) => {
        ok = false;
        // Termix error text can echo back a value that was submitted, so it is
        // scrubbed and bounded before being written to the log or shipped over
        // syslog. The model still sees the original, which it needs to recover.
        errorMessage = scrubValue(String(message)).slice(0, 500);
        finish();
        return { content: [{ type: 'text', text: message }], isError: true };
      };

      try {
        // 1. Access profile: is this caller allowed to use this tool at all,
        //    and to write at all? Checked before anything else, because a tool
        //    the profile forbids should not even report whether a host exists.
        if (profile && !profile.allowsTool(name)) {
          return fail(
            `The "${profile.name}" access profile does not grant the ${name} tool.`,
          );
        }
        if (isMutating && profile && !profile.allowsMutations()) {
          return fail(
            `The "${profile.name}" access profile is read-only. ${name} changes state, so it is `
            + 'refused; this cannot be lifted with toggle_state.',
          );
        }

        // 2. Mutation gate: a free local check, so a disabled mutation is
        //    refused with an actionable message before any network call. Reads
        //    are never gated and fall straight through.
        if (isMutating && !state.mutationsEnabled) {
          return fail(
            `Mutating tools are disabled. Ask the user for permission, then call `
              + `toggle_state with { enabled: true } to enable writes for this session.`,
          );
        }

        // 3. Path rules, before the host is even resolved.
        if (profile && pathArgs.length) {
          for (const arg of pathArgs) {
            const value = args[arg];
            if (value === undefined || value === null || value === '') continue;
            if (!profile.allowsPath(value)) {
              return fail(
                `The "${profile.name}" access profile does not grant access to ${value} `
                + `(argument "${arg}").`,
              );
            }
          }
        }

        // 4. Resolve + blocklist + profile host rules. Always runs for
        //    host-targeted tools, reads included, and always before the handler
        //    opens any session -- so a forbidden host is never touched
        //    regardless of the mutation flag.
        const hostSupplied = args[hostArg] !== undefined
          && args[hostArg] !== null && args[hostArg] !== '';
        if (hostArg && (hostSupplied || !hostArgOptional)) {
          try {
            host = await hosts.resolveAllowed(args[hostArg]);
          } catch (error) {
            // The message already names the rule that applied and where it
            // lives. Appending a fixed sentence made a blocklist denial say so
            // twice, and made a profile denial claim a blocklist it is not on --
            // sending whoever read it to the wrong config file.
            return fail(
              error.blocked
                ? `Refused: ${error.message}.`
                : `Cannot resolve host: ${error.message}`,
            );
          }
        }

        if (host) touchedHosts.push(host);

        // 3. Run, serialized per host (Termix sessions are stateful).
        //    recordHost/noteSession let a handler report what it reached when
        //    the gate could not know it from the arguments alone.
        const ctx = {
          ...deps,
          host,
          args,
          recordHost: (h) => { if (h && !touchedHosts.some((x) => x.id === h.id)) touchedHosts.push(h); },
          noteSession: (kind, sessionId) => {
            if (sessionId && !touchedSessions.some((s) => s.sessionId === sessionId)) {
              touchedSessions.push({ kind, sessionId });
            }
          },
        };
        const run = () => handler(args, ctx);
        value = host ? await mutex(host.id, run) : await run();

        ok = true;
        const text = toText(value, config.maxOutputBytes);
        finish();
        return { content: [{ type: 'text', text }] };
      } catch (error) {
        const message = error instanceof TermixError
          ? `Termix error (${error.status || 'network'}): ${error.message}`
          : error.message || String(error);
        logger.warn({ tool: name, err: message }, 'tool call failed');
        return fail(message);
      } finally {
        // Last-resort guarantee: no path leaves the gate without a record, even
        // one that throws inside finish() itself on the way out.
        if (!written) {
          try {
            finish();
          } catch (error) {
            logger.error({ tool: name, err: error.message }, 'audit record could not be written');
          }
        }
      }
    }

    // registerTool wants inputSchema as a raw Zod shape (a plain object of Zod
    // types), which is exactly what tool specs declare.
    return {
      name,
      config: { title, description, inputSchema },
      handler: wrapped,
      mutating,
    };
  }

  return { wrap };
}
