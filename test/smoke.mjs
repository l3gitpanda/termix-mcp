import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { redactArgs, redactContainerDetails } from '../src/util/redact.mjs';
import { dockerTools } from '../src/mcp/tools/docker.mjs';
import { observabilityTools } from '../src/mcp/tools/observability.mjs';
import { policyTools, readPolicyFile } from '../src/mcp/tools/policy.mjs';
import { createKeyedMutex } from '../src/util/lock.mjs';
import { createHostRegistry } from '../src/termix/hosts.mjs';
import { createAuditLog } from '../src/audit.mjs';
import { createClient, TermixError } from '../src/termix/client.mjs';
import { createGate } from '../src/mcp/gate.mjs';
import { buildSyslogLine } from '../src/wazuh.mjs';
import { loadConfig } from '../src/config.mjs';
import { extractRelease, listVersions, buildReleaseBody } from '../src/changelog.mjs';
import { buildWrappedScript, parseWrappedOutput } from '../src/mcp/tools/exec.mjs';
import {
  canonicalizePath, checkForbidden, extractHostIds, extractSessionId,
} from '../src/termix/api-policy.mjs';

const silentLog = { info() {}, warn() {}, debug() {}, error() {} };

// --- redaction ------------------------------------------------------------
test('redactArgs removes secrets and truncates bulk fields with a hash', () => {
  const out = redactArgs(
    { host: 'web', password: 'hunter2', sshKey: 'PRIVATE', content: 'x'.repeat(1000) },
    64,
  );
  assert.equal(out.host, 'web');
  assert.equal(out.password, '[redacted]');
  assert.equal(out.sshKey, '[redacted]');
  assert.equal(typeof out.content, 'object');
  assert.equal(out.content.bytes, 1000);
  assert.match(out.content.sha256, /^[a-f0-9]{64}$/);
  // No preview for a file body, at any size -- see the next test.
  assert.equal(out.content.preview, undefined);
});

test('a SHORT file body is hashed too, because size is the wrong control for it', () => {
  // The size cap protects against bulk, not against secrets: a .env or a private
  // key written through write_file is small, and it used to land verbatim in
  // audit.jsonl -- which is bind-mounted for Wazuh, so it left the host as well.
  const secret = 'DISCORD_TOKEN=abc123\n';
  const out = redactArgs({ path: '/opt/app/.env', content: secret }, 4096);

  assert.equal(out.path, '/opt/app/.env', 'the path still says what was touched');
  assert.equal(typeof out.content, 'object', 'body is never kept verbatim');
  assert.equal(out.content.bytes, Buffer.byteLength(secret));
  assert.ok(!JSON.stringify(out).includes('abc123'), 'the secret must not appear anywhere');
  // Still provable: the hash matches a copy you hold.
  assert.match(out.content.sha256, /^[a-f0-9]{64}$/);
});

test('redactArgs leaves an empty/absent secret as null, never the string', () => {
  const out = redactArgs({ password: '' });
  assert.equal(out.password, null);
});

test('redactArgs covers every secret-bearing field name Termix actually uses', () => {
  const out = redactArgs({
    sudoPassword: 's', keyPassword: 'k', privateKey: 'p', key: 'k2',
    passphrase: 'x', apiKey: 'a', token: 't', secret: 'z', totpCode: '123456',
  }, 512);
  for (const [field, value] of Object.entries(out)) {
    assert.equal(value, '[redacted]', `${field} must be redacted`);
  }
});

// --- blocklist ------------------------------------------------------------
function fakeClient(hosts) {
  return {
    get: async (p) => {
      if (p === '/host/db/host') return hosts;
      const m = /\/host\/db\/host\/(\d+)/.exec(p);
      if (m) return hosts.find((h) => String(h.id) === m[1]) ?? null;
      throw new TermixError({ status: 404, message: 'not found', method: 'GET', path: p });
    },
  };
}

test('blocklist matches name or IP exactly, case-insensitively, not by substring', async () => {
  const hosts = [
    { id: 1, name: 'app', ip: '10.0.0.14' },
    { id: 2, name: 'app-main', ip: '10.0.0.10' },
    { id: 3, name: 'web', ip: '10.0.0.104' },
  ];
  const reg = createHostRegistry(fakeClient(hosts), ['app', '10.0.0.104'], silentLog);
  const all = await reg.list();
  assert.equal(reg.isBlocked(all[0]), true, 'app blocked by name');
  assert.equal(reg.isBlocked(all[1]), false, 'app-main NOT blocked (no substring match)');
  assert.equal(reg.isBlocked(all[2]), true, 'web blocked by IP');
});

test('resolveAllowed throws a blocked error for a blocklisted host', async () => {
  const hosts = [{ id: 1, name: 'legacy-box', ip: '10.0.0.9' }];
  const reg = createHostRegistry(fakeClient(hosts), ['legacy-box'], silentLog);
  await assert.rejects(() => reg.resolveAllowed('legacy-box'), (e) => e.blocked === true);
});

test('resolve accepts a numeric id and a name', async () => {
  const hosts = [{ id: 7, name: 'web', ip: '10.0.0.1', port: 22, username: 'root' }];
  const reg = createHostRegistry(fakeClient(hosts), [], silentLog);
  assert.equal((await reg.resolve(7)).name, 'web');
  assert.equal((await reg.resolve('web')).id, 7);
});

// --- keyed mutex ----------------------------------------------------------
test('keyed mutex serializes the same key and parallelizes different keys', async () => {
  const mutex = createKeyedMutex();
  const order = [];
  const slow = (label, ms) => mutex('A', async () => {
    order.push(`${label}-start`);
    await new Promise((r) => setTimeout(r, ms));
    order.push(`${label}-end`);
  });
  await Promise.all([slow('a', 20), slow('b', 1)]);
  // b must not start until a ends, because they share key A.
  assert.deepEqual(order, ['a-start', 'a-end', 'b-start', 'b-end']);
});

// --- audit rotation -------------------------------------------------------
test('an oversized record cannot be used to rotate the history away', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'termix-audit-big-'));
  const filePath = path.join(dir, 'audit.jsonl');
  const audit = createAuditLog({ filePath, maxBytes: 10 * 1024 * 1024, maxFiles: 3 }, silentLog);
  // A 4 MB argument blob, the size an HTTP request body is allowed to be.
  audit.record({ ts: 'now', id: 'x', tool: 'call_api', ok: true, args: { blob: 'A'.repeat(4 * 1024 * 1024) } });
  const written = fs.statSync(filePath).size;
  assert.ok(written < 128 * 1024, `record was capped, got ${written} bytes`);
  const entry = JSON.parse(fs.readFileSync(filePath, 'utf8').trim());
  assert.equal(entry.oversized, true);
  assert.equal(entry.tool, 'call_api', 'identity survives the reduction');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('audit log rotates when it exceeds maxBytes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'termix-audit-'));
  const filePath = path.join(dir, 'audit.jsonl');
  const audit = createAuditLog({ filePath, maxBytes: 200, maxFiles: 3 }, silentLog);
  for (let i = 0; i < 20; i += 1) audit.record({ i, pad: 'x'.repeat(50) });
  assert.ok(fs.existsSync(filePath), 'current file exists');
  assert.ok(fs.existsSync(`${filePath}.1`), 'rotated file .1 exists');
  // Every line that exists is valid JSON.
  const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n').filter(Boolean);
  for (const l of lines) JSON.parse(l);
  fs.rmSync(dir, { recursive: true, force: true });
});

// --- client error normalization + retry -----------------------------------
test('client normalizes a JSON error envelope into a TermixError', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ error: 'File is not executable' }), {
    status: 400, headers: { 'Content-Type': 'application/json' },
  });
  try {
    const client = createClient(
      { baseUrl: 'http://x', serviceUrls: {}, apiKey: 'k', timeoutMs: 1000, retry: 0 }, silentLog,
    );
    await assert.rejects(() => client.get('/anything'), (e) => e instanceof TermixError
      && e.status === 400 && e.message === 'File is not executable');
  } finally {
    globalThis.fetch = original;
  }
});

test('client retries a GET on 503 then succeeds', async () => {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    if (calls < 2) return new Response('', { status: 503 });
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    const client = createClient(
      { baseUrl: 'http://x', serviceUrls: {}, apiKey: 'k', timeoutMs: 1000, retry: 2 }, silentLog,
    );
    const res = await client.get('/thing');
    assert.deepEqual(res, { ok: true });
    assert.equal(calls, 2);
  } finally {
    globalThis.fetch = original;
  }
});

test('client routes file-manager paths to the FILES override when set', () => {
  const client = createClient(
    { baseUrl: 'http://base', serviceUrls: { files: 'http://files' }, apiKey: 'k', timeoutMs: 1, retry: 0 },
    silentLog,
  );
  assert.equal(client.urlFor('/ssh/file_manager/ssh/readFile'), 'http://files/ssh/file_manager/ssh/readFile');
  assert.equal(client.urlFor('/host/db/host'), 'http://base/host/db/host');
});

// --- gate: mutation flag + blocklist + audit ------------------------------
function gateHarness({ mutationsEnabled = false, captureOutput = false } = {}) {
  const records = [];
  const outputRecords = [];
  const state = { mutationsEnabled, capabilities: {} };
  const hosts = {
    resolveAllowed: async (ref) => {
      // Throw what resolveAllowed really throws, message and all. A bare
      // 'blocked' let this fake pass only because the gate used to append a
      // fixed "on the configured blocklist" sentence to every denial -- the
      // same sentence that made profile denials claim a blocklist they were
      // not on. Assert against the real text, not a stand-in.
      if (String(ref) === 'blocked') {
        const e = new Error(`host ${ref} is on the blocklist and cannot be accessed`);
        e.blocked = true;
        e.reason = 'blocklist';
        throw e;
      }
      if (String(ref) === 'notinprofile') {
        const e = new Error(`host ${ref} is not granted to the "ops" access profile`);
        e.blocked = true;
        e.reason = 'profile';
        throw e;
      }
      return { id: 1, name: String(ref), ip: '10.0.0.1' };
    },
  };
  const deps = {
    hosts,
    mutex: createKeyedMutex(),
    audit: { record: (e) => records.push(e) },
    outputAudit: captureOutput ? { record: (e) => outputRecords.push(e) } : null,
    wazuh: null,
    state,
    logger: silentLog,
    config: {
      auditArgMax: 512,
      maxOutputBytes: 2048,
      allowToggle: false,
      auditOutputMaxRecordBytes: 64,
    },
    transport: 'test',
  };
  return {
    gate: createGate(deps), records, outputRecords, state,
  };
}

test('gate refuses a mutating tool while mutations are disabled, and audits it', async () => {
  const { gate, records } = gateHarness({ mutationsEnabled: false });
  const { handler } = gate.wrap({
    name: 'write_thing', mutating: true, hostArg: 'host', inputSchema: {},
    handler: async () => ({ wrote: true }),
  });
  const res = await handler({ host: 'web' });
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /disabled/);
  assert.equal(records.at(-1).ok, false);
  assert.equal(records.at(-1).tool, 'write_thing');
});

test('gate allows a mutating tool once mutations are enabled', async () => {
  const { gate, state, records } = gateHarness({ mutationsEnabled: true });
  const { handler } = gate.wrap({
    name: 'write_thing', mutating: true, hostArg: 'host', inputSchema: {},
    handler: async () => ({ wrote: true }),
  });
  const res = await handler({ host: 'web' });
  assert.ok(!res.isError);
  assert.equal(records.at(-1).ok, true);
  assert.equal(records.at(-1).host.name, 'web');
  assert.equal(state.mutationsEnabled, true);
});

test('gate refuses any operation on a blocklisted host, read or write', async () => {
  const { gate } = gateHarness({ mutationsEnabled: true });
  const { handler } = gate.wrap({
    name: 'read_thing', mutating: false, hostArg: 'host', inputSchema: {},
    handler: async () => ({ ok: true }),
  });
  const res = await handler({ host: 'blocked' });
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /blocklist/);
  // Said once. It used to appear twice: the message names the rule, and the
  // gate appended a second sentence saying the same thing.
  assert.equal(res.content[0].text.match(/blocklist/g).length, 1);
});

test('a profile denial does not claim the host is blocklisted', async () => {
  // These live in different config -- TERMIX_BLOCKLIST in the environment
  // versus the policy file -- so conflating them sends whoever reads the
  // refusal to the wrong place to fix it.
  const { gate } = gateHarness({ mutationsEnabled: true });
  const { handler } = gate.wrap({
    name: 'read_thing', mutating: false, hostArg: 'host', inputSchema: {},
    handler: async () => ({ ok: true }),
  });
  const res = await handler({ host: 'notinprofile' });
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /access profile/);
  assert.ok(!/blocklist/.test(res.content[0].text), 'must not mention a blocklist it is not on');
});

test('a read-only pin cannot be lifted at runtime, but writes can still be locked', async () => {
  const { gate, state } = gateHarness({ mutationsEnabled: false });
  const { handler } = gate.wrap({
    name: 'toggle_state', mutating: false, hostArg: null, inputSchema: {},
    handler: (args, ctx) => {
      if (args.enabled && !ctx.config.allowToggle) throw new Error('pinned read-only');
      ctx.state.mutationsEnabled = args.enabled;
      return { mutationsEnabled: ctx.state.mutationsEnabled };
    },
  });
  const res = await handler({ enabled: true });
  assert.equal(res.isError, true, 'enabling writes is refused when pinned');
  assert.equal(state.mutationsEnabled, false, 'and the flag did not move');

  // Locking back down must always work, pin or not.
  state.mutationsEnabled = true;
  await handler({ enabled: false });
  assert.equal(state.mutationsEnabled, false);
});

test('gate redacts secrets in the audit record', async () => {
  const { gate, records } = gateHarness({ mutationsEnabled: true });
  const { handler } = gate.wrap({
    name: 'connect', mutating: true, hostArg: null, inputSchema: {},
    handler: async () => ({ ok: true }),
  });
  await handler({ password: 'hunter2' });
  assert.equal(records.at(-1).args.password, '[redacted]');
});

test('a mutating predicate is evaluated per call and recorded, not assumed', async () => {
  const { gate, records } = gateHarness({ mutationsEnabled: false });
  const { handler } = gate.wrap({
    name: 'call_api',
    mutating: (args) => (args?.method ?? 'GET') !== 'GET',
    hostArg: null,
    inputSchema: {},
    handler: async () => ({ ok: true }),
  });
  const read = await handler({ method: 'GET' });
  assert.ok(!read.isError, 'GET is a read and passes with writes disabled');
  assert.equal(records.at(-1).mutating, false);

  const write = await handler({ method: 'DELETE' });
  assert.equal(write.isError, true, 'DELETE is gated');
  assert.equal(records.at(-1).mutating, true, 'and is recorded as a mutation');
});

test('a handler can attribute the hosts it reached when the gate cannot', async () => {
  const { gate, records } = gateHarness({ mutationsEnabled: true });
  const { handler } = gate.wrap({
    name: 'call_api', mutating: false, hostArg: null, inputSchema: {},
    handler: async (_args, ctx) => {
      ctx.recordHost({ id: 9, name: 'prod-db', ip: '10.0.0.9' });
      ctx.noteSession('file', 'sess-abc');
      return { ok: true };
    },
  });
  await handler({});
  const entry = records.at(-1);
  assert.equal(entry.host.name, 'prod-db', 'searchable by host name');
  assert.deepEqual(entry.usedSessions, [{ kind: 'file', sessionId: 'sess-abc' }]);
});

test('exactly one audit record is written even if the result cannot be serialized', async () => {
  const { gate, records } = gateHarness({ mutationsEnabled: true });
  const { handler } = gate.wrap({
    name: 'hostile', mutating: true, hostArg: null, inputSchema: {},
    // Throws during both summarize() and toText().
    handler: async () => ({ get exitCode() { throw new Error('boom'); } }),
  });
  const before = records.length;
  await handler({});
  assert.equal(records.length - before, 1, 'one record, never zero or two');
});

test('a command result records output sizes and hashes, not the output itself', async () => {
  const { gate, records } = gateHarness({ mutationsEnabled: true });
  const { handler } = gate.wrap({
    name: 'run_command', mutating: true, hostArg: 'host', inputSchema: {},
    handler: async () => ({ exitCode: 0, stdout: 'secret-looking output', stderr: '' }),
  });
  await handler({ host: 'web', command: 'id' });
  const entry = records.at(-1);
  assert.equal(entry.output.stdout.bytes, 21);
  assert.match(entry.output.stdout.sha256, /^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(entry).includes('secret-looking output'), 'output body is not stored');
});

// --- wazuh frame ----------------------------------------------------------
test('wazuh syslog line uses correct PRI and @cee payload', () => {
  const ok = buildSyslogLine({ ts: '2026-08-13T00:00:00.000Z', ok: true, tool: 't' }, { facility: 'local0' });
  assert.match(ok, /^<134>1 2026-08-13T00:00:00\.000Z termix-mcp termix-mcp 0 - - @cee:\{/);
  const bad = buildSyslogLine({ ts: '2026-08-13T00:00:00.000Z', ok: false, tool: 't' }, { facility: 'local0' });
  assert.match(bad, /^<131>1 /); // error severity
  const payload = JSON.parse(ok.slice(ok.indexOf('@cee:') + 5));
  assert.equal(payload.tool, 't');
});

// --- call_api policy (escape-hatch containment) ---------------------------
test('call_api policy forbids credential, api-key, export and session-opening paths', () => {
  const mustRefuse = [
    '/host/db/host/5/password',
    '/host/db/host/internal/all',
    '/host/db/hosts/export',
    '/credentials',
    '/credentials/3',
    '/vault/profiles',
    '/users/api-keys',
    '/users/me/token',
    '/host/quick-connect',
    '/host/enroll',
    '/ssh/file_manager/ssh/connect',
    '/docker/ssh/connect',
    '/ssh/file_manager/sudo-password',
    '/guacamole/token',
    '/rbac/host/4/share',
    // Termix 2.7.0 remote-execution surfaces.
    '/automations',
    '/automations/7/run',
    '/automations/webhook/abc123',
    '/fleet/2/execute',
    '/fleet/2/transfer/push',
    '/ai/chat/stream',
    '/ai/proposals/9/apply',
    '/ai/providers',
  ];
  for (const path of mustRefuse) {
    assert.ok(checkForbidden(path), `${path} must be refused by call_api`);
  }
  // Ordinary endpoints stay reachable, or the escape hatch is useless.
  for (const path of ['/users/me', '/snippets', '/audit-logs', '/uptime', '/ssh/file_manager/ssh/readFile']) {
    assert.equal(checkForbidden(path), null, `${path} should remain callable`);
  }
});

test('call_api denylist survives case, slash and percent-encoding tricks', () => {
  // Every one of these was proven to reach the real endpoint before
  // canonicalization: nginx and Express normalize them back onto the route.
  const evasions = [
    '/Host/DB/Host/2/Password',
    '/host/db/host/1//password',
    '/host/db/host/1/%70assword',
    '/host/db/host/1/%2570assword',
    '/HOST/DB/HOST/1/PASSWORD',
    '/host/db/host/1/password/',
    '/users/../host/db/host/1/password',
    '/Users/API-Keys',
    '/Host/Quick-Connect',
    '/SSH/file_manager/ssh/connect',
  ];
  for (const path of evasions) {
    assert.ok(checkForbidden(path), `${path} must still be refused`);
  }
});

test('2.7.0 remote-execution surfaces are refused, and the /ai rule does not over-match', () => {
  // Each of these stores its target server-side and runs later, so the request
  // carries no host id: extractHostIds finds nothing and the blocklist never
  // gets a chance to apply. They have to be refused by path or not at all.
  for (const path of ['/automations', '/AUTOMATIONS/1/RUN', '/fleet/1/execute', '/ai', '/ai/']) {
    assert.ok(checkForbidden(path), `${path} must be refused by call_api`);
  }
  // The prefix rules are anchored with (\/|$), so a longer name that merely
  // starts with the same letters stays reachable.
  for (const path of ['/airflow/status', '/fleets-report', '/automation-templates']) {
    assert.equal(checkForbidden(path), null, `${path} is a different route and must stay callable`);
  }
});

test('host records are read-only through call_api, so a rename cannot escape the blocklist', () => {
  assert.equal(checkForbidden('/host/db/host', 'GET'), null, 'reading the inventory is fine');
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    assert.ok(checkForbidden('/host/db/host', method), `${method} on a host record must be refused`);
    assert.ok(checkForbidden('/Host/DB/Host/7', method), `${method} must be refused case-insensitively`);
  }
  assert.ok(checkForbidden('/host/bulk-update', 'PATCH'));
  assert.ok(checkForbidden('/host/ssh-config-import', 'POST'));
});

test('canonicalizePath collapses the forms a proxy would re-normalize', () => {
  assert.equal(canonicalizePath('/a//b'), '/a/b');
  assert.equal(canonicalizePath('/a/./b'), '/a/b');
  assert.equal(canonicalizePath('/a/../b'), '/b');
  assert.equal(canonicalizePath('/a/b/'), '/a/b');
  assert.equal(canonicalizePath('/%70ath'), '/path');
  assert.equal(canonicalizePath('/%2570ath'), '/path', 'double encoding resolves too');

  // A leading "//" must COLLAPSE, not be read as a protocol-relative authority.
  // This previously asserted '/x' -- treating `evil.com` as a host to discard --
  // which protected against a risk that does not exist here (the client builds
  // `${origin}${path}` from a fixed origin, so no path string can redirect the
  // request) while creating a real one: the same parse ate the first segment of
  // any doubled-slash path, so "//credentials" became "/" and walked past the
  // credential denylist.
  assert.equal(canonicalizePath('//evil.com/x'), '/evil.com/x', 'collapsed, not treated as authority');
  assert.equal(canonicalizePath('//users/me'), '/users/me', 'first segment must survive');
  assert.equal(canonicalizePath('///users/me'), '/users/me');
  assert.equal(canonicalizePath('/users//me'), '/users/me');
  // The case that mattered: this has to still reach the denylist.
  assert.equal(canonicalizePath('//credentials'), '/credentials');
});

test('the credential denylist matches a sensitive segment under any prefix', () => {
  // Root-anchored rules are right for the routes Termix has today, but a route
  // remounted under a prefix in a later release would escape them silently.
  assert.ok(checkForbidden('/credentials'), 'root form still refused');
  assert.ok(checkForbidden('//credentials'), 'doubled slash refused (was normalising to "/")');
  assert.ok(checkForbidden('/ssh/credentials'), 'prefixed form refused');
  assert.ok(checkForbidden('/api/v2/vault/x'), 'nested vault refused');
  assert.ok(checkForbidden('/%63redentials'), 'percent-encoded refused');
  // Ordinary routes are unaffected.
  assert.equal(checkForbidden('/status/12'), null);
  assert.equal(checkForbidden('/ssh/file_manager/ssh/readFile'), null);
});

test('a host id anywhere in the path is checked, not only on known routes', () => {
  // The known-route list enumerates what Termix has today; a future /…/:hostId
  // would otherwise reach a blocklisted host through the escape hatch while the
  // dedicated tools refuse it.
  assert.deepEqual(extractHostIds('/probe/route/117', null, null), ['117']);
  assert.deepEqual(extractHostIds('/ssh/db/host/117', null, null), ['117']);
  // Known shapes still work, and a path with no numeric segment finds nothing.
  assert.deepEqual(extractHostIds('/status/12', null, null), ['12']);
  assert.deepEqual(extractHostIds('/users/me', null, null), []);
});

test('host ids are found whatever the field is spelled', () => {
  for (const key of ['hostId', 'hostID', 'host_id', 'HOSTID', 'sourceHostId']) {
    assert.deepEqual(extractHostIds('/x', null, { [key]: 5 }), ['5'], `${key} must be seen`);
  }
  assert.deepEqual(extractHostIds('/Host/DB/Host/8', null, null), ['8'], 'mixed-case path still matches');
});

test('call_api policy finds host ids in paths, bodies and queries', () => {
  assert.deepEqual(extractHostIds('/host/db/host/7', null, null), ['7']);
  assert.deepEqual(extractHostIds('/metrics/history/12', null, null), ['12']);
  assert.deepEqual(extractHostIds('/host-metrics/managers/services/9', null, null), ['9']);
  assert.deepEqual(extractHostIds('/ssh/tunnel/connect', null, { sourceHostId: 3 }), ['3']);
  assert.deepEqual(extractHostIds('/whatever', { hostId: 4 }, null), ['4']);
  assert.deepEqual(extractHostIds('/host/bulk-update', null, { hostIds: [1, 2] }), ['1', '2']);
  assert.deepEqual(extractHostIds('/uptime', null, null), []);
});

test('call_api policy extracts session ids only on session-scoped paths', () => {
  assert.equal(extractSessionId('/ssh/file_manager/ssh/readFile', { sessionId: 's1' }, null), 's1');
  assert.equal(extractSessionId('/docker/containers/s2', null, null), 's2');
  assert.equal(extractSessionId('/ssh/file_manager/ssh/writeFile', null, { sessionId: 's3' }), 's3');
  assert.equal(extractSessionId('/snippets', { sessionId: 's4' }, null), null, 'not session-scoped');
});

// --- output capping -------------------------------------------------------
test('oversized tool output is truncated with a recoverable hint', async () => {
  const { gate } = gateHarness({ mutationsEnabled: true });
  const { handler } = gate.wrap({
    name: 'big', mutating: false, hostArg: null, inputSchema: {},
    handler: async () => 'x'.repeat(5000),
  });
  const res = await handler({});
  const text = res.content[0].text;
  assert.ok(text.length < 5000, 'output was capped');
  assert.match(text, /truncated: showing \d+ of 5000 bytes/);
  assert.match(text, /Narrow the request/);
});

// --- changelog / release notes --------------------------------------------
const SAMPLE_CHANGELOG = `# Changelog

## 0.2.0

Second release.

### Added
- a thing

## 0.1.0

First release.
`;

test('extractRelease pulls one version section and stops at the next heading', () => {
  const notes = extractRelease(SAMPLE_CHANGELOG, '0.2.0');
  assert.match(notes, /Second release/);
  assert.match(notes, /### Added/, 'subsections do not terminate the section');
  assert.ok(!notes.includes('First release'), 'stops before the next version');
  assert.equal(extractRelease(SAMPLE_CHANGELOG, 'v0.1.0'), 'First release.', 'v-prefix tolerated');
  assert.equal(extractRelease(SAMPLE_CHANGELOG, '9.9.9'), null, 'missing version returns null');
});

test('listVersions returns every version heading in order', () => {
  assert.deepEqual(listVersions(SAMPLE_CHANGELOG), ['0.2.0', '0.1.0']);
});

test('buildReleaseBody appends pull instructions, with sha line only when known', () => {
  const withSha = buildReleaseBody({ notes: 'Notes.', image: 'reg/img', tag: 'v1.0.0', short: 'abc123' });
  assert.match(withSha, /^Notes\./);
  assert.match(withSha, /docker pull reg\/img:v1\.0\.0/);
  assert.match(withSha, /sha-abc123/);
  const without = buildReleaseBody({ notes: 'Notes.', image: 'reg/img', tag: 'v1.0.0' });
  assert.ok(!without.includes('sha-'), 'no invented sha when the commit is unknown');
  assert.equal(buildReleaseBody({ notes: null, image: 'i', tag: 't' }), null);
});

test('the real CHANGELOG has an entry for the current package version', () => {
  const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  const changelog = fs.readFileSync(new URL('../CHANGELOG.md', import.meta.url), 'utf8');
  assert.ok(extractRelease(changelog, pkg.version), `CHANGELOG.md needs a "## ${pkg.version}" section`);
});

// --- config validation ----------------------------------------------------
test('loadConfig throws without the required Termix variables', () => {
  const saved = { url: process.env.TERMIX_BASE_URL, key: process.env.TERMIX_API_KEY };
  delete process.env.TERMIX_BASE_URL;
  delete process.env.TERMIX_API_KEY;
  try {
    assert.throws(() => loadConfig('stdio'), /TERMIX_BASE_URL/);
  } finally {
    if (saved.url) process.env.TERMIX_BASE_URL = saved.url;
    if (saved.key) process.env.TERMIX_API_KEY = saved.key;
  }
});

test('loadConfig in http mode requires MCP_HTTP_TOKEN', () => {
  const saved = { ...process.env };
  process.env.TERMIX_BASE_URL = 'http://x';
  process.env.TERMIX_API_KEY = 'k';
  delete process.env.MCP_HTTP_TOKEN;
  try {
    assert.throws(() => loadConfig('http'), /MCP_HTTP_TOKEN/);
  } finally {
    process.env = saved;
  }
});

// --- run_command exit status ---------------------------------------------
// Termix's executeFile reports exitCode 0 for the API call, merges stderr into
// output, and appends the script's real status as a trailing EXIT_CODE line.
// Every one of these covers a symptom observed against the live server.
const NONCE = '__TERMIX_MCP_test__';

// Shaped exactly as the wrapper prints it: rc, stdout section, stderr section,
// then Termix's own trailer glued on the end.
//
// The trailer's leading newline is NOT unconditional, and an earlier version of
// this helper added one anyway -- which made it impossible to express the empty
// stderr case and shipped a leak of "EXIT_CODE:0" into every successful call.
// `cat` of an empty stream writes nothing, so the trailer lands flush against
// the marker; a non-empty stream ends with its own newline first.
function wrapped({ rc, out, err }) {
  // Both streams are delimited now, so the shape is exact: `cat` emits the
  // stream verbatim and the wrapper's printf adds one newline before each
  // closing marker. Termix's trailer lands after the final marker.
  return `${NONCE} rc=${rc}\n${NONCE} stdout\n${out}\n${NONCE} stderr\n${err}\n${NONCE} end\nEXIT_CODE:${rc}`;
}

test('a failing command reports its real exit code, not Termix zero', () => {
  const parsed = parseWrappedOutput(wrapped({ rc: 42, out: 'to-stdout', err: 'boom' }), NONCE);
  assert.equal(parsed.exitCode, 42);
});

test('stdout and stderr are separated, and no EXIT_CODE sentinel leaks', () => {
  const parsed = parseWrappedOutput(wrapped({ rc: 7, out: 'to-stdout', err: 'to-stderr' }), NONCE);
  assert.equal(parsed.stdout, 'to-stdout');
  assert.equal(parsed.stderr, 'to-stderr');
  // find_file splits stdout into matches, so a leaked sentinel became a "path".
  assert.ok(!parsed.stdout.includes('EXIT_CODE'), 'sentinel must not survive into stdout');
  assert.ok(!parsed.stderr.includes('EXIT_CODE'), 'sentinel must not survive into stderr');
});

test('a stream with no trailing newline keeps its last line intact', () => {
  // `cat` of a file not ending in a newline; the wrapper prints the closing
  // marker with a leading newline so the last line cannot be glued to it.
  const raw = `${NONCE} rc=0\n${NONCE} stdout\nno-trailing-newline\n${NONCE} stderr\n\nEXIT_CODE:0`;
  const parsed = parseWrappedOutput(raw, NONCE);
  assert.equal(parsed.stdout, 'no-trailing-newline');
  assert.equal(parsed.exitCode, 0);
});

test('command output cannot forge an exit code it does not own', () => {
  // The command prints a marker bearing a DIFFERENT nonce, then really exits 1.
  const hostile = 'sneaky\n__TERMIX_MCP_guessed__ rc=0';
  const parsed = parseWrappedOutput(wrapped({ rc: 1, out: hostile, err: '' }), NONCE);
  assert.equal(parsed.exitCode, 1, 'the real rc line, keyed to this run, wins');
  assert.ok(parsed.stdout.includes('__TERMIX_MCP_guessed__'), 'and the fake stays inert in stdout');
});

test('a trailing newline on stderr is the command\'s and is preserved', () => {
  // `echo to-stderr >&2` writes "to-stderr\n"; `echo -n` writes "to-stderr".
  // These must not collapse to the same result. They did: the strip pattern was
  // loosened to cope with EMPTY stderr, where Termix's trailer lands flush
  // against the marker, and that same looseness ate a real trailing newline.
  // The two cases pull in opposite directions, which is what made it subtle --
  // so both are asserted here, together, deliberately.
  const withNewline = parseWrappedOutput(wrapped({ rc: 0, out: '', err: 'to-stderr\n' }), NONCE);
  assert.equal(withNewline.stderr, 'to-stderr\n', 'the command wrote this newline');

  const without = parseWrappedOutput(wrapped({ rc: 0, out: '', err: 'to-stderr' }), NONCE);
  assert.equal(without.stderr, 'to-stderr');

  assert.notEqual(withNewline.stderr, without.stderr, 'the two must stay distinguishable');
});

test('stdout keeps its own trailing newline independently of stderr', () => {
  const parsed = parseWrappedOutput(wrapped({ rc: 0, out: 'to-stdout\n', err: '' }), NONCE);
  assert.equal(parsed.stdout, 'to-stdout\n');
  assert.equal(parsed.stderr, '');
});

test('a command with empty stderr returns empty stderr, not the sentinel', () => {
  // Observed live after 0.3.2: every successful call came back with
  // "stderr": "EXIT_CODE:0". With nothing written to the error stream, Termix's
  // trailer has no newline in front of it to anchor on.
  const parsed = parseWrappedOutput(wrapped({ rc: 0, out: 'hi', err: '' }), NONCE);
  assert.equal(parsed.stderr, '', 'stderr must be empty, not the trailer');
  assert.equal(parsed.stdout, 'hi');
  assert.equal(parsed.exitCode, 0);
});

test('missing markers parse as null so the caller can fall back', () => {
  assert.equal(parseWrappedOutput('some raw output\nEXIT_CODE:3', NONCE), null);
  assert.equal(parseWrappedOutput('', NONCE), null);
});

test('the command runs in a subshell so an explicit exit cannot kill the trailer', () => {
  // The bug this exists for: with a brace group, `echo hi; exit 7` terminated
  // the whole script before the trailer ran. Both streams were already
  // redirected into the capture files, so every byte was lost and the status
  // came back null. A subshell confines `exit` to itself.
  const s = buildWrappedScript({
    script: 'echo hi; exit 7', shebang: '#!/usr/bin/env bash',
    outPath: '/tmp/o', errPath: '/tmp/e', nonce: NONCE,
  });
  assert.match(s, /^\($/m, 'the command must open a subshell');
  assert.match(s, /^\) > '\/tmp\/o' 2> '\/tmp\/e'$/m, 'and the redirect closes it');
  assert.ok(!/^\{$/m.test(s), 'a brace group would run in the current shell');
  // The trailer has to sit after the group, unguarded, or none of this helps.
  assert.ok(s.indexOf('__tmcp_rc=$?') > s.indexOf(') >'), 'status captured after the subshell');
  assert.ok(s.indexOf(`cat '/tmp/o'`) > s.indexOf('__tmcp_rc=$?'), 'streams replayed after that');
});

test('capture files are created under a tightened umask, which is then restored', () => {
  // They hold whatever the command printed, which may be a secret, in a
  // world-readable /tmp. The restore matters too: files the COMMAND creates
  // should keep the host's normal permissions.
  const s = buildWrappedScript({
    script: 'cat /etc/shadow', shebang: '#!/bin/sh',
    outPath: '/tmp/o', errPath: '/tmp/e', nonce: NONCE,
  });
  assert.match(s, /umask 077/);
  assert.ok(s.indexOf('umask 077') < s.indexOf(`: > '/tmp/o'`), 'tightened before creation');
  assert.ok(s.indexOf(`umask "$__tmcp_um"`) > s.indexOf(`: > '/tmp/e'`), 'restored after');
  // Anchor on the subshell opener as its own line -- a bare '(' also matches
  // the $(umask) two lines above, which made this assertion vacuous.
  assert.ok(s.indexOf(`umask "$__tmcp_um"`) < s.indexOf('\n(\n'), 'and before the command runs');
});

test('the script does not delete its own capture files', () => {
  // Cleanup lives in the caller's finally, which runs however the script ended.
  // An in-script rm is skipped by exactly the paths that strand output in /tmp.
  const s = buildWrappedScript({
    script: 'true', shebang: '#!/bin/sh', outPath: '/tmp/o', errPath: '/tmp/e', nonce: NONCE,
  });
  assert.ok(!s.includes('rm -f'), 'cleanup must not depend on the script reaching its end');
});

test('the wrapper redirects both streams and sets pipefail only where supported', () => {
  const args = { script: 'echo hi', outPath: '/tmp/o', errPath: '/tmp/e', nonce: NONCE };
  const bash = buildWrappedScript({ ...args, shebang: '#!/usr/bin/env bash' });
  assert.match(bash, /set -o pipefail/);
  assert.match(bash, /\) > '\/tmp\/o' 2> '\/tmp\/e'/, 'streams captured separately');

  // dash is /bin/sh on Debian and exits immediately on `set -o pipefail`.
  const sh = buildWrappedScript({ ...args, shebang: '#!/bin/sh' });
  assert.ok(!sh.includes('pipefail'), 'pipefail must not be emitted for /bin/sh');
});

// --- streamable-HTTP session lifecycle ------------------------------------
// A container restart empties the in-memory session registry, which is by
// design. What is NOT by design is answering 400 to a request carrying a
// session id from before the restart: 400 reads as a malformed request, which
// is permanent, so a compliant client never re-initializes and stays stranded
// until a human reconnects it. 404 is the only status the spec makes
// recoverable.
test('an unknown session id gets 404, so the client re-initializes', async () => {
  const { routeUnmatchedSession } = await import('../src/mcp/http-session.mjs');

  for (const method of ['POST', 'GET', 'DELETE']) {
    const out = routeUnmatchedSession({
      sessionId: 'a-uuid-that-was-never-issued', method, isInitialize: false,
    });
    assert.equal(out.status, 404, `${method} with a stale session id must be 404`);
    assert.match(out.body.error, /initialize/i, 'and must say how to recover');
  }

  // The SSE reconnect is a GET carrying the session id, so it hits the same
  // path on every restart -- arguably the more frequent trigger of the two.
  assert.equal(
    routeUnmatchedSession({ sessionId: 'x', method: 'GET', isInitialize: false }).status,
    404,
  );
});

test('no session id and no initialize is still a 400, not a 404', async () => {
  const { routeUnmatchedSession } = await import('../src/mcp/http-session.mjs');

  // This one really is a malformed request: nothing to recover, nothing
  // terminated. Pinned so the fix above cannot swallow it.
  assert.equal(
    routeUnmatchedSession({ sessionId: undefined, method: 'POST', isInitialize: false }).status,
    400,
  );
  assert.equal(
    routeUnmatchedSession({ sessionId: undefined, method: 'GET', isInitialize: false }).status,
    400,
  );
  // A fresh initialize with no session id proceeds to build one.
  assert.equal(
    routeUnmatchedSession({ sessionId: undefined, method: 'POST', isInitialize: true }),
    null,
  );
});

// --- ambiguous host references --------------------------------------------
test('an ambiguous host reference is refused, naming the candidates', async () => {
  // Two stopped guests both report 0.0.0.0 today, so this is live, not
  // hypothetical. First-match-wins meant run_command could land on a different
  // machine than the caller named, with nothing to show for it.
  const listed = [
    { id: 126, name: 'opnsense', ip: '0.0.0.0' },
    { id: 127, name: 'macos-ci', ip: '0.0.0.0' },
    { id: 121, name: 'app-main', ip: '10.0.0.10' },
  ];
  const client = {
    get: async (p) => {
      if (p === '/host/db/host') return listed;
      throw new Error(`unexpected ${p}`);
    },
  };
  const registry = createHostRegistry(client, [], silentLog);

  await assert.rejects(
    () => registry.resolve('0.0.0.0'),
    (err) => /matches 2 hosts/.test(err.message)
      && /opnsense \(id 126/.test(err.message)
      && /macos-ci \(id 127/.test(err.message)
      && /numeric id/.test(err.message),
    'must name both candidates and the way out',
  );

  // An unambiguous name still resolves, and an id is never ambiguous.
  assert.equal((await registry.resolve('app-main')).id, 121);
});

// --- full output capture --------------------------------------------------
test('output capture is off by default and the command trail keeps only a digest', async () => {
  const { gate, records, outputRecords } = gateHarness({ mutationsEnabled: true });
  const { handler } = gate.wrap({
    name: 'run_command', mutating: true, hostArg: 'host', inputSchema: {},
    handler: async () => ({ exitCode: 0, stdout: 'secret-value', stderr: '' }),
  });
  await handler({ host: 'web', command: 'cat /etc/shadow' });

  assert.equal(outputRecords.length, 0, 'nothing captured unless asked for');
  const entry = records.at(-1);
  assert.equal(entry.output.stdout.bytes, 12);
  assert.match(entry.output.stdout.sha256, /^[0-9a-f]{64}$/);
  assert.ok(!JSON.stringify(entry).includes('secret-value'), 'the trail is not a copy of the output');
});

test('with capture on, the output lands in the separate log, joined by call id', async () => {
  const { gate, records, outputRecords } = gateHarness({
    mutationsEnabled: true, captureOutput: true,
  });
  const { handler } = gate.wrap({
    name: 'run_command', mutating: true, hostArg: 'host', inputSchema: {},
    handler: async () => ({ exitCode: 3, stdout: 'the actual output', stderr: 'a warning' }),
  });
  await handler({ host: 'web', command: 'do-the-thing' });

  assert.equal(outputRecords.length, 1);
  const [out] = outputRecords;
  assert.equal(out.stdout, 'the actual output');
  assert.equal(out.stderr, 'a warning');
  assert.equal(out.exitCode, 3);
  // The join key, and the tamper check: the digest travels with the copy, so a
  // later edit to this file diverges from the hash in the command trail.
  assert.equal(out.id, records.at(-1).id, 'joins to the command trail by id');
  assert.equal(out.digest.stdout.sha256, records.at(-1).output.stdout.sha256);
});

test('a captured output is clipped per record so one huge read cannot flush history', async () => {
  const { gate, outputRecords } = gateHarness({ mutationsEnabled: true, captureOutput: true });
  const { handler } = gate.wrap({
    name: 'read_file', mutating: false, hostArg: 'host', inputSchema: {},
    handler: async () => ({ content: 'x'.repeat(5000), encoding: 'utf8' }),
  });
  await handler({ host: 'web', path: '/big' });

  const [out] = outputRecords;
  assert.ok(out.content.length < 5000, 'clipped');
  assert.match(out.content, /clipped: 5000 bytes total/);
  // A file read is output too -- "everything they did", not just commands.
  assert.equal(out.tool, 'read_file');
});

test('a refused call captures no output, because there was none', async () => {
  const { gate, outputRecords } = gateHarness({ mutationsEnabled: false, captureOutput: true });
  const { handler } = gate.wrap({
    name: 'run_command', mutating: true, hostArg: 'host', inputSchema: {},
    handler: async () => ({ stdout: 'never runs' }),
  });
  await handler({ host: 'web', command: 'x' });
  assert.equal(outputRecords.length, 0, 'the gate refused before the handler ran');
});

// --- read windowing and upstream success reporting ------------------------
test('read_file windowing takes a head, a slice, and a negative-offset tail', async () => {
  const { windowLines } = await import('../src/mcp/tools/files.mjs');
  const content = Array.from({ length: 10 }, (_, i) => `line${i + 1}`).join('\n');

  const head = windowLines(content, { limit: 3 });
  assert.equal(head.content, 'line1\nline2\nline3');
  assert.deepEqual([head.firstLine, head.lastLine, head.totalLines], [1, 3, 10]);

  const slice = windowLines(content, { offset: 4, limit: 2 });
  assert.equal(slice.content, 'line4\nline5', 'offset is 1-based');

  // The case that matters: a read-only profile tailing a log it cannot grep.
  const tail = windowLines(content, { offset: -2 });
  assert.equal(tail.content, 'line9\nline10');
  assert.equal(tail.firstLine, 9);

  // Out-of-range must clamp, not throw or produce negative indices.
  assert.equal(windowLines(content, { offset: 99 }).content, '');
  assert.equal(windowLines(content, { offset: -99 }).content, content);

  // A file ending in a newline splits to a trailing empty element that is not a
  // line -- `wc -l` does not count it. Counting it made totalLines one too high
  // and spent one line of every tail on the phantom, so a 3-line tail returned
  // two real lines.
  const trailing = 'a\nb\nc\n';
  assert.equal(windowLines(trailing).totalLines, 3, 'matches wc -l');
  const tail2 = windowLines(trailing, { offset: -2 });
  assert.equal(tail2.content, 'b\nc', 'a 2-line tail is two real lines');
  assert.deepEqual([tail2.firstLine, tail2.lastLine], [2, 3]);
  // A file with no trailing newline is unaffected.
  assert.equal(windowLines('a\nb\nc').totalLines, 3);
});

test('an upstream success:false becomes an error instead of a successful result', async () => {
  const { assertUpstreamOk, withUnconfirmedTarget } = await import('../src/util/upstream.mjs');
  // Observed: process_signal on a nonexistent pid returned HTTP 200 with
  // success:false and was surfaced as a normal result.
  assert.throws(
    () => assertUpstreamOk({ success: false, output: 'kill: (4194304) - No such process' }, 'signal'),
    /No such process/,
  );
  assert.doesNotThrow(() => assertUpstreamOk({ success: true }, 'signal'));
  // Absent `success` means the endpoint does not report one; not a failure.
  assert.doesNotThrow(() => assertUpstreamOk({ output: 'ok' }, 'signal'));

  const noted = withUnconfirmedTarget({ message: 'Alert dismissed successfully' }, 'alert "nope"');
  assert.match(noted.unconfirmed, /not evidence/);
  assert.equal(noted.message, 'Alert dismissed successfully', 'original payload preserved');
});

// --- image packaging ------------------------------------------------------
// access_policy_schema require()s access-policy.schema.json from the repo root,
// which the Dockerfile did not COPY -- so the tool threw MODULE_NOT_FOUND in
// every container deploy while passing over stdio, where the repo root supplies
// it. That asymmetry is the point: a file only the *image* lacks cannot be
// caught by importing modules here, so assert against the Dockerfile text.
test('Dockerfile COPYs every repo-root file that src/ loads at runtime', () => {
  const root = path.resolve(import.meta.dirname, '..');
  const srcDir = path.join(root, 'src');
  const dockerfile = fs.readFileSync(path.join(root, 'Dockerfile'), 'utf8');

  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const p = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(p) : [p];
  });

  const escaping = new Set();
  for (const file of walk(srcDir)) {
    const text = fs.readFileSync(file, 'utf8');
    for (const m of text.matchAll(/(?:require\(|import\(|from\s+)\s*['"](\.\.?\/[^'"]+)['"]/g)) {
      const resolved = path.resolve(path.dirname(file), m[1]);
      // Only files that leave src/ but stay inside the repo matter: those are
      // the ones the image has to be told about by name.
      if (resolved.startsWith(srcDir + path.sep)) continue;
      if (!resolved.startsWith(root + path.sep)) continue;
      escaping.add(path.relative(root, resolved).split(path.sep).join('/'));
    }
  }

  // Guard the guard: if this ever finds nothing the matcher has drifted, and
  // the assertions below would pass vacuously.
  assert.ok(escaping.size > 0, 'found no repo-root loads from src/ -- matcher is broken');

  // Parse the COPY sources rather than searching the whole file. A substring
  // search over the raw text passes on any *comment* that happens to name the
  // file -- including the one above the COPY line explaining this very rule.
  const copied = new Set();
  for (const line of dockerfile.matchAll(/^\s*COPY\s+(.+)$/gm)) {
    const parts = line[1].trim().split(/\s+/).filter((p) => !p.startsWith('--'));
    parts.pop(); // destination
    for (const p of parts) copied.add(p.replace(/^\.\//, ''));
  }

  const isCopied = (rel) => copied.has(rel)
    || [...copied].some((c) => rel.startsWith(`${c}/`));

  for (const rel of escaping) {
    assert.ok(
      isCopied(rel),
      `src/ loads ${rel} at runtime but no COPY instruction brings it into the image: `
      + 'it throws MODULE_NOT_FOUND in the container while working over stdio from the repo root',
    );
  }
});

// --- secret exposure through read-only tools ------------------------------
// Three separate paths by which a profile granted only @readonly could reach
// credentials, each sufficient on its own to escalate to whatever the most
// privileged profile can do. All three were live in 0.4.3.

test('an inspect payload comes back with its secrets redacted', () => {
  const details = {
    Args: ['--password', 'hunter2'],
    Config: {
      Env: [
        'PATH=/usr/local/bin:/usr/bin',
        'NODE_ENV=production',
        'MCP_TOKEN_OPS=opstoken123',
        'TERMIX_API_KEY=tmx_apikey456',
        'DB_PASSWORD=dbpass789',
        'BARE_NAME',
      ],
      Labels: {
        'com.docker.compose.project': 'termix-mcp',
        registry_password: 'labelpass',
      },
      Cmd: ['node', 'src/index-http.mjs'],
      Entrypoint: ['docker-entrypoint.sh', '--token=entrytoken'],
    },
  };

  const out = redactContainerDetails(details);
  const blob = JSON.stringify(out);

  for (const secret of ['opstoken123', 'tmx_apikey456', 'dbpass789', 'labelpass',
    'hunter2', 'entrytoken']) {
    assert.ok(!blob.includes(secret), `${secret} survived redaction`);
  }

  // Everything that is not a secret has to survive, or the tool stops being
  // useful for the thing it exists for.
  assert.ok(out.Config.Env.includes('PATH=/usr/local/bin:/usr/bin'));
  assert.ok(out.Config.Env.includes('NODE_ENV=production'));
  assert.ok(out.Config.Env.includes('BARE_NAME'), 'a name with no value has nothing to leak');
  assert.equal(out.Config.Labels['com.docker.compose.project'], 'termix-mcp');
  assert.deepEqual(out.Config.Cmd, ['node', 'src/index-http.mjs'], 'a plain command is untouched');
  // The key is kept so the reader still knows the variable is set.
  assert.ok(out.Config.Env.some((e) => e === 'MCP_TOKEN_OPS=[redacted]'));

  // Redaction must not write through to the caller's object.
  assert.ok(details.Config.Env.includes('MCP_TOKEN_OPS=opstoken123'), 'input not mutated');
});

test('docker_container_info wires that redaction into the details mode', async () => {
  const spec = dockerTools().find((t) => t.name === 'docker_container_info');
  const ctx = {
    host: { id: 1, name: 'app-main' },
    sessions: { withDockerSession: (host, op) => op({ sessionId: 'sid' }) },
    client: { get: async () => ({ Config: { Env: ['SOME_TOKEN=leaked'] } }) },
  };
  const out = await spec.handler({ containerId: 'c', mode: 'details' }, ctx);
  assert.ok(!JSON.stringify(out).includes('leaked'), 'the handler returned a raw environment');
});

test('session_logs cannot walk out of its endpoint with a crafted id', async () => {
  const spec = observabilityTools().find((t) => t.name === 'session_logs');
  const asked = [];
  const ctx = { client: { get: async (p) => { asked.push(p); return {}; } } };

  // Both branches: metadata and content.
  await spec.handler({ id: '../users/me', content: false }, ctx);
  await spec.handler({ id: '../../users/api-keys', content: true }, ctx);
  await spec.handler({ id: 'x?query=1', content: false }, ctx);

  assert.equal(asked.length, 3);
  for (const asked_path of asked) {
    // Resolve it the way fetch will, which is where the bug actually bit.
    const resolved = new URL(`http://x${asked_path}`);
    assert.ok(
      resolved.pathname.startsWith('/session_logs/'),
      `${asked_path} resolved to ${resolved.pathname}, outside /session_logs/`,
    );
    assert.equal(resolved.search, '', `${asked_path} opened a query string`);
  }
});

test('the client refuses any path that does not resolve to itself', async () => {
  const client = createClient(
    { baseUrl: 'http://127.0.0.1:1', serviceUrls: {}, apiKey: 'k', timeoutMs: 50, retry: 0 },
    silentLog,
  );
  // Refused before any socket is opened, so an unreachable base URL is fine.
  await assert.rejects(
    () => client.get('/session_logs/../users/api-keys'),
    (error) => error.code === 'PATH_NOT_CANONICAL',
    'a traversing path reached the network',
  );
  // The same guard must not reject the paths the server actually uses.
  await assert.rejects(
    () => client.get('/host/db/host'),
    (error) => error.code !== 'PATH_NOT_CANONICAL',
    'a legitimate path was rejected as non-canonical',
  );
});

test('access_policy_check fromFile is confined to the policy directory', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'termix-policy-'));
  const policyFile = path.join(dir, 'access-policy.json');
  fs.writeFileSync(policyFile, '{"profiles":{}}');
  try {
    assert.equal(readPolicyFile('access-policy.json', policyFile), '{"profiles":{}}');
    assert.throws(() => readPolicyFile('/etc/hostname', policyFile), /confined to/);
    assert.throws(() => readPolicyFile('../../../etc/hostname', policyFile), /confined to/);
    assert.throws(() => readPolicyFile('/proc/self/environ', policyFile), /confined to/);
    // Absent and unreadable must be indistinguishable, or this is an existence
    // oracle over the whole filesystem.
    assert.throws(() => readPolicyFile('absent.json', policyFile), /could not read a policy file/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('fromFile is refused outright when no policy file is configured', () => {
  assert.throws(() => readPolicyFile('anything.json', ''), /TERMIX_POLICY_FILE/);
});

test('a fromFile parse failure does not echo the file back', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'termix-policy-'));
  const policyFile = path.join(dir, 'access-policy.json');
  fs.writeFileSync(policyFile, 'SUPERSECRETVALUE, definitely not JSON');
  const spec = policyTools({ catalog: [] }).find((t) => t.name === 'access_policy_check');
  const ctx = { config: { policyFile }, hosts: { list: async () => [] } };
  try {
    const out = await spec.handler({ policy: 'access-policy.json', fromFile: true }, ctx);
    assert.equal(out.valid, false);
    assert.ok(
      !out.error.includes('SUPERSECRETVALUE'),
      'the parser error handed the file contents back',
    );

    // An inline document is the caller's own, so echoing the parse error leaks
    // nothing and stays useful for fixing a draft.
    const inline = await spec.handler({ policy: 'ALSO NOT JSON', fromFile: false }, ctx);
    assert.equal(inline.valid, false);
    assert.match(inline.error, /JSON/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- HTTP front end: attribution and session bounds ------------------------
test('X-Forwarded-For is believed only from a trusted proxy', async () => {
  const { resolveClientAddress } = await import('../src/mcp/http-session.mjs');

  // Nothing trusted: the header is ignored entirely, however it is spelled.
  assert.deepEqual(
    resolveClientAddress({ socketAddress: '10.0.0.9', forwardedFor: '1.2.3.4' }),
    { address: '10.0.0.9', forwarded: false },
  );

  // A direct caller forging the header must not be able to write its own source
  // address into the trail -- this is the whole reason the allowlist exists.
  assert.deepEqual(
    resolveClientAddress({
      socketAddress: '10.0.0.9', forwardedFor: '1.2.3.4', trustedProxies: ['10.0.0.2'],
    }),
    { address: '10.0.0.9', forwarded: false },
  );

  // From the proxy, the RIGHTMOST hop is the one the proxy appended.
  assert.deepEqual(
    resolveClientAddress({
      socketAddress: '10.0.0.2',
      forwardedFor: 'forged.by.client, 10.0.0.99',
      trustedProxies: ['10.0.0.2'],
    }),
    { address: '10.0.0.99', forwarded: true },
  );

  // Node reports IPv4 peers as ::ffff:… on a dual-stack socket, so a proxy
  // written the ordinary way still has to match.
  assert.deepEqual(
    resolveClientAddress({
      socketAddress: '::ffff:10.0.0.2',
      forwardedFor: '10.0.0.99',
      trustedProxies: ['10.0.0.2'],
    }),
    { address: '10.0.0.99', forwarded: true },
  );

  // Chain of trusted proxies with no real client behind it: report the peer
  // rather than inventing an origin.
  assert.deepEqual(
    resolveClientAddress({
      socketAddress: '10.0.0.1',
      forwardedFor: '10.0.0.2, 10.0.0.1',
      trustedProxies: ['10.0.0.1', '10.0.0.2'],
    }),
    { address: '10.0.0.1', forwarded: false },
  );
});

test('idle and over-capacity sessions are selected for reaping, never the current one', async () => {
  const { selectExpiredSessions } = await import('../src/mcp/http-session.mjs');
  const now = 1_000_000;
  const mk = (entries) => new Map(entries.map(([id, lastSeen]) => [id, { lastSeen }]));

  // Idle beyond the window goes; recent stays.
  const idle = selectExpiredSessions({
    sessions: mk([['old', now - 60_000], ['fresh', now - 1_000]]),
    now,
    idleMs: 30_000,
    maxSessions: 10,
  });
  assert.deepEqual(idle, [{ id: 'old', reason: 'idle' }]);

  // The session serving the request is never a candidate, however stale.
  const kept = selectExpiredSessions({
    sessions: mk([['current', 0]]),
    now,
    idleMs: 30_000,
    maxSessions: 10,
    keep: 'current',
  });
  assert.deepEqual(kept, []);

  // Over capacity: least recently seen go first, and the kept session still
  // occupies one of the slots.
  const over = selectExpiredSessions({
    sessions: mk([['a', now - 3], ['b', now - 1], ['c', now - 2]]),
    now,
    idleMs: 0,
    maxSessions: 2,
    keep: 'current',
  });
  assert.deepEqual(over.map((e) => e.id), ['a', 'c'], 'oldest first, down to the cap');
  assert.ok(over.every((e) => e.reason === 'over-capacity'));

  // Disabled bounds select nothing, so a deployment can turn this off.
  assert.deepEqual(
    selectExpiredSessions({
      sessions: mk([['a', 0], ['b', 0]]), now, idleMs: 0, maxSessions: 0,
    }),
    [],
  );
});

test('the audit record says where a call came from, not just which profile', async () => {
  // Two holders of one token are indistinguishable in a trail that records only
  // the profile -- which is exactly the question asked after a token leaks.
  const records = [];
  const gate = createGate({
    hosts: { resolveAllowed: async (ref) => ({ id: 1, name: String(ref), ip: '10.0.0.1' }) },
    mutex: createKeyedMutex(),
    audit: { record: (e) => records.push(e) },
    outputAudit: null,
    wazuh: null,
    state: { mutationsEnabled: true },
    logger: silentLog,
    config: { auditArgMax: 512, maxOutputBytes: 2048, allowToggle: false },
    transport: 'http',
    profile: { name: 'ops', allowsTool: () => true, allowsMutations: () => true, allowsPath: () => true },
    peer: { address: '10.0.0.99', forwarded: true },
  });

  const { handler } = gate.wrap({
    name: 'read_thing', mutating: false, hostArg: 'host', inputSchema: {}, handler: async () => ({ ok: 1 }),
  });
  await handler({ host: 'web' });

  assert.equal(records.at(-1).peer, '10.0.0.99');
  assert.equal(records.at(-1).profile, 'ops');
});

test('a stdio call records a null peer rather than inventing one', async () => {
  const records = [];
  const gate = createGate({
    hosts: { resolveAllowed: async (ref) => ({ id: 1, name: String(ref), ip: '10.0.0.1' }) },
    mutex: createKeyedMutex(),
    audit: { record: (e) => records.push(e) },
    outputAudit: null,
    wazuh: null,
    state: { mutationsEnabled: true },
    logger: silentLog,
    config: { auditArgMax: 512, maxOutputBytes: 2048, allowToggle: false },
    transport: 'stdio',
  });
  const { handler } = gate.wrap({
    name: 'read_thing', mutating: false, hostArg: 'host', inputSchema: {}, handler: async () => ({ ok: 1 }),
  });
  await handler({ host: 'web' });
  assert.equal(records.at(-1).peer, null);
});
