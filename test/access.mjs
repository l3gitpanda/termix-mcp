import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { parsePolicy, createPolicyStore, unrestrictedProfile } from '../src/access/policy.mjs';
import { normalizePath, pathGlobToRegExp, globToRegExp } from '../src/access/match.mjs';
import { TOOL_GROUPS } from '../src/access/groups.mjs';
import { createHostRegistry } from '../src/termix/hosts.mjs';

const silentLog = { info() {}, warn() {}, debug() {}, error() {} };

const POLICY = {
  defaultProfile: 'readonly',
  profiles: {
    readonly: {
      token: 'ro-token',
      hosts: { allow: ['*'], deny: ['legacy-box'] },
      mutations: 'deny',
    },
    ops: {
      token: 'ops-token',
      hosts: { allow: ['app-*', '10.0.0.10'] },
      mutations: 'allow',
      tools: { deny: ['process_signal'] },
    },
    appdata: {
      token: 'app-token',
      hosts: { allow: ['app-main'] },
      paths: { allow: ['/opt/appdata/**'], deny: ['/opt/appdata/secrets/**'] },
      tools: { deny: ['run_command', 'find_file'] },
    },
  },
};

// --- modes: choosing the scope of each restriction ------------------------
test('mode "all" turns a dimension off and "none" locks it entirely', () => {
  const { profiles } = parsePolicy({
    profiles: {
      open: { hosts: 'all', tools: 'all', paths: 'all' },
      shut: { hosts: 'none', tools: 'none', paths: 'none' },
    },
  });
  const open = profiles.get('open');
  assert.equal(open.allowsHost({ name: 'anything', ip: '1.2.3.4' }), true);
  assert.equal(open.allowsTool('run_command'), true);
  assert.equal(open.allowsPath('/etc/shadow'), true);

  const shut = profiles.get('shut');
  assert.equal(shut.allowsHost({ name: 'anything', ip: '1.2.3.4' }), false);
  assert.equal(shut.allowsTool('list_hosts'), false);
  assert.equal(shut.allowsPath('/opt'), false);
});

test('allowlist fails closed and deny carves exceptions out of the grant', () => {
  const { profiles } = parsePolicy({
    profiles: {
      p: { hosts: { mode: 'allowlist', allow: ['web*'], deny: ['web-prod'] } },
    },
  });
  const p = profiles.get('p');
  assert.equal(p.allowsHost({ name: 'web-dev' }), true, 'inside the grant');
  assert.equal(p.allowsHost({ name: 'web-prod' }), false, 'exception removed');
  assert.equal(p.allowsHost({ name: 'db' }), false, 'outside the grant fails closed');
});

test('blocklist fails open and allow carves exceptions back in', () => {
  const { profiles } = parsePolicy({
    profiles: {
      p: { hosts: { mode: 'blocklist', deny: ['prod*'], allow: ['prod-sandbox'] } },
    },
  });
  const p = profiles.get('p');
  assert.equal(p.allowsHost({ name: 'anything-new' }), true, 'unlisted passes');
  assert.equal(p.allowsHost({ name: 'prod-db' }), false, 'denied');
  assert.equal(p.allowsHost({ name: 'prod-sandbox' }), true, 'exception restored');
});

test('a rule set may be written as a string, an array, or an object', () => {
  const { profiles } = parsePolicy({
    profiles: {
      str: { hosts: 'all' },
      arr: { hosts: ['a', 'b'] },
      obj: { hosts: { mode: 'allowlist', allow: ['a'] } },
    },
  });
  assert.equal(profiles.get('str').allowsHost({ name: 'zzz' }), true);
  assert.equal(profiles.get('arr').allowsHost({ name: 'a' }), true);
  assert.equal(profiles.get('arr').allowsHost({ name: 'c' }), false, 'array is allowlist shorthand');
  assert.equal(profiles.get('obj').allowsHost({ name: 'a' }), true);
});

test('an omitted mode is inferred, preserving what older policies meant', () => {
  const { profiles } = parsePolicy({
    profiles: {
      // allow present -> allowlist; no lists at all -> hosts still fail closed,
      // while tools and paths stay unrestricted.
      inferred: { hosts: { allow: ['a'] }, tools: { deny: ['run_command'] } },
      bare: {},
    },
  });
  const inferred = profiles.get('inferred');
  assert.equal(inferred.hostRules.mode, 'allowlist');
  assert.equal(inferred.toolRules.mode, 'blocklist', 'deny-only implies blocklist');
  assert.equal(inferred.allowsTool('read_file'), true);
  assert.equal(inferred.allowsTool('run_command'), false);

  const bare = profiles.get('bare');
  assert.equal(bare.hostRules.mode, 'allowlist', 'hosts default closed');
  assert.equal(bare.allowsHost({ name: 'x' }), false);
  assert.equal(bare.allowsTool('run_command'), true, 'tools default unrestricted');
  assert.equal(bare.allowsPath('/etc/shadow'), true, 'paths default unrestricted');
});

test('an invalid mode is rejected rather than silently ignored', () => {
  assert.throws(() => parsePolicy({ profiles: { p: { hosts: 'sometimes' } } }), /is not a mode/);
  assert.throws(
    () => parsePolicy({ profiles: { p: { hosts: { mode: 'maybe', allow: ['a'] } } } }),
    /mode must be one of/,
  );
});

// --- tool groups ----------------------------------------------------------
test('tool groups expand, so a policy need not enumerate every tool name', () => {
  const { profiles } = parsePolicy({
    profiles: { observer: { hosts: 'all', tools: { allow: ['@readonly'] } } },
  });
  const p = profiles.get('observer');
  assert.equal(p.allowsTool('read_file'), true);
  assert.equal(p.allowsTool('list_hosts'), true);
  assert.equal(p.allowsTool('write_file'), false);
  assert.equal(p.allowsTool('run_command'), false);
});

test('groups compose with explicit names and with deny', () => {
  const { profiles } = parsePolicy({
    profiles: { p: { hosts: 'all', tools: { allow: ['@files.read', 'list_hosts'], deny: ['get_file_info'] } } },
  });
  const p = profiles.get('p');
  assert.equal(p.allowsTool('read_file'), true);
  assert.equal(p.allowsTool('list_hosts'), true);
  assert.equal(p.allowsTool('get_file_info'), false, 'deny carves out of the group');
  assert.equal(p.allowsTool('write_file'), false);
});

test('a misspelled group is an error, not a silently empty rule', () => {
  assert.throws(
    () => parsePolicy({ profiles: { p: { tools: { allow: ['@readonyl'] } } } }),
    /unknown tool group "@readonyl"/,
  );
});

test('the @escape group denies every path-bypassing tool at once', () => {
  const { profiles } = parsePolicy({
    profiles: {
      p: { hosts: 'all', paths: { allow: ['/opt/**'] }, tools: { mode: 'blocklist', deny: ['@escape'] } },
    },
  });
  const p = profiles.get('p');
  for (const tool of ['run_command', 'run_snippet', 'find_file', 'call_api']) {
    assert.equal(p.allowsTool(tool), false, `${tool} denied`);
  }
  assert.equal(p.allowsTool('read_file'), true);
  // With the escapes closed, the path restriction is real, so no warning.
  assert.equal(p.warnings.filter((w) => /restricts paths/.test(w)).length, 0);
});

// --- global blocklist toggle ---------------------------------------------
test('a profile can enforce or ignore the global blocklist', async () => {
  const hosts = [{ id: 1, name: 'legacy-box', ip: '10.0.0.1' }];
  const client = {
    get: async (p) => (p === '/host/db/host' ? hosts : hosts[0]),
  };
  const { profiles } = parsePolicy({
    profiles: {
      strict: { hosts: 'all' },
      override: { hosts: 'all', globalBlocklist: 'ignore' },
    },
  });

  const enforced = createHostRegistry(client, ['legacy-box'], silentLog, profiles.get('strict'));
  await assert.rejects(() => enforced.resolveAllowed('legacy-box'), /blocklist/);

  const ignored = createHostRegistry(client, ['legacy-box'], silentLog, profiles.get('override'));
  assert.equal((await ignored.resolveAllowed('legacy-box')).name, 'legacy-box', 'profile opted out');
  // Opting out is loud, not silent.
  assert.ok(profiles.get('override').warnings.some((w) => /ignores TERMIX_BLOCKLIST/.test(w)));
});

test('globalBlocklist only accepts the two documented values', () => {
  assert.throws(
    () => parsePolicy({ profiles: { p: { globalBlocklist: 'off' } } }),
    /must be "enforce" or "ignore"/,
  );
});

// --- explain --------------------------------------------------------------
test('explain answers what a profile would actually permit', () => {
  const { profiles } = parsePolicy({
    profiles: { p: { hosts: ['web'], tools: { allow: ['@readonly'] }, paths: { allow: ['/opt/**'] } } },
  });
  const out = profiles.get('p').explain({
    hosts: [{ name: 'web', ip: '10.0.0.1' }, { name: 'db', ip: '10.0.0.2' }],
    tools: ['read_file', 'run_command'],
    paths: ['/opt/a', '/etc/shadow'],
  });
  assert.deepEqual(out.modes, { hosts: 'allowlist', tools: 'allowlist', paths: 'allowlist' });
  assert.deepEqual(out.hosts, [
    { host: 'web', allowed: true },
    { host: 'db', allowed: false },
  ]);
  assert.deepEqual(out.tools, [
    { tool: 'read_file', allowed: true },
    { tool: 'run_command', allowed: false },
  ]);
  assert.equal(out.paths[0].allowed, true);
  assert.equal(out.paths[1].allowed, false);
});

// --- host scoping ---------------------------------------------------------
test('a profile reaches only the hosts it lists, and unlisted hosts fail closed', () => {
  const { profiles } = parsePolicy(POLICY);
  const ops = profiles.get('ops');
  assert.equal(ops.allowsHost({ name: 'app-main', ip: '10.0.0.10' }), true);
  assert.equal(ops.allowsHost({ name: 'app-edge', ip: '10.0.0.2' }), true, 'glob matches');
  assert.equal(ops.allowsHost({ name: 'web-proxy', ip: '10.0.0.2' }), false, 'unlisted host denied');
  // A host added to Termix tomorrow must not be reachable by accident.
  assert.equal(ops.allowsHost({ name: 'brand-new-host', ip: '10.9.9.9' }), false);
});

test('a host matches by name or by IP, and deny beats allow', () => {
  const { profiles } = parsePolicy(POLICY);
  const ro = profiles.get('readonly');
  assert.equal(ro.allowsHost({ name: 'web-proxy', ip: '10.0.0.2' }), true);
  assert.equal(ro.allowsHost({ name: 'legacy-box', ip: '10.0.0.1' }), false, 'denied by name');
  const ops = profiles.get('ops');
  assert.equal(ops.allowsHost({ name: 'anything', ip: '10.0.0.10' }), true, 'allowed by IP');
});

test('the host registry enforces the profile, so every tool inherits it', async () => {
  const hosts = [
    { id: 1, name: 'app-main', ip: '10.0.0.10' },
    { id: 2, name: 'web-proxy', ip: '10.0.0.2' },
  ];
  const client = {
    get: async (p) => {
      if (p === '/host/db/host') return hosts;
      const m = /\/host\/db\/host\/(\d+)/.exec(p);
      return hosts.find((h) => String(h.id) === m?.[1]) ?? null;
    },
  };
  const { profiles } = parsePolicy(POLICY);
  const registry = createHostRegistry(client, [], silentLog, profiles.get('ops'));

  assert.equal((await registry.resolveAllowed('app-main')).id, 1);
  await assert.rejects(
    () => registry.resolveAllowed('web-proxy'),
    (e) => e.blocked === true && /not granted to the "ops" access profile/.test(e.message),
  );
});

// --- read/write scoping ---------------------------------------------------
test('a read-only profile cannot mutate and cannot be talked into it', () => {
  const { profiles } = parsePolicy(POLICY);
  assert.equal(profiles.get('readonly').allowsMutations(), false);
  assert.equal(profiles.get('ops').allowsMutations(), true);
});

// --- tool scoping ---------------------------------------------------------
test('a profile can deny individual tools', () => {
  const { profiles } = parsePolicy(POLICY);
  const ops = profiles.get('ops');
  assert.equal(ops.allowsTool('run_command'), true);
  assert.equal(ops.allowsTool('process_signal'), false);
  const app = profiles.get('appdata');
  assert.equal(app.allowsTool('read_file'), true);
  assert.equal(app.allowsTool('run_command'), false);
});

// --- path scoping ---------------------------------------------------------
test('path rules confine a profile, including against traversal', () => {
  const { profiles } = parsePolicy(POLICY);
  const app = profiles.get('appdata');
  assert.equal(app.allowsPath('/opt/appdata/jellyfin/config.xml'), true);
  assert.equal(app.allowsPath('/etc/shadow'), false);
  assert.equal(app.allowsPath('/opt/appdata/secrets/db.env'), false, 'deny beats allow');
  // The bypass this class of feature usually ships with.
  assert.equal(app.allowsPath('/opt/appdata/../../etc/shadow'), false, 'traversal is normalized away');
  assert.equal(app.allowsPath('/opt/appdata/./../../etc/shadow'), false);
  assert.equal(app.allowsPath('/opt//appdata/../../etc/shadow'), false);
  assert.equal(app.allowsPath('/opt/appdata/x/../y.conf'), true, 'traversal inside the grant is fine');
});

test('normalizePath resolves the forms an ACL must not be fooled by', () => {
  assert.equal(normalizePath('/opt/../etc/shadow'), '/etc/shadow');
  assert.equal(normalizePath('/opt//a///b'), '/opt/a/b');
  assert.equal(normalizePath('/opt/./a'), '/opt/a');
  assert.equal(normalizePath('/a/b/../../../../etc'), '/etc', 'cannot climb above root');
  assert.equal(normalizePath('/opt/a/'), '/opt/a');
  assert.equal(normalizePath('\\opt\\a'), '/opt/a', 'backslashes are treated as separators');
});

test('path globs respect segment depth', () => {
  assert.equal(pathGlobToRegExp('/opt/*').test('/opt/a'), true);
  assert.equal(pathGlobToRegExp('/opt/*').test('/opt/a/b'), false, '* stays in one segment');
  assert.equal(pathGlobToRegExp('/opt/**').test('/opt/a/b'), true, '** crosses separators');
  assert.equal(pathGlobToRegExp('/opt').test('/opt/a/b'), true, 'a bare prefix covers the subtree');
  assert.equal(pathGlobToRegExp('/opt').test('/optional/x'), false, 'prefix is segment-aware');
});

test('host globs are anchored so a prefix does not leak', () => {
  assert.equal(globToRegExp('web').test('web'), true);
  assert.equal(globToRegExp('web').test('web-prod'), false);
  assert.equal(globToRegExp('web*').test('web-prod'), true);
  assert.equal(globToRegExp('WEB').test('web'), true, 'case-insensitive');
});

// --- identity -------------------------------------------------------------
test('tokens select a profile, and an unknown token selects none', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'termix-policy-'));
  const file = path.join(dir, 'policy.json');
  fs.writeFileSync(file, JSON.stringify(POLICY));
  const store = createPolicyStore({ filePath: file, logger: silentLog });
  assert.equal(store.byToken('ops-token').name, 'ops');
  assert.equal(store.byToken('ro-token').name, 'readonly');
  assert.equal(store.byToken('nope'), null);
  assert.equal(store.byToken(''), null);
  assert.equal(store.defaultName(), 'readonly');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a token may be given as a sha256 digest instead of in plaintext', () => {
  const digest = crypto.createHash('sha256').update('secret-value').digest('hex');
  const { profiles } = parsePolicy({
    profiles: { hashed: { tokenSha256: digest, hosts: { allow: ['*'] } } },
  });
  assert.ok(profiles.get('hashed').tokenDigest);
});

test('a token may be referenced by environment variable', () => {
  process.env.TEST_MCP_TOKEN = 'from-env';
  try {
    const { profiles } = parsePolicy({
      profiles: { envd: { tokenEnv: 'TEST_MCP_TOKEN', hosts: { allow: ['*'] } } },
    });
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'termix-policy-env-'));
    const file = path.join(dir, 'p.json');
    fs.writeFileSync(file, JSON.stringify({ profiles: { envd: { tokenEnv: 'TEST_MCP_TOKEN', hosts: { allow: ['*'] } } } }));
    const store = createPolicyStore({ filePath: file, logger: silentLog });
    assert.equal(store.byToken('from-env').name, 'envd');
    assert.ok(profiles.get('envd'));
    fs.rmSync(dir, { recursive: true, force: true });
  } finally {
    delete process.env.TEST_MCP_TOKEN;
  }
});

// --- validation -----------------------------------------------------------
test('a policy that would be ambiguous or unusable is rejected at load', () => {
  assert.throws(() => parsePolicy({ profiles: {} }), /no profiles/);
  assert.throws(
    () => parsePolicy({ profiles: { a: { token: 'x', hosts: { allow: ['*'] } }, b: { token: 'x' } } }),
    /share the same token/,
  );
  assert.throws(
    () => parsePolicy({ defaultProfile: 'ghost', profiles: { a: { hosts: { allow: ['*'] } } } }),
    /not defined/,
  );
  assert.throws(
    () => parsePolicy({ profiles: { a: { mutations: 'maybe' } } }),
    /must be "allow" or "deny"/,
  );
  assert.throws(
    () => parsePolicy({ profiles: { a: { tokenEnv: 'DEFINITELY_NOT_SET_XYZ' } } }),
    /which is not set/,
  );
});

test('a path-restricted profile that keeps a shell tool is flagged, not silently accepted', () => {
  const { profiles } = parsePolicy({
    profiles: { leaky: { hosts: { allow: ['*'] }, paths: { allow: ['/opt/**'] } } },
  });
  const warnings = profiles.get('leaky').warnings;
  assert.ok(warnings.some((w) => /restricts paths but still grants/.test(w)));
  assert.ok(warnings.some((w) => /run_command/.test(w)));
});

// --- drift guards ---------------------------------------------------------
// The groups are hand-written lists, which is exactly the thing that rots. These
// two tests tie them to the real tool catalog so a tool added later cannot fall
// outside every group, and @readonly cannot drift from "does not mutate".
async function realCatalog() {
  const saved = { ...process.env };
  process.env.TERMIX_BASE_URL = 'http://127.0.0.1:1';
  process.env.TERMIX_API_KEY = 'x';
  process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'termix-cat-'));
  try {
    const { loadConfig } = await import('../src/config.mjs');
    const { buildServer } = await import('../src/mcp/server.mjs');
    const built = buildServer({
      config: loadConfig('stdio'), logger: silentLog, transport: 'stdio',
    });
    await built.sessions.closeAll();
    return built.catalog;
  } finally {
    process.env = saved;
  }
}

// The describe() text is the only thing steering the model toward passing a
// name. Pass an id and the call reads as an unrecognisable number in the
// client's tool-call view and in the audit trail, because a Termix record id
// has no relation to the guest's VMID. A new tool hand-rolling its own host arg
// would silently reintroduce that, so tie every one of them to the shared text.
test('every host argument steers callers to the name, not the opaque record id', async () => {
  const { HOST_ARG_DESCRIPTION } = await import('../src/mcp/tools/host-arg.mjs');
  // .optional() and friends wrap the schema; the description sits on the inner.
  const unwrap = (s) => (s?._def?.innerType ? unwrap(s._def.innerType) : s);

  // realCatalog() projects to {name, mutating, description}, so go to the tool
  // factories for the actual input schemas.
  const factories = await Promise.all([
    import('../src/mcp/tools/hosts.mjs').then((m) => m.hostTools()),
    import('../src/mcp/tools/exec.mjs').then((m) => m.execTools()),
    import('../src/mcp/tools/files.mjs').then((m) => m.fileTools()),
    import('../src/mcp/tools/docker.mjs').then((m) => m.dockerTools()),
    import('../src/mcp/tools/system.mjs').then((m) => m.systemTools()),
    import('../src/mcp/tools/tunnels.mjs').then((m) => m.tunnelTools()),
    import('../src/mcp/tools/snippets.mjs').then((m) => m.snippetTools()),
  ]);

  const offenders = [];
  let checked = 0;
  for (const tool of factories.flat()) {
    const spec = unwrap(tool.inputSchema?.host);
    if (!spec) continue;
    checked += 1;
    const desc = spec.description ?? spec._def?.description ?? '';
    if (!desc.startsWith(HOST_ARG_DESCRIPTION)) {
      offenders.push(`${tool.name}: ${JSON.stringify(desc).slice(0, 80)}`);
    }
  }

  assert.ok(checked > 10, `expected many host-taking tools, found ${checked} -- unwrap is broken`);
  assert.deepEqual(offenders, [], `these declare their own host description:\n  ${offenders.join('\n  ')}`);
});

test('every tool named by a group actually exists', async () => {
  const names = new Set((await realCatalog()).map((t) => t.name));
  for (const [group, members] of Object.entries(TOOL_GROUPS)) {
    for (const member of members) {
      assert.ok(names.has(member), `${group} names "${member}", which is not a registered tool`);
    }
  }
});

test('@readonly covers exactly the tools that cannot mutate', async () => {
  const catalog = await realCatalog();
  const readonly = new Set(TOOL_GROUPS['@readonly']);
  for (const tool of catalog) {
    // `mutating` may be a predicate (call_api), meaning "depends on arguments";
    // those are allowed in @readonly because their default form is a read.
    if (tool.mutating === false) {
      assert.ok(readonly.has(tool.name), `${tool.name} does not mutate but is missing from @readonly`);
    }
    if (tool.mutating === true) {
      assert.ok(!readonly.has(tool.name), `${tool.name} mutates but is listed in @readonly`);
    }
  }
});

test('with no policy file the server is unrestricted, preserving existing behaviour', () => {
  const p = unrestrictedProfile();
  assert.equal(p.allowsHost({ name: 'anything', ip: '1.2.3.4' }), true);
  assert.equal(p.allowsTool('run_command'), true);
  assert.equal(p.allowsPath('/etc/shadow'), true);
  assert.equal(p.allowsMutations(), true);
});
