import fs from 'node:fs';
import crypto from 'node:crypto';
import {
  globToRegExp, pathGlobToRegExp, normalizePath, decideValue, MODES,
} from './match.mjs';
import { expandGroups } from './groups.mjs';

// Per-profile access control: which machines a caller may reach, whether it may
// write at all, which tools it may call, and which paths it may touch.
//
// A profile is selected by the bearer token on the HTTP transport, or by
// TERMIX_PROFILE on stdio.
//
// Each dimension carries its own MODE, so the scope of every restriction is a
// deliberate choice rather than a posture baked into the server:
//   allowlist (fail closed) | blocklist (fail open) | all (off) | none (locked)
// The global TERMIX_BLOCKLIST can likewise be enforced or ignored per profile.

const sha256 = (value) => crypto.createHash('sha256').update(String(value)).digest();

// Secrets can be given inline, pre-hashed, or by env var name, so the policy
// file itself can be committed alongside the rest of the compose config while
// the actual tokens stay in the secrets env file.
function resolveSecret(spec, field, profileName) {
  const inline = spec[field];
  const fromEnv = spec[`${field}Env`];
  if (inline && fromEnv) {
    throw new Error(`profile "${profileName}": set either ${field} or ${field}Env, not both`);
  }
  if (fromEnv) {
    const value = process.env[fromEnv];
    if (!value) throw new Error(`profile "${profileName}": ${field}Env names ${fromEnv}, which is not set`);
    return value;
  }
  return inline ?? null;
}

// A dimension may be written as a full object, or as bare shorthand that reads
// naturally in a hand- or AI-written policy:
//   "hosts": "all"                      -> mode all
//   "hosts": ["app-main", "web-proxy"]   -> allowlist of those
//   "hosts": { "mode": "blocklist", "deny": ["legacy-box"] }
function normalizeDimension(spec) {
  if (spec === undefined || spec === null) return {};
  if (typeof spec === 'string') {
    if (!MODES.includes(spec)) {
      throw new Error(`"${spec}" is not a mode; use one of ${MODES.join(', ')}`);
    }
    return { mode: spec };
  }
  if (Array.isArray(spec)) return { mode: 'allowlist', allow: spec };
  if (typeof spec !== 'object') throw new Error('a rule set must be a string, array, or object');
  return spec;
}

// When no mode is given, infer the one the lists imply. This keeps every
// pre-existing policy meaning exactly what it used to mean, and makes the
// common cases writable without stating a mode at all.
function inferMode(spec, fallback) {
  if (spec.mode) {
    if (!MODES.includes(spec.mode)) {
      throw new Error(`mode must be one of ${MODES.join(', ')}, got "${spec.mode}"`);
    }
    return spec.mode;
  }
  if (spec.allow?.length) return 'allowlist';
  if (spec.deny?.length) return 'blocklist';
  return fallback;
}

function compileRules(rawSpec, toRegExp, { fallbackMode, expand = false, where = '' }) {
  const spec = normalizeDimension(rawSpec);
  const mode = inferMode(spec, fallbackMode);
  const allowList = expand ? expandGroups(spec.allow, { where }) : (spec.allow ?? []);
  const denyList = expand ? expandGroups(spec.deny, { where }) : (spec.deny ?? []);
  return {
    mode,
    allow: allowList.map(toRegExp),
    deny: denyList.map(toRegExp),
    // Kept for help, explain and diagnostics so an operator (or a model) can
    // see the effective rules, including what a @group expanded to.
    describe: {
      mode,
      allow: spec.allow ?? [],
      deny: spec.deny ?? [],
      ...(expand && (spec.allow?.some((p) => String(p).startsWith('@'))
        || spec.deny?.some((p) => String(p).startsWith('@')))
        ? { expanded: { allow: allowList, deny: denyList } }
        : {}),
    },
  };
}

function buildProfile(name, spec) {
  if (!spec || typeof spec !== 'object') throw new Error(`profile "${name}" must be an object`);

  const tokenPlain = resolveSecret(spec, 'token', name);
  const tokenHashHex = spec.tokenSha256 ?? null;
  const tokenDigest = tokenPlain ? sha256(tokenPlain)
    : (tokenHashHex ? Buffer.from(tokenHashHex, 'hex') : null);
  if (tokenDigest && tokenDigest.length !== 32) {
    throw new Error(`profile "${name}": tokenSha256 must be a 64-character hex digest`);
  }

  const mutations = spec.mutations ?? 'allow';
  if (!['allow', 'deny'].includes(mutations)) {
    throw new Error(`profile "${name}": mutations must be "allow" or "deny"`);
  }

  // Whether the global TERMIX_BLOCKLIST still applies on top of this profile.
  // "enforce" is the default so turning it off is always a deliberate act.
  const globalBlocklist = spec.globalBlocklist ?? 'enforce';
  if (!['enforce', 'ignore'].includes(globalBlocklist)) {
    throw new Error(`profile "${name}": globalBlocklist must be "enforce" or "ignore"`);
  }

  // Fallbacks apply only when a dimension names neither a mode nor any rule.
  // Hosts fail closed because the machine list is the boundary being drawn;
  // tools and paths default to unrestricted, since forcing every profile to
  // enumerate 34 tool names just to work invites a careless "*" everywhere.
  const hosts = compileRules(spec.hosts, globToRegExp, { fallbackMode: 'allowlist' });
  const tools = compileRules(spec.tools, globToRegExp, {
    fallbackMode: 'all', expand: true, where: `profile "${name}" tools`,
  });
  const paths = compileRules(spec.paths, pathGlobToRegExp, { fallbackMode: 'all' });

  // Path rules constrain the file tools, but a shell command reads and writes
  // wherever the SSH user can. A profile that restricts paths while keeping an
  // escape tool is not actually restricted, and that is worth saying out loud
  // at startup rather than letting it read as a control that holds.
  const allowsTool = (tool) => decideValue({
    candidates: String(tool), mode: tools.mode, allow: tools.allow, deny: tools.deny,
  });

  const warnings = [];
  if (paths.mode !== 'all') {
    const reachable = expandGroups(['@escape']).filter(allowsTool);
    if (reachable.length) {
      warnings.push(
        `profile "${name}" restricts paths but still grants ${reachable.join(', ')}; `
        + 'a shell command can reach any path the SSH user can, so the path rules are advisory. '
        + 'Deny those tools (or "tools": { "deny": ["@escape"] }) to make the restriction real.',
      );
    }
  }
  if (hosts.mode === 'allowlist' && !hosts.allow.length) {
    warnings.push(
      `profile "${name}" is a host allowlist that grants nothing, so every host-targeted tool `
      + 'will refuse. Use "hosts": "all" to leave machines unrestricted.',
    );
  }
  if (hosts.mode === 'all' && globalBlocklist === 'ignore') {
    warnings.push(
      `profile "${name}" reaches every host and ignores the global blocklist, so it has `
      + 'unrestricted machine access.',
    );
  }
  if (globalBlocklist === 'ignore') {
    warnings.push(
      `profile "${name}" ignores TERMIX_BLOCKLIST; hosts excluded globally are reachable by it.`,
    );
  }

  return {
    name,
    description: spec.description ?? '',
    warnings,
    tokenDigest,
    termixApiKey: resolveSecret(spec, 'termixApiKey', name),
    mutations,
    globalBlocklist,
    hostRules: hosts,
    toolRules: tools,
    pathRules: paths,

    // A host matches on either its name or its IP, so a rule can be written
    // whichever way the operator thinks about that machine.
    allowsHost(host) {
      if (!host) return false;
      const candidates = [host.name, host.ip].filter(Boolean).map(String);
      if (!candidates.length) return hosts.mode === 'all';
      return decideValue({ candidates, mode: hosts.mode, allow: hosts.allow, deny: hosts.deny });
    },
    allowsTool,
    allowsPath(path) {
      if (paths.mode === 'all') return true;
      const normalized = normalizePath(path);
      if (!normalized) return false;
      return decideValue({
        candidates: normalized, mode: paths.mode, allow: paths.allow, deny: paths.deny,
      });
    },
    allowsMutations() {
      return mutations !== 'deny';
    },
    // Does the global TERMIX_BLOCKLIST still apply to this profile?
    enforcesGlobalBlocklist() {
      return globalBlocklist === 'enforce';
    },
    summary() {
      return {
        profile: name,
        description: spec.description ?? '',
        hosts: hosts.describe,
        tools: tools.describe,
        paths: paths.describe,
        mutations,
        globalBlocklist,
      };
    },
    // Answer "what can this profile actually do" against real inputs, so a
    // generated policy can be checked before it is trusted rather than by
    // reading the rules and hoping.
    explain({ hosts: hostList = [], tools: toolList = [], paths: pathList = [] } = {}) {
      return {
        profile: name,
        description: spec.description ?? '',
        mutations,
        globalBlocklist,
        modes: { hosts: hosts.mode, tools: tools.mode, paths: paths.mode },
        hosts: hostList.map((h) => ({
          host: h.name || h.ip,
          allowed: this.allowsHost(h),
        })),
        tools: toolList.map((t) => ({ tool: t, allowed: allowsTool(t) })),
        paths: pathList.map((p) => ({
          path: p, normalized: normalizePath(p), allowed: this.allowsPath(p),
        })),
        warnings,
      };
    },
  };
}

// The profile used when no policy file is configured at all: current behaviour,
// where the global blocklist is the only host restriction.
export function unrestrictedProfile() {
  return {
    name: 'unrestricted',
    description: 'No policy file configured; only the global blocklist applies.',
    tokenDigest: null,
    termixApiKey: null,
    mutations: 'allow',
    globalBlocklist: 'enforce',
    warnings: [],
    allowsHost: () => true,
    allowsTool: () => true,
    allowsPath: () => true,
    allowsMutations: () => true,
    enforcesGlobalBlocklist: () => true,
    summary: () => ({
      profile: 'unrestricted',
      modes: { hosts: 'all', tools: 'all', paths: 'all' },
      mutations: 'allow',
      globalBlocklist: 'enforce',
    }),
    explain: () => ({ profile: 'unrestricted', modes: { hosts: 'all', tools: 'all', paths: 'all' } }),
  };
}

export function parsePolicy(raw) {
  const doc = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!doc || typeof doc !== 'object') throw new Error('policy must be a JSON object');
  const entries = Object.entries(doc.profiles ?? {});
  if (!entries.length) throw new Error('policy defines no profiles');

  const profiles = new Map();
  for (const [name, spec] of entries) profiles.set(name, buildProfile(name, spec));

  if (doc.defaultProfile && !profiles.has(doc.defaultProfile)) {
    throw new Error(`defaultProfile "${doc.defaultProfile}" is not defined`);
  }

  // Two profiles sharing a token would make access non-deterministic.
  const seen = new Set();
  for (const profile of profiles.values()) {
    if (!profile.tokenDigest) continue;
    const hex = profile.tokenDigest.toString('hex');
    if (seen.has(hex)) throw new Error(`two profiles share the same token (${profile.name})`);
    seen.add(hex);
  }

  return { defaultProfile: doc.defaultProfile ?? null, profiles };
}

export function createPolicyStore({ filePath, logger }) {
  let loaded = null;
  let mtimeMs = 0;

  function load() {
    const stat = fs.statSync(filePath);
    const parsed = parsePolicy(fs.readFileSync(filePath, 'utf8'));
    mtimeMs = stat.mtimeMs;
    loaded = parsed;
    logger?.info({ filePath, profiles: [...parsed.profiles.keys()] }, 'access policy loaded');
    for (const profile of parsed.profiles.values()) {
      for (const warning of profile.warnings ?? []) logger?.warn({ profile: profile.name }, warning);
    }
    return parsed;
  }

  // Reloaded when the file changes, so granting or revoking access does not
  // need a restart. A broken edit keeps the last good policy rather than
  // failing open.
  function current() {
    try {
      const stat = fs.statSync(filePath);
      if (!loaded || stat.mtimeMs !== mtimeMs) load();
    } catch (error) {
      if (!loaded) throw error;
      logger?.error({ err: error.message }, 'policy reload failed; keeping the previous policy');
    }
    return loaded;
  }

  function byName(name) {
    const policy = current();
    const profile = policy.profiles.get(name);
    if (!profile) throw new Error(`no such profile "${name}" in the access policy`);
    return profile;
  }

  // Compared over digests with timingSafeEqual, and every profile is examined
  // so the time taken does not reveal which token nearly matched.
  function byToken(token) {
    if (!token) return null;
    const presented = sha256(token);
    let matched = null;
    for (const profile of current().profiles.values()) {
      if (!profile.tokenDigest) continue;
      if (crypto.timingSafeEqual(presented, profile.tokenDigest)) matched = profile;
    }
    return matched;
  }

  load();
  return { current, byName, byToken, defaultName: () => current().defaultProfile };
}
