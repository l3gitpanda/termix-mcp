// Host lookup and blocklist classification. Every tool that targets a host
// resolves it through here first, so the blocklist is enforced in exactly one
// place and a host record always arrives with its connection fields intact.

// Normalize whatever GET /host/db/host returns into the fields the rest of the
// server relies on. Termix has carried slightly different key casings across
// versions, so read defensively rather than assume one shape.
function normalizeHost(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const id = raw.id ?? raw.hostId;
  if (id === undefined || id === null) return null;
  return {
    id,
    name: raw.name ?? raw.label ?? '',
    ip: raw.ip ?? raw.host ?? raw.address ?? '',
    port: raw.port ?? 22,
    username: raw.username ?? raw.user ?? '',
    folder: raw.folder ?? '',
    tags: Array.isArray(raw.tags) ? raw.tags : [],
    authType: raw.authType ?? raw.auth_type ?? '',
    enableTerminal: raw.enableTerminal ?? true,
    enableFileManager: raw.enableFileManager ?? true,
    enableTunnel: raw.enableTunnel ?? false,
    enableDocker: raw.enableDocker ?? raw.dockerEnabled ?? false,
  };
}

// `profile` carries the caller's access policy. It is applied inside
// resolveAllowed -- the one function every host-targeting path already goes
// through -- so a new tool cannot reach a machine the profile forbids by
// forgetting to ask.
export function createHostRegistry(client, blocklist, logger, profile = null) {
  const blocked = new Set(blocklist.map((entry) => entry.toLowerCase()));

  // Whether the global TERMIX_BLOCKLIST applies at all. A profile may opt out
  // of it -- deliberately, and it is warned about at load -- so that the
  // env-level list can be a default for most callers without being a ceiling
  // that no profile can ever be granted past.
  const globalBlocklistApplies = profile?.enforcesGlobalBlocklist?.() ?? true;

  // A host is blocked when its name OR its IP matches a blocklist entry
  // exactly (case-insensitive). Exact, not substring, so "app" blocks that
  // one host without also blocking "app-main". Name is the primary key because a
  // DHCP host's IP can change out from under a pinned entry.
  function isBlocked(host) {
    if (!host || !globalBlocklistApplies) return false;
    const name = String(host.name ?? '').toLowerCase();
    const ip = String(host.ip ?? '').toLowerCase();
    return (name && blocked.has(name)) || (ip && blocked.has(ip));
  }

  async function list() {
    const raw = await client.get('/host/db/host');
    const arr = Array.isArray(raw) ? raw : (raw?.hosts ?? []);
    return arr.map(normalizeHost).filter(Boolean);
  }

  // Fetch a single host by numeric id. Falls back to scanning the list if the
  // by-id endpoint is unavailable on this instance.
  async function getById(id) {
    try {
      const raw = await client.get(`/host/db/host/${id}`);
      const host = normalizeHost(raw);
      if (host) return host;
    } catch (error) {
      logger?.debug({ id, err: error.message }, 'host by-id lookup failed, scanning list');
    }
    const all = await list();
    return all.find((h) => String(h.id) === String(id)) ?? null;
  }

  // Resolve a tool's host argument, which may be a numeric id or a name/IP
  // string, into a normalized host record. Throws if it cannot be found so the
  // caller never operates on a guessed target.
  async function resolve(hostRef) {
    if (hostRef === undefined || hostRef === null || hostRef === '') {
      throw new Error('a host id or name is required');
    }
    if (typeof hostRef === 'number' || /^\d+$/.test(String(hostRef))) {
      const host = await getById(hostRef);
      if (!host) throw new Error(`no host with id ${hostRef}`);
      return host;
    }
    const needle = String(hostRef).toLowerCase();
    const all = await list();
    const matches = all.filter(
      (h) => h.name.toLowerCase() === needle || h.ip.toLowerCase() === needle,
    );
    if (!matches.length) throw new Error(`no host named ${hostRef}`);
    // First-match-wins was the one place this file guessed. Two hosts sharing
    // an address is not hypothetical -- a pair of stopped guests both report
    // 0.0.0.0 -- and on run_command or write_file it means the call lands on a
    // different machine than the caller named, with nothing to show for it.
    // Refuse and name the candidates: an ambiguous target is an error, not a
    // coin flip. Addressing by id stays unambiguous and is the way out.
    if (matches.length > 1) {
      const candidates = matches.map((h) => `${h.name || '(unnamed)'} (id ${h.id}, ${h.ip})`);
      throw new Error(
        `"${hostRef}" matches ${matches.length} hosts: ${candidates.join('; ')}. `
        + 'Address one by its numeric id.',
      );
    }
    return matches[0];
  }

  // Is this host outside what the caller's profile grants? Separate from the
  // global blocklist so the refusal can say which rule applied.
  function isOutsideProfile(host) {
    return !!profile && !profile.allowsHost(host);
  }

  // Resolve AND enforce both the global blocklist and the caller's profile.
  // Tools call this, never resolve() directly.
  async function resolveAllowed(hostRef) {
    const host = await resolve(hostRef);
    // `reason` distinguishes the two, because they live in different config and
    // send whoever reads the refusal to different places: the blocklist is
    // TERMIX_BLOCKLIST in the environment, the profile is the policy file. A
    // lone `blocked` boolean made every profile denial also claim the host was
    // blocklisted -- a wrong answer to "why can it not reach this?".
    if (isBlocked(host)) {
      const err = new Error(
        `host ${host.name || host.ip} is on the blocklist and cannot be accessed`,
      );
      err.blocked = true;
      err.reason = 'blocklist';
      throw err;
    }
    if (isOutsideProfile(host)) {
      const err = new Error(
        `host ${host.name || host.ip} is not granted to the "${profile.name}" access profile`,
      );
      err.blocked = true;
      err.reason = 'profile';
      throw err;
    }
    return host;
  }

  return {
    list, getById, resolve, resolveAllowed, isBlocked, isOutsideProfile, normalizeHost,
  };
}
