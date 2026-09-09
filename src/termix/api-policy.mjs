// Policy for the call_api escape hatch.
//
// call_api exists so the model can reach the ~240 Termix endpoints that have no
// dedicated tool. Unguarded, it also reaches every endpoint that hands out
// credentials or opens a connection -- which would make the host blocklist and
// the mutation gate advisory rather than enforced. This module is what keeps
// call_api from being a hole in both.

// Endpoints call_api must never reach, whatever the method.
const FORBIDDEN = [
  [/^\/host\/db\/host\/[^/]+\/password\b/, 'returns a stored host password'],
  [/^\/host\/db\/host\/internal/, 'returns internal host data including credentials'],
  // Exports embed decrypted credentials unless share=1, and the escape hatch
  // has no business dumping the whole inventory either way.
  [/^\/host\/db\/hosts\/export/, 'exports every host with decrypted credentials'],
  [/^\/host\/db\/host\/[^/]+\/export/, 'exports a host with its decrypted credentials'],
  [/^\/credentials(\/|$)/, 'reads or writes stored SSH credentials'],
  [/^\/vault(\/|$)/, 'vault profiles hold credential material'],
  [/^\/termix-id\/linked-credentials/, 'exposes credential linkage'],
  [/^\/users\/api-keys/, 'lists or mints Termix API keys'],
  [/^\/users\/me\/token/, 'returns the current session token'],
  [/^\/users\/webauthn\/credentials/, 'passkey material'],
  [/^\/users\/(admin\/reset-password|change-password|internal\/auto-session)/, 'account credential operation'],
  [/^\/host\/quick-connect/, 'connects to an arbitrary address, bypassing the host blocklist'],
  [/^\/host\/enroll/, 'enrolls a new host using an API key'],
  [/^\/guacamole(\/|$)/, 'issues remote-desktop connection tokens'],
  [/^\/session-sharing(\/|$)/, 'shares a live session with other people'],
  [/^\/rbac\/.*\/share/, 'grants other users access to a host or snippet'],
  // Termix 2.7.0 added three surfaces that reach a shell without going through
  // resolveAllowed. Each stores its target server-side and runs later, so the
  // request carries no host id for extractHostIds to find: the blocklist, the
  // access profile, the mutation gate and this server's audit log are bypassed
  // together, and the command lands on the host with nothing here to explain
  // it. Remote execution belongs to run_command, which enforces all four.
  //
  // Denied by whole prefix rather than per-route -- as /vault, /guacamole and
  // /session-sharing already are -- because these are new and unexercised, and
  // the rule at the top of extractHostIds applies just as well here: a false
  // refusal on the escape hatch is recoverable, a false pass is not. Narrow
  // them once the surface has been reviewed against a live 2.7.0 instance.
  [/^\/automations(\/|$)/, 'an automation step can be a run_command action, so this executes on hosts outside the blocklist, the access profile and the audit log'],
  [/^\/fleet(\/|$)/, 'fleet operations execute across every member host at once, outside the blocklist, the access profile and the audit log'],
  // The entire safety model of Termix AI is that a proposed command runs only
  // after a human approves it -- and /ai/proposals/:id/apply IS that approval,
  // so the hatch would be able to approve proposals it had just generated
  // itself via /ai/chat/stream. /ai/providers additionally stores third-party
  // provider API keys, which no rule above and no SENSITIVE_SEGMENTS term covers.
  [/^\/ai(\/|$)/, 'applies AI-proposed commands and stores third-party provider API keys'],
  // Session establishment must go through the real tools, which resolve the
  // host and apply the blocklist first.
  [/^\/ssh\/file_manager\/ssh\/connect/, 'opens an SSH session; use the file tools so the blocklist applies'],
  [/^\/docker\/ssh\/connect/, 'opens an SSH session; use the docker tools so the blocklist applies'],
  [/^\/ssh\/file_manager\/sudo-password/, 'sets a sudo password on a session'],
];

// Where a host id can appear in a path, so a targeted call can be blocklist-checked.
const HOST_ID_IN_PATH = [
  /^\/host\/db\/host\/(\d+)/,
  /^\/status\/(\d+)/,
  /^\/metrics\/(?:history\/)?(\d+)/,
  /^\/host-metrics\/(?:managers\/[^/]+|platform|preferences)\/(\d+)/,
  /^\/host\/command-history\/(\d+)/,
  /^\/host\/opkssh\/token\/(\d+)/,
  /^\/rbac\/host\/(\d+)/,
  /^\/credentials\/[^/]+\/apply-to-host\/(\d+)/,
];

// Terms that make a path segment credential-bearing wherever it appears. The
// FORBIDDEN patterns above are anchored at the root, which is correct for the
// routes Termix has today -- but it means /ssh/credentials and /api/credentials
// sail past a rule written for /credentials. Any Termix release that remounts a
// credential route under a prefix would escape the denylist silently, and an
// escape hatch is the wrong place to be one release behind.
const SENSITIVE_SEGMENTS = new Set([
  'credentials', 'credential', 'vault', 'password', 'passwords',
  'api-keys', 'apikeys', 'api_key', 'apikey', 'webauthn', 'passkey', 'passkeys',
  'private-key', 'privatekey', 'secret', 'secrets',
]);

// Body/query fields that name a host.
const HOST_ID_FIELDS = ['hostId', 'sourceHostId', 'host_id'];

// Paths whose stateful sessions this server owns. A call_api request touching
// one must present a session this server opened, so a leaked or guessed session
// id cannot be used to reach a host the blocklist forbids.
const SESSION_SCOPED = [/^\/ssh\/file_manager\//, /^\/docker\//];

// Reduce a caller-supplied path to the single form every rule is matched
// against, and that is then sent upstream -- so what was checked is exactly what
// is transmitted. Without this the rules are decorative: nginx (merge_slashes)
// and Express (case-insensitive routing by default) both re-normalize
// "/Host/DB/Host/2//Password" back onto the very route the denylist forbids.
export function canonicalizePath(rawPath) {
  // Collapse repeated separators BEFORE any URL parsing, and again after every
  // step that can reintroduce them. A leading "//" is a protocol-relative URL,
  // so new URL("//users/me") reads `users` as the HOST and yields pathname
  // "/me" -- the first segment silently eaten. Collapsing only at the end, as
  // this used to, is too late: "//credentials" had already become "/" and
  // walked past the credential denylist. Same class as the earlier
  // canonicalisation flaw -- the rules judged a path the caller never wrote.
  const collapse = (p) => String(p).replace(/\/{2,}/g, '/');

  let path = new URL(collapse(rawPath), 'http://x').pathname;

  // Percent-decode to a fixed point, so %70 and %2570 both collapse.
  for (let i = 0; i < 5; i += 1) {
    let decoded;
    try {
      decoded = decodeURIComponent(path);
    } catch {
      break; // malformed escape: keep the last good form
    }
    if (decoded === path) break;
    path = decoded;
  }

  // Decoding can reveal traversal, an authority, or a fresh "//", so collapse
  // and resolve again after it.
  path = new URL(collapse(path), 'http://x').pathname;
  path = collapse(path);
  if (path.length > 1) path = path.replace(/\/+$/, '');
  return path;
}

// Methods that change state. A denylist entry can apply to writes only.
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// Creating or renaming a host record would move a machine off a blocklist that
// is keyed on name and IP, so host records are read-only through the hatch.
const FORBIDDEN_WRITES = [
  [/^\/host\/db\/hosts?(\/|$)/, 'creates or rewrites host records, which would move a host off the blocklist'],
  [/^\/host\/bulk-(import|update)/, 'rewrites host records in bulk, which would move a host off the blocklist'],
  [/^\/host\/ssh-config-import/, 'creates host records from an SSH config'],
];

export function checkForbidden(rawPath, method = 'GET') {
  const path = canonicalizePath(rawPath).toLowerCase();
  for (const [re, why] of FORBIDDEN) {
    if (re.test(path)) return why;
  }
  if (WRITE_METHODS.has(String(method).toUpperCase())) {
    for (const [re, why] of FORBIDDEN_WRITES) {
      if (re.test(path)) return why;
    }
  }
  // Prefix-independent backstop: a credential term in ANY segment, so a route
  // remounted under a prefix in some later Termix release cannot slip past the
  // root-anchored rules above.
  for (const segment of path.split('/')) {
    if (segment && SENSITIVE_SEGMENTS.has(segment)) {
      return `contains the credential-bearing path segment "${segment}"`;
    }
  }
  return null;
}

// Field names are compared normalized, so hostID / host_id / HostId are all
// recognised -- an unrecognised spelling would skip the blocklist entirely.
const normalizeKey = (key) => String(key).toLowerCase().replace(/[_\-\s]/g, '');
const HOST_ID_KEYS = new Set(HOST_ID_FIELDS.map(normalizeKey));

// Every host id this request targets, from the path and from body/query fields.
export function extractHostIds(rawPath, query, body) {
  const path = canonicalizePath(rawPath).toLowerCase();
  const ids = new Set();
  for (const re of HOST_ID_IN_PATH) {
    const m = re.exec(path);
    if (m) ids.add(m[1]);
  }
  // Plus every all-digit segment, because the list above enumerates the routes
  // Termix has TODAY. A future /…/:hostId route would otherwise reach a
  // blocklisted host through the escape hatch while the dedicated tools refuse
  // it -- and the tool's own description promises the same blocklist applies.
  //
  // This over-matches on purpose: a numeric segment that is really a snippet or
  // alert id gets checked as though it were a host, so call_api on such a path
  // is refused when that number happens to be a blocklisted host id. A false
  // refusal on the escape hatch is recoverable -- use the dedicated tool -- and
  // a false pass is not.
  for (const segment of path.split('/')) {
    if (/^\d+$/.test(segment)) ids.add(segment);
  }
  for (const source of [query, body]) {
    if (!source || typeof source !== 'object') continue;
    for (const [key, value] of Object.entries(source)) {
      const normalized = normalizeKey(key);
      if (HOST_ID_KEYS.has(normalized) && value !== undefined && value !== null && value !== '') {
        ids.add(String(value));
      }
      if (normalized === 'hostids' && Array.isArray(value)) {
        for (const entry of value) ids.add(String(entry));
      }
    }
  }
  return [...ids];
}

// The session id a request carries, if it targets a session-scoped surface.
export function extractSessionId(rawPath, query, body) {
  const path = canonicalizePath(rawPath);
  const lower = path.toLowerCase();
  if (!SESSION_SCOPED.some((re) => re.test(lower))) return null;
  const fromPath = /^\/docker\/(?:containers|validate)\/([^/]+)/.exec(lower);
  // Read the id from the ORIGINAL-case path: session ids are case-sensitive.
  if (fromPath) return path.split('/')[3] ?? null;
  return query?.sessionId ?? body?.sessionId ?? null;
}
