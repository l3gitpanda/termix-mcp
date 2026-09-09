// What to answer when an inbound request matches no live session.
//
// Two conditions used to collapse into one 400, and only one of them is a bad
// request:
//
//   1. The request carries an Mcp-Session-Id this server does not know. That
//      session was TERMINATED -- the usual cause is a container restart, since
//      the registry is in memory by design. Streamable HTTP defines exactly one
//      recovery signal for this: 404, on which a client MUST start a new
//      session with a fresh InitializeRequest. It recovers on nothing else.
//   2. The request carries no session id and is not an initialize. That is a
//      genuine client protocol error, and 400 is right.
//
// Answering 400 for case 1 told a compliant client its request was malformed --
// a permanent error, not a recoverable one -- so it never re-initialized and
// stayed stranded until a human reconnected it. Every restart broke every
// connected client, including the SSE reconnect, which carries the session id
// and so hit the same wrong status.
//
// Session persistence across restarts is deliberately NOT the fix: the spec
// does not ask for it, and a durable session store would reintroduce the
// session-fixation risk the cross-profile check exists to prevent.
//
// Returns null when the request should proceed to create a new session.
export function routeUnmatchedSession({ sessionId, method, isInitialize }) {
  if (sessionId) {
    return {
      status: 404,
      body: { error: 'session not found or expired; start a new one with initialize' },
    };
  }
  if (method !== 'POST') {
    return { status: 400, body: { error: 'missing mcp-session-id' } };
  }
  if (!isInitialize) {
    return { status: 400, body: { error: 'no session; expected an initialize request' } };
  }
  return null;
}

// Node reports an IPv4 peer on a dual-stack socket as ::ffff:10.0.0.2, so
// a configured trusted proxy written the ordinary way would never match.
function normalizeAddress(value) {
  const text = String(value ?? '').trim();
  if (!text) return '';
  return text.startsWith('::ffff:') ? text.slice(7) : text;
}

// Which address to attribute a request to, given that a reverse proxy is in
// front of this server.
//
// Behind a reverse proxy the socket peer is ALWAYS that proxy, so the useful
// X-Forwarded-For. But that header is caller-supplied: honouring it whenever it
// appears would let anyone reaching the published port write whatever source
// address they like into the audit trail, which is worse than recording none at
// all. So it is read only when the direct peer is a configured trusted proxy.
//
// The RIGHTMOST entry is the one that proxy appended, and therefore the only one
// it vouches for -- a client sending its own X-Forwarded-For prepends to the
// list and cannot displace it. For a chain more than one proxy deep, walk
// right-to-left past addresses that are themselves trusted.
export function resolveClientAddress({ socketAddress, forwardedFor, trustedProxies = [] }) {
  const peer = normalizeAddress(socketAddress);
  const trusted = new Set(trustedProxies.map(normalizeAddress).filter(Boolean));

  if (!peer) return { address: 'unknown', forwarded: false };
  if (!trusted.has(peer) || !forwardedFor) return { address: peer, forwarded: false };

  const hops = String(forwardedFor).split(',').map(normalizeAddress).filter(Boolean);
  for (let i = hops.length - 1; i >= 0; i -= 1) {
    if (!trusted.has(hops[i])) return { address: hops[i], forwarded: true };
  }
  // Every hop was a trusted proxy: nothing here identifies an originating
  // client, so report the peer rather than inventing one.
  return { address: peer, forwarded: false };
}

// Which sessions to drop from the live registry.
//
// An entry leaves the map only when its transport closes, and a client that
// simply goes away never closes one. Reconnecting is the NORMAL case -- an
// unknown session id correctly gets a 404 and the client re-initializes -- so
// each reconnect strands a whole McpServer, and with it a session manager whose
// own SSH pool is bounded separately. That makes the real ceiling on Termix
// sessions maxSessions PER MCP SESSION rather than overall.
//
// Idle entries go first. If the cap is still exceeded, the least recently seen
// go until it is met. `keep` is the session serving the current request, which
// must never be selected.
export function selectExpiredSessions({
  sessions, now, idleMs, maxSessions, keep = null,
}) {
  const entries = [...sessions.entries()]
    .map(([id, entry]) => ({ id, lastSeen: entry?.lastSeen ?? 0 }))
    .filter((entry) => entry.id !== keep);

  const drop = new Map();
  if (Number.isFinite(idleMs) && idleMs > 0) {
    for (const entry of entries) {
      if (now - entry.lastSeen >= idleMs) drop.set(entry.id, 'idle');
    }
  }

  if (Number.isFinite(maxSessions) && maxSessions > 0) {
    const surviving = entries
      .filter((entry) => !drop.has(entry.id))
      .sort((a, b) => a.lastSeen - b.lastSeen);
    // The kept session still occupies a slot even though it is not a candidate.
    let over = surviving.length + (keep ? 1 : 0) - maxSessions;
    for (let i = 0; i < surviving.length && over > 0; i += 1, over -= 1) {
      drop.set(surviving[i].id, 'over-capacity');
    }
  }

  return [...drop.entries()].map(([id, reason]) => ({ id, reason }));
}
