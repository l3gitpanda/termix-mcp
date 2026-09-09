import { fileSessionId, dockerSessionId } from '../util/ids.mjs';

// Manages the stateful SSH sessions Termix requires for file operations and
// Docker control. The frontend opens one such session per host and keeps it
// warm; this does the same, lazily, on behalf of the model. Two pools share the
// same lifecycle machinery.
//
// A session that Termix has forgotten (backend restart, its own idle sweep)
// surfaces as a 400 "not connected" on the next op; ensureConnected transparently
// reconnects once. Per-host serialization is enforced by the gate's mutex, so
// this module assumes it is never called concurrently for the same host.

const KIND = {
  file: {
    connectPath: '/ssh/file_manager/ssh/connect',
    keepalivePath: '/ssh/file_manager/ssh/keepalive',
    disconnectPath: '/ssh/file_manager/ssh/disconnect',
    makeId: fileSessionId,
  },
  docker: {
    connectPath: '/docker/ssh/connect',
    keepalivePath: '/docker/ssh/keepalive',
    disconnectPath: '/docker/ssh/disconnect',
    makeId: dockerSessionId,
  },
};

// A connect response is only usable when status === "success". Every other
// documented shape means the host needs interaction this server cannot provide.
function connectProblem(kind, response) {
  if (kind === 'docker') {
    // Docker connect returns { message } on success; treat an error field or a
    // requires_* flag as a problem.
    if (response?.requires_totp) return 'host requires a TOTP code';
    if (response?.requires_warpgate) return 'host requires Warpgate authentication';
    if (response?.error) return response.error;
    return null;
  }
  if (response?.status === 'success') return null;
  if (response?.requires_totp) return 'host requires a TOTP code';
  if (response?.requires_warpgate) return 'host requires Warpgate authentication';
  if (response?.status === 'passphrase_required') return 'host key needs a passphrase';
  if (response?.status === 'auth_required') return 'host needs interactive authentication';
  if (response?.status === 'error') return response.message || 'connection failed';
  return `unexpected connect status: ${response?.status ?? 'none'}`;
}

export function createSessionManager({ client, config, logger, audit, wazuh }) {
  // Session open/close is an authenticated SSH connection to a real host. It
  // outlives the tool call that caused it (keepalive holds it open), so it
  // belongs in the audit trail, not only in the app log -- otherwise a
  // connection in Termix's logs at 02:00 has nothing here to explain it.
  function auditEvent(event, session, extra = {}) {
    if (!audit) return;
    const entry = {
      ts: new Date().toISOString(),
      event,
      kind: session.kind,
      host: { id: session.host?.id ?? session.hostId, name: session.host?.name, ip: session.host?.ip },
      sessionId: session.sessionId,
      ok: true,
      ...extra,
    };
    audit.record(entry);
    wazuh?.emit(entry);
  }

  const pools = { file: new Map(), docker: new Map() };
  let keepaliveTimer = null;
  let idleTimer = null;
  let closed = false;

  function evictOldestIfFull() {
    const total = pools.file.size + pools.docker.size;
    if (total < config.maxSessions) return;
    let oldest = null;
    for (const kind of ['file', 'docker']) {
      for (const s of pools[kind].values()) {
        // Same reasoning as the idle sweep: a session carrying a running
        // command is the opposite of idle, whatever its lastActive says.
        if (s.inFlight > 0) continue;
        if (!oldest || s.lastActive < oldest.lastActive) oldest = s;
      }
    }
    if (oldest) {
      logger.info({ hostId: oldest.hostId, kind: oldest.kind }, 'evicting LRU session (pool full)');
      return teardown(oldest.kind, oldest.hostId, 'lru-evicted');
    }
    // Every session is busy, so there is nothing safe to evict and the pool
    // overshoots maxSessions rather than killing a live command. Temporary by
    // construction -- each of those sessions becomes evictable the moment its
    // operation returns -- but logged, because a cap that silently stops
    // holding is worse than one that says so.
    logger.warn({ total, max: config.maxSessions }, 'session pool over cap: all sessions have work in flight');
  }

  async function connect(kind, host) {
    const spec = KIND[kind];
    const sessionId = spec.makeId(host.id);
    const body = kind === 'docker'
      ? { sessionId, hostId: host.id }
      : { sessionId, hostId: host.id, ip: host.ip, port: host.port, username: host.username };

    const response = await client.post(spec.connectPath, body);
    const problem = connectProblem(kind, response);
    if (problem) {
      const err = new Error(`cannot open ${kind} session on ${host.name || host.ip}: ${problem}`);
      err.unsupported = true;
      throw err;
    }

    // inFlight counts operations currently running against this session.
    // lastActive is stamped when a call STARTS and again when it finishes, so
    // between those two points the counter is the only thing that says the
    // session is alive; see withSession and runIdleSweep.
    const session = { kind, sessionId, hostId: host.id, host, lastActive: Date.now(), inFlight: 0 };
    pools[kind].set(host.id, session);
    logger.info({ hostId: host.id, kind, sessionId }, 'opened session');
    auditEvent('session.open', session);
    return session;
  }

  // Returns a live session for the host, opening one if needed. Docker sessions
  // additionally validate that Docker is actually reachable on the host.
  async function ensure(kind, host) {
    await evictOldestIfFull();
    let session = pools[kind].get(host.id);
    if (!session) {
      session = await connect(kind, host);
      if (kind === 'docker') {
        try {
          await client.get(`/docker/validate/${session.sessionId}`);
        } catch (error) {
          await teardown('docker', host.id, 'docker-unavailable');
          throw new Error(`Docker is not available on ${host.name || host.ip}: ${error.message}`);
        }
      }
    }
    session.lastActive = Date.now();
    startTimers();
    return session;
  }

  // Run an operation against a host's session, reconnecting once if Termix has
  // forgotten the session out from under us.
  // Runs op with the session marked busy, and re-stamps lastActive when it
  // finishes. Without the second stamp the idle sweep measures from the moment
  // a call STARTED, so a command that runs longer than TERMIX_SESSION_IDLE_MS
  // has its own session disconnected out from under it -- which is why the exec
  // timeout had to be kept below the idle window. The counter decouples them.
  async function runInFlight(session, op) {
    session.inFlight += 1;
    try {
      return await op(session);
    } finally {
      session.inFlight -= 1;
      session.lastActive = Date.now();
    }
  }

  async function withSession(kind, host, op) {
    const session = await ensure(kind, host);
    try {
      return await runInFlight(session, op);
    } catch (error) {
      if (isStaleSession(error)) {
        logger.warn({ hostId: host.id, kind }, 'session stale, reconnecting once');
        pools[kind].delete(host.id);
        const fresh = await ensure(kind, host);
        return runInFlight(fresh, op);
      }
      throw error;
    }
  }

  function isStaleSession(error) {
    const status = error?.status;
    const msg = String(error?.message ?? '').toLowerCase();
    return (status === 400 || status === 404)
      && (msg.includes('not connected')
        || msg.includes('session not found')
        || msg.includes('not available')
        || msg.includes('no ssh'));
  }

  async function teardown(kind, hostId, reason = 'explicit') {
    const session = pools[kind].get(hostId);
    if (!session) return;
    pools[kind].delete(hostId);
    auditEvent('session.close', session, { reason });
    try {
      await client.post(KIND[kind].disconnectPath, { sessionId: session.sessionId });
    } catch (error) {
      logger.debug({ hostId, kind, err: error.message }, 'disconnect on teardown failed (already gone?)');
    }
    if (pools.file.size + pools.docker.size === 0) stopTimers();
  }

  function startTimers() {
    if (closed) return;
    if (!keepaliveTimer) {
      keepaliveTimer = setInterval(runKeepalive, config.keepaliveMs);
      keepaliveTimer.unref?.();
    }
    if (!idleTimer) {
      idleTimer = setInterval(runIdleSweep, Math.max(30000, Math.floor(config.sessionIdleMs / 2)));
      idleTimer.unref?.();
    }
  }

  function stopTimers() {
    if (keepaliveTimer) { clearInterval(keepaliveTimer); keepaliveTimer = null; }
    if (idleTimer) { clearInterval(idleTimer); idleTimer = null; }
  }

  async function runKeepalive() {
    for (const kind of ['file', 'docker']) {
      for (const session of [...pools[kind].values()]) {
        try {
          await client.post(KIND[kind].keepalivePath, { sessionId: session.sessionId });
        } catch (error) {
          logger.debug({ hostId: session.hostId, kind, err: error.message }, 'keepalive failed');
        }
      }
    }
  }

  async function runIdleSweep() {
    const now = Date.now();
    for (const kind of ['file', 'docker']) {
      for (const session of [...pools[kind].values()]) {
        // A session with work in flight is not idle no matter how long ago
        // lastActive was stamped -- that stamp is the START of the call.
        if (session.inFlight > 0) continue;
        if (now - session.lastActive >= config.sessionIdleMs) {
          logger.info({ hostId: session.hostId, kind }, 'disconnecting idle session');
          await teardown(kind, session.hostId, 'idle');
        }
      }
    }
  }

  async function closeAll() {
    closed = true;
    stopTimers();
    const jobs = [];
    for (const kind of ['file', 'docker']) {
      for (const hostId of [...pools[kind].keys()]) jobs.push(teardown(kind, hostId, 'shutdown'));
    }
    await Promise.allSettled(jobs);
  }

  function stats() {
    return { file: pools.file.size, docker: pools.docker.size };
  }

  // Did this server open that session? call_api uses this so a stateful request
  // cannot ride a session id the blocklist never vetted.
  function ownsSession(sessionId) {
    if (!sessionId) return false;
    for (const kind of ['file', 'docker']) {
      for (const session of pools[kind].values()) {
        if (session.sessionId === sessionId) return true;
      }
    }
    return false;
  }

  // The live session id for a host, for audit records.
  function sessionIdFor(hostId) {
    return pools.file.get(hostId)?.sessionId ?? pools.docker.get(hostId)?.sessionId ?? null;
  }

  return {
    withFileSession: (host, op) => withSession('file', host, op),
    withDockerSession: (host, op) => withSession('docker', host, op),
    ensureFile: (host) => ensure('file', host),
    ensureDocker: (host) => ensure('docker', host),
    teardown,
    // The same routine the idle timer runs, on demand. Exposed so the
    // in-flight rule can be tested without waiting out a 30-second interval.
    sweepIdle: runIdleSweep,
    closeAll,
    stats,
    ownsSession,
    sessionIdFor,
  };
}
