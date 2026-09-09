import http from 'node:http';
import crypto from 'node:crypto';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';

import { loadConfig } from './config.mjs';
import { createLogger } from './logging.mjs';
import { buildServer } from './mcp/server.mjs';
import {
  routeUnmatchedSession, resolveClientAddress, selectExpiredSessions,
} from './mcp/http-session.mjs';
import { createClient } from './termix/client.mjs';
import { version } from './version.mjs';
import { createPolicyStore, unrestrictedProfile } from './access/policy.mjs';

// Streamable-HTTP transport: the containerized deployment. Each MCP session gets
// its own McpServer instance so the per-session mutation flag never leaks
// between clients. The /mcp endpoint is guarded by MCP_HTTP_TOKEN (distinct from
// the Termix API key); /healthz is unauthenticated for the container probe.

const config = loadConfig('http');
const logger = createLogger({ level: config.logLevel, file: config.logFile });

// With a policy file, the bearer token identifies WHICH profile is calling, and
// MCP_HTTP_TOKEN is no longer the only key to the door. Without one, behaviour
// is unchanged: the single shared token, unrestricted access.
const policy = config.policyFile ? createPolicyStore({ filePath: config.policyFile, logger }) : null;

// sessionId -> { transport, server, sessions, wazuh, profile, lastSeen }
const sessions = new Map();

// Who is calling, for the app log and the audit trail. Without this every
// request behind the reverse proxy is attributed to the proxy, so a stolen
// token's use is indistinguishable from the operator's own.
function clientOf(req) {
  return resolveClientAddress({
    socketAddress: req.socket?.remoteAddress,
    forwardedFor: req.headers['x-forwarded-for'],
    trustedProxies: config.trustedProxies,
  });
}

// Correlates repeated attempts with the same wrong credential without ever
// writing one down. A prefix of a SHA-256 digest is not reversible.
function tokenFingerprint(token) {
  if (!token) return 'none';
  return crypto.createHash('sha256').update(token).digest('hex').slice(0, 8);
}

// Tear a session down and release what it holds. Idempotent: the transport's
// own onclose runs the same cleanup, and either order is safe.
async function dropSession(sid, reason) {
  const entry = sessions.get(sid);
  if (!entry) return;
  sessions.delete(sid);
  logger.info({ sid: `${sid.slice(0, 8)}...`, reason }, 'dropping mcp session');
  try {
    await entry.sessions.closeAll();
  } catch (error) {
    logger.warn({ sid: `${sid.slice(0, 8)}...`, err: error.message }, 'session cleanup failed');
  }
  entry.wazuh?.close();
  try {
    await entry.transport.close();
  } catch (error) {
    logger.debug({ sid: `${sid.slice(0, 8)}...`, err: error.message }, 'transport close failed');
  }
}

// Called on every request rather than on a timer: a server whose clients have
// all gone away has no reason to hold a timer open, and the registry only ever
// changes as a result of a request anyway.
async function reapSessions(keep = null) {
  const expired = selectExpiredSessions({
    sessions,
    now: Date.now(),
    idleMs: config.mcpSessionIdleMs,
    maxSessions: config.mcpMaxSessions,
    keep,
  });
  for (const { id, reason } of expired) await dropSession(id, reason);
}

// Hash both sides so timingSafeEqual compares equal-length buffers and the
// supplied token's length does not leak.
function tokenMatches(supplied, expected) {
  if (typeof supplied !== 'string' || !supplied) return false;
  const a = crypto.createHash('sha256').update(supplied).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

function bearer(req) {
  const header = req.headers.authorization ?? '';
  return header.startsWith('Bearer ') ? header.slice(7).trim() : header.trim();
}

const MAX_BODY_BYTES = 4 * 1024 * 1024;

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        // Destroy, don't just reject: without this the socket keeps streaming
        // into a promise nobody is listening to, so an oversized body still
        // costs the full transfer.
        req.destroy();
        reject(new Error('request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve(undefined);
      try { resolve(JSON.parse(raw)); } catch (error) { reject(error); }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(text);
}

// A browser on the operator's LAN can be lured into POSTing to this endpoint by
// a hostile page (DNS rebinding). The bearer token is the real control, but an
// Origin check costs nothing and stops the request before it is parsed. Requests
// with no Origin -- ordinary MCP clients and curl -- are unaffected.
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  if (!config.allowedOrigins.length) return false;
  return config.allowedOrigins.includes(origin);
}

async function handleMcp(req, res) {
  const client = clientOf(req);

  // Authentication FIRST, so an unauthenticated caller cannot tell a rejected
  // Origin (403) from a rejected token (401) and learn anything about how this
  // server is configured. The Origin check still runs before the body is read,
  // which is what the DNS-rebinding protection actually depends on.
  const presented = bearer(req);
  let profile;
  if (policy) {
    profile = policy.byToken(presented);
  } else if (tokenMatches(presented, config.httpToken)) {
    profile = unrestrictedProfile();
  }
  if (!profile) {
    // A failed authentication used to be answered in silence: no app log, and
    // no audit record either, because the gate only runs for a call that got
    // past this point. Probing or brute-forcing the one credential that reaches
    // shell on every host left no trace anywhere the SIEM could see it.
    logger.warn(
      {
        client: client.address,
        forwarded: client.forwarded || undefined,
        token: tokenFingerprint(presented),
        method: req.method,
      },
      'rejected unauthorized MCP request',
    );
    return sendJson(res, 401, { error: 'unauthorized' });
  }

  if (!originAllowed(req)) {
    logger.warn(
      { origin: req.headers.origin, client: client.address, profile: profile.name },
      'rejected cross-origin MCP request',
    );
    return sendJson(res, 403, { error: 'origin not allowed' });
  }

  const sessionId = req.headers['mcp-session-id'];

  // Existing session: hand straight to its transport, but only for the profile
  // that created it. Otherwise one token holder could present another's session
  // id and inherit its access and its enabled-writes state.
  if (sessionId && sessions.has(sessionId)) {
    const entry = sessions.get(sessionId);
    if (entry.profile.name !== profile.name) {
      logger.warn(
        {
          sid: `${sessionId.slice(0, 8)}...`,
          presented: profile.name,
          owner: entry.profile.name,
          client: client.address,
        },
        'rejected cross-profile session reuse',
      );
      return sendJson(res, 403, { error: 'session belongs to a different access profile' });
    }
    // Touch before reaping, so the session serving this request is current.
    entry.lastSeen = Date.now();
    entry.client = client;
    await reapSessions(sessionId);
    const body = req.method === 'POST' ? await readBody(req).catch(() => undefined) : undefined;
    return entry.transport.handleRequest(req, res, body);
  }

  // An unrecognised session id means that session was terminated -- almost
  // always a restart, since the registry above is in memory on purpose. That is
  // lifecycle, not a malformed request, and 404 is the only status a client
  // re-initializes on. See routeUnmatchedSession for why this distinction is
  // load-bearing. Note the cross-profile branch above stays 403: that session
  // exists and the caller is not entitled to it, and answering 404 there would
  // let a caller probe for other profiles' sessions.
  const body = req.method === 'POST' ? await readBody(req).catch(() => undefined) : undefined;
  const unmatched = routeUnmatchedSession({
    sessionId,
    method: req.method,
    isInitialize: isInitializeRequest(body),
  });
  if (unmatched) {
    if (sessionId) {
      logger.info(
        { sid: `${String(sessionId).slice(0, 8)}...` },
        'unknown session id; answering 404 so the client re-initializes',
      );
    }
    return sendJson(res, unmatched.status, unmatched.body);
  }

  // `peer` rides into the gate so every audit record says where the call came
  // from, not just which profile it used. Two holders of one token are
  // otherwise indistinguishable in the trail.
  const built = buildServer({
    config, logger, transport: 'http', profile, peer: client,
  });
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    onsessioninitialized: (sid) => {
      sessions.set(sid, {
        transport,
        server: built.server,
        sessions: built.sessions,
        wazuh: built.wazuh,
        profile,
        client,
        lastSeen: Date.now(),
      });
      // Truncated: a full session id in the app log is a usable credential for
      // anyone who can also read the shared bearer token.
      logger.info(
        { sid: `${sid.slice(0, 8)}...`, profile: profile.name, client: client.address },
        'mcp session initialized',
      );
    },
  });
  transport.onclose = async () => {
    if (transport.sessionId) {
      sessions.delete(transport.sessionId);
      await built.sessions.closeAll();
      // Each session builds its own emitter, so its UDP socket has to be
      // released here or the fd survives until GC.
      built.wazuh?.close();
      logger.info({ sid: `${transport.sessionId.slice(0, 8)}...` }, 'mcp session closed');
    }
  };

  await built.probeCapabilities();
  await built.server.connect(transport);
  const result = await transport.handleRequest(req, res, body);
  // After the new session is registered, so it is never its own eviction
  // candidate and a burst of reconnects cannot drop the one just created.
  await reapSessions(transport.sessionId ?? null);
  return result;
}

// One client for health probing, independent of any MCP session, with a short
// cache so a tight polling loop cannot turn the health endpoint into an
// amplifier against Termix. The container probe runs every 30s; this TTL means
// each probe is answered by at most one upstream request.
const healthClient = createClient(config, logger);
const PROBE_TTL_MS = 15000;
let lastProbe = { at: 0, reachable: null, error: null };

async function probeUpstream() {
  if (lastProbe.at && Date.now() - lastProbe.at < PROBE_TTL_MS) return lastProbe;
  try {
    await healthClient.get('/users/me');
    lastProbe = { at: Date.now(), reachable: true, error: null };
  } catch (error) {
    lastProbe = { at: Date.now(), reachable: false, error: error.message };
  }
  return lastProbe;
}

const httpServer = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);

    if (url.pathname === '/healthz') {
      // Minimal on purpose. This endpoint is unauthenticated so the container
      // probe can reach it, so it reports only liveness -- not the Termix base
      // URL, and not live session counts, which would tell anyone on the LAN
      // when an operator is actively driving hosts. Detail requires the token.
      const detailed = tokenMatches(bearer(req), config.httpToken);
      if (!detailed) return sendJson(res, 200, { ok: true });

      // Reachability is probed only on the AUTHENTICATED branch, so an
      // unauthenticated caller cannot make this server generate traffic to
      // Termix on demand. healthcheck.mjs runs inside the container and has the
      // token, so the container probe still gets the real answer.
      const upstream = await probeUpstream();

      const live = [...sessions.values()].reduce(
        (acc, s) => {
          const st = s.sessions.stats();
          acc.file += st.file; acc.docker += st.docker;
          return acc;
        },
        { file: 0, docker: 0 },
      );
      return sendJson(res, 200, {
        ok: true,
        version,
        // Liveness of THIS process is not the same as being able to do the job.
        // Deployed on 2026-08-14 the server answered ok:true while its API key
        // owned no hosts, so every tool call failed target resolution and the
        // container still read healthy.
        termixReachable: upstream.reachable,
        termixCheckedAt: new Date(upstream.at).toISOString(),
        ...(upstream.error ? { termixError: upstream.error } : {}),
        mcpSessions: sessions.size,
        sshSessions: live,
        wazuh: [...sessions.values()][0]?.wazuh?.stats() ?? null,
      });
    }

    if (url.pathname === '/mcp') return await handleMcp(req, res);

    return sendJson(res, 404, { error: 'not found' });
  } catch (error) {
    logger.error({ err: error.message }, 'request handler error');
    if (!res.headersSent) sendJson(res, 500, { error: 'internal error' });
  }
});

async function shutdown(signal) {
  logger.info({ signal }, 'shutting down');
  httpServer.close();
  await Promise.allSettled([...sessions.values()].map((s) => s.sessions.closeAll()));
  process.exit(0);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// Socket-level bounds. headersTimeout is the slowloris control. requestTimeout
// is deliberately left at Node's default: this transport keeps a long-lived SSE
// stream open, and tightening that timeout is how you break it.
httpServer.maxConnections = config.httpMaxConnections;
httpServer.headersTimeout = config.httpHeadersTimeoutMs;

// MCP_HTTP_TOKEN is easy to mistake for dead config once a policy file is in
// use -- the per-profile tokens are what select access -- but it still gates the
// detailed health response, so it is a live credential and belongs in a
// rotation. Say so once at boot rather than leaving it to be rediscovered.
if (policy) {
  logger.info(
    { profiles: true },
    'access policy in use: per-profile tokens select access, and MCP_HTTP_TOKEN '
    + 'gates only the detailed /healthz response -- it is still a live credential',
  );
}
if (!config.trustedProxies.length) {
  logger.info(
    {},
    'TERMIX_TRUSTED_PROXIES is unset, so X-Forwarded-For is ignored and every request '
    + 'is attributed to its socket peer. Behind a reverse proxy that is the proxy; set '
    + "this to the proxy's address to record real client addresses.",
  );
}

httpServer.listen(config.httpPort, config.httpBind, () => {
  logger.info({ bind: config.httpBind, port: config.httpPort, baseUrl: config.baseUrl },
    'termix-mcp ready on streamable-http');
});
