// Configuration is read once at boot and validated hard. An MCP server that
// starts half-configured looks healthy to the client while every tool call
// fails; refusing to start is the honest failure mode.

import path from 'node:path';

function required(name) {
  const value = process.env[name];
  if (!value || !value.trim()) throw new Error(`missing required environment variable ${name}`);
  return value.trim();
}

function optional(name, fallback) {
  const value = process.env[name];
  return value && value.trim() ? value.trim() : fallback;
}

function number(name, fallback) {
  const raw = optional(name, String(fallback));
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) throw new Error(`${name} must be numeric, got ${raw}`);
  return parsed;
}

function bool(name, fallback) {
  const raw = optional(name, String(fallback)).toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(raw)) return true;
  if (['0', 'false', 'no', 'off'].includes(raw)) return false;
  throw new Error(`${name} must be a boolean, got ${raw}`);
}

function baseUrl(raw) {
  const trimmed = raw.replace(/\/+$/, '');
  if (!/^https?:\/\//.test(trimmed)) throw new Error(`expected an http(s) URL, got ${raw}`);
  return trimmed;
}

// mode is 'stdio' or 'http'. Only the HTTP transport exposes a network
// endpoint, so only it requires MCP_HTTP_TOKEN.
export function loadConfig(mode = 'stdio') {
  if (mode !== 'stdio' && mode !== 'http') throw new Error(`unknown mode ${mode}`);

  const dataDir = path.resolve(optional('DATA_DIR', './data'));

  const serviceUrls = {};
  for (const service of ['MAIN', 'TUNNELS', 'FILES', 'STATS', 'DASHBOARD', 'DOCKER', 'SERIAL']) {
    const value = optional(`TERMIX_URL_${service}`, '');
    if (value) serviceUrls[service.toLowerCase()] = baseUrl(value);
  }

  return {
    mode,
    baseUrl: baseUrl(required('TERMIX_BASE_URL')),
    apiKey: required('TERMIX_API_KEY'),
    serviceUrls,
    timeoutMs: number('TERMIX_TIMEOUT_MS', 20000),

    // Bounds the executeFile call alone. TERMIX_TIMEOUT_MS is global to every
    // Termix request, so raising it far enough for a slow command also widened
    // the failure tail on every metadata read: GETs retry twice, so a hung
    // read_file or list_files took roughly timeoutMs x 3 to give up. Splitting
    // the two buys commands their minutes without charging every other call
    // for them.
    //
    // Keep it under TERMIX_SESSION_IDLE_MS. The idle sweep now skips sessions
    // with work in flight, so that is a backstop rather than the only guard,
    // but a value above the idle window still means a reconnect mid-command
    // whenever the in-flight signal is lost.
    execTimeoutMs: number('TERMIX_EXEC_TIMEOUT_MS', 240000),
    retry: number('TERMIX_RETRY', 2),

    keepaliveMs: number('TERMIX_KEEPALIVE_MS', 60000),
    sessionIdleMs: number('TERMIX_SESSION_IDLE_MS', 300000),
    maxSessions: number('TERMIX_MAX_SESSIONS', 16),

    tmpDir: optional('TERMIX_TMP_DIR', '/tmp').replace(/\/+$/, '') || '/',
    execShebang: optional('TERMIX_EXEC_SHEBANG', '#!/usr/bin/env bash'),

    // Ceiling on a single tool result, so one read_file on a huge journal
    // cannot exhaust the model's context. Truncation is reported in-band.
    // Tuned for a context window, not a filesystem. At 128 KiB a single result
    // could exceed an MCP client's per-result budget and spill to a file,
    // arriving unreadable in-context -- which defeats the point of capping it.
    // 32 KiB is roughly 8k tokens: big enough for real output, small enough to
    // stay inline. read_file's offset/limit is the way to ask for more.
    maxOutputBytes: number('MAX_OUTPUT_BYTES', 32 * 1024),

    mutationsEnabled: bool('TERMIX_MUTATIONS_ENABLED', false),
    // toggle_state is a lock the model itself holds the key to: prompt-injected
    // content can simply ask it to enable writes. Setting this false pins the
    // server read-only for its whole life, which is the right posture for an
    // always-on deployment nobody is watching.
    allowToggle: bool('TERMIX_ALLOW_TOGGLE', true),
    // Exact-match entries (name or IP), lowercased once here so every later
    // comparison is a Set lookup. Exact, not substring: "app" must block
    // that one host without also blocking "app-main".
    //
    // Empty by default: this list names machines in YOUR estate, so there is no
    // sane value to ship. It is a coarse backstop anyway -- the access policy's
    // per-profile "hosts" is the real control. Set TERMIX_BLOCKLIST to keep
    // named hosts away from every profile at once.
    blocklist: optional('TERMIX_BLOCKLIST', '')
      .split(',')
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean),

    // Per-profile access control. Unset, there are no profiles and the global
    // blocklist is the only host restriction (the original behaviour).
    policyFile: optional('TERMIX_POLICY_FILE', ''),
    // Which profile a stdio server runs as; the policy's defaultProfile is used
    // when this is unset.
    profileName: optional('TERMIX_PROFILE', ''),

    httpToken: mode === 'http' ? required('MCP_HTTP_TOKEN') : optional('MCP_HTTP_TOKEN', ''),
    httpBind: optional('HTTP_BIND', '0.0.0.0'),
    httpPort: number('HTTP_PORT', 8080),
    // Browser Origins permitted to reach /mcp. Empty means "reject any request
    // that carries an Origin at all", which is right for a server whose clients
    // are MCP tools rather than web pages.
    allowedOrigins: optional('MCP_ALLOWED_ORIGINS', '')
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean),
    // Addresses whose X-Forwarded-For this server will believe. Behind a proxy
    // the socket peer is always the proxy, so without this every request is
    // attributed to it -- but believing the header from anyone lets a direct
    // caller forge its own source address into the audit trail. Empty means
    // trust nobody and always record the socket peer, which is right for a
    // server reached directly. Set it to the reverse proxy's address.
    trustedProxies: optional('TERMIX_TRUSTED_PROXIES', '')
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean),
    // Bounds on the in-memory MCP session registry. An entry is removed when
    // its transport closes, which a client that simply disappears never does,
    // so without these a reconnecting client strands one server instance per
    // reconnect -- each with its own SSH session pool.
    mcpSessionIdleMs: number('MCP_SESSION_IDLE_MS', 30 * 60 * 1000),
    mcpMaxSessions: number('MCP_MAX_SESSIONS', 32),
    // Socket-level bounds. headersTimeout is the slowloris control; the request
    // timeout is deliberately left at Node's default because tightening it
    // risks the long-lived SSE stream this transport depends on.
    httpMaxConnections: number('HTTP_MAX_CONNECTIONS', 256),
    httpHeadersTimeoutMs: number('HTTP_HEADERS_TIMEOUT_MS', 20000),

    dataDir,
    logLevel: optional('LOG_LEVEL', 'info'),
    logFile: optional('LOG_FILE', ''),
    auditLogPath: optional('AUDIT_LOG_PATH', path.join(dataDir, 'audit.jsonl')),
    // The command itself is the point of the default record -- what ran, where,
    // through which tool -- so this ceiling has to be generous enough that a
    // real command is never clipped. 512 truncated long ones in exactly the
    // field the trail exists for. The per-line cap in audit.mjs still bounds the
    // record, so raising this cannot make a record unbounded.
    auditArgMax: number('AUDIT_ARG_MAX', 4096),
    auditMaxBytes: number('AUDIT_MAX_BYTES', 25 * 1024 * 1024),
    auditMaxFiles: number('AUDIT_MAX_FILES', 5),

    // Full output capture, off by default. The main audit log deliberately
    // keeps only bytes+sha256 of each result, because an unbounded record is an
    // audit-DELETION primitive: a few huge outputs roll real history out of the
    // retained generations using nothing but permitted tools. Turning this on
    // writes the outputs to a SEPARATE file with its own rotation, so they can
    // never evict the command trail no matter how much the agent reads.
    //
    // Understand what the file becomes: a verbatim copy of everything the agent
    // read, including any secret it was pointed at. Keep it 0600, and do NOT
    // add it to the Wazuh localfile stanza -- that stanza names audit.jsonl
    // explicitly, so this sibling is not shipped unless someone adds it.
    auditCaptureOutput: bool('AUDIT_CAPTURE_OUTPUT', false),
    auditOutputPath: optional('AUDIT_OUTPUT_PATH', path.join(dataDir, 'audit-output.jsonl')),
    auditOutputMaxBytes: number('AUDIT_OUTPUT_MAX_BYTES', 100 * 1024 * 1024),
    auditOutputMaxFiles: number('AUDIT_OUTPUT_MAX_FILES', 5),
    // Per-stream ceiling inside one record. Generous, because the point is the
    // content; bounded, because one 128 KB read should not be able to push five
    // generations of output history out on its own.
    auditOutputMaxRecordBytes: number('AUDIT_OUTPUT_MAX_RECORD_BYTES', 256 * 1024),

    wazuh: {
      enabled: bool('WAZUH_ENABLED', false),
      // Loopback by default: the usual shape is a wazuh-agent on this host
      // forwarding to the manager. Point it at the collector for your estate.
      // Never ship a real collector address as a default -- an operator who
      // enables Wazuh without setting this would send their audit trail there.
      host: optional('WAZUH_SYSLOG_HOST', '127.0.0.1'),
      port: number('WAZUH_SYSLOG_PORT', 5514),
      facility: optional('WAZUH_FACILITY', 'local0'),
    },
  };
}
