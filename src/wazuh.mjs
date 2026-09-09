import dgram from 'node:dgram';

// Optional forwarder that ships each audit record to Wazuh as an RFC 5424
// syslog line carrying an @cee: JSON payload, so Wazuh's JSON decoder parses the
// fields directly. UDP is lossy and unauthenticated; for production prefer a
// Wazuh agent tailing the audit JSONL over the TLS agent channel. A send failure
// is logged and never blocks a tool call.

const FACILITIES = {
  local0: 16, local1: 17, local2: 18, local3: 19,
  local4: 20, local5: 21, local6: 22, local7: 23,
};

// Build the RFC 5424 line for one audit entry. Exported so the framing (PRI
// math, @cee prefix) is unit-testable without opening a socket.
export function buildSyslogLine(entry, { facility = 'local0', hostname = 'termix-mcp', pid = 0 } = {}) {
  const fac = FACILITIES[facility] ?? 16;
  const severity = entry.ok ? 6 : 3; // informational vs error
  const pri = fac * 8 + severity;
  return `<${pri}>1 ${entry.ts} ${hostname} termix-mcp ${pid} - - @cee:${JSON.stringify(entry)}`;
}

// Syslog receivers truncate: rsyslog defaults to 8 KB and Wazuh's UDP path is
// the same order, while anything over the path MTU gets IP-fragmented so one
// lost fragment loses the record. A truncated line fails the @cee JSON decoder
// and is dropped silently, so an oversized record is sent in a reduced form
// that still points at the full one by id.
const MAX_DATAGRAM_BYTES = 1400;

export function createWazuhEmitter(cfg, logger) {
  const socket = dgram.createSocket('udp4');
  socket.unref?.();
  const stats = { sent: 0, failed: 0, reduced: 0, lastError: null };
  socket.on('error', (err) => {
    stats.lastError = err.message;
    logger.warn({ err: err.message }, 'wazuh socket error');
  });

  function frame(entry) {
    const line = buildSyslogLine(entry, { facility: cfg.facility, pid: process.pid });
    if (Buffer.byteLength(line, 'utf8') <= MAX_DATAGRAM_BYTES) return { line, reduced: false };
    const slim = {
      ts: entry.ts,
      id: entry.id,
      event: entry.event,
      tool: entry.tool,
      mutating: entry.mutating,
      host: entry.host,
      ok: entry.ok,
      error: entry.error,
      exitCode: entry.exitCode,
      truncated: true,
    };
    return { line: buildSyslogLine(slim, { facility: cfg.facility, pid: process.pid }), reduced: true };
  }

  function emit(entry) {
    try {
      const { line, reduced } = frame(entry);
      if (reduced) stats.reduced += 1;
      socket.send(Buffer.from(line, 'utf8'), cfg.port, cfg.host, (err) => {
        if (err) {
          // warn, not debug: LOG_LEVEL defaults to info, so a debug-level
          // failure would make a dead collector completely invisible.
          stats.failed += 1;
          stats.lastError = err.message;
          logger.warn({ err: err.message, host: cfg.host, port: cfg.port }, 'wazuh send failed');
        } else {
          stats.sent += 1;
        }
      });
    } catch (error) {
      stats.failed += 1;
      stats.lastError = error.message;
      logger.warn({ err: error.message }, 'wazuh emit failed');
    }
  }

  function close() {
    try { socket.close(); } catch { /* already closed */ }
  }

  return { emit, close, stats: () => ({ ...stats }) };
}
