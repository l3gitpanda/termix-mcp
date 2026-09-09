import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { version } from '../version.mjs';
import { createClient } from '../termix/client.mjs';
import { createHostRegistry } from '../termix/hosts.mjs';
import { createSessionManager } from '../termix/sessions.mjs';
import { createAuditLog } from '../audit.mjs';
import { createWazuhEmitter } from '../wazuh.mjs';
import { createKeyedMutex } from '../util/lock.mjs';
import { createGate } from './gate.mjs';
import { globToRegExp } from '../access/match.mjs';

import { hostTools } from './tools/hosts.mjs';
import { execTools } from './tools/exec.mjs';
import { fileTools } from './tools/files.mjs';
import { dockerTools } from './tools/docker.mjs';
import { systemTools } from './tools/system.mjs';
import { tunnelTools } from './tools/tunnels.mjs';
import { snippetTools } from './tools/snippets.mjs';
import { observabilityTools } from './tools/observability.mjs';
import { policyTools } from './tools/policy.mjs';
import { metaTools } from './tools/meta.mjs';

// Build a fully wired MCP server plus the shared runtime pieces. Both transports
// call this, so stdio and HTTP register exactly the same 24 tools with the same
// safety and audit behaviour.
export function buildServer({
  config, logger, transport, profile = null, peer = null,
}) {
  // A profile may carry its own Termix API key, so Termix's native host
  // ownership enforces the same restriction at the source -- defence in depth
  // rather than trusting this server's checks alone.
  const effectiveConfig = profile?.termixApiKey
    ? { ...config, apiKey: profile.termixApiKey }
    : config;
  const client = createClient(effectiveConfig, logger);
  const hosts = createHostRegistry(client, config.blocklist, logger, profile);
  // audit and wazuh are built before the session manager: opening an SSH
  // session is itself an auditable event, so the manager needs the sink.
  const audit = createAuditLog(
    { filePath: config.auditLogPath, maxBytes: config.auditMaxBytes, maxFiles: config.auditMaxFiles },
    logger,
  );
  // A SECOND log, when full output capture is on. Separate on purpose: it
  // rotates on its own budget, so however much the agent reads, it can never
  // push the command trail out of retention. That was the original reason the
  // main log keeps only bytes+sha256.
  const outputAudit = config.auditCaptureOutput
    ? createAuditLog(
      {
        filePath: config.auditOutputPath,
        maxBytes: config.auditOutputMaxBytes,
        maxFiles: config.auditOutputMaxFiles,
        maxLineBytes: config.auditOutputMaxRecordBytes + 8 * 1024,
      },
      logger,
    )
    : null;
  if (outputAudit) {
    logger.warn(
      { path: config.auditOutputPath },
      'AUDIT_CAPTURE_OUTPUT is on: this file records verbatim tool output, including any '
      + 'secret the agent reads. Keep it 0600 and do not ship it wholesale to the SIEM.',
    );
  }

  const wazuh = config.wazuh.enabled ? createWazuhEmitter(config.wazuh, logger) : null;
  const sessions = createSessionManager({ client, config, logger, audit, wazuh });
  const mutex = createKeyedMutex();

  // Session-scoped mutable state. capabilities is filled by the startup probe.
  const state = {
    // A read-only profile never starts writable, whatever the global default.
    mutationsEnabled: config.mutationsEnabled && (profile?.allowsMutations() ?? true),
    capabilities: { execFileOutputCapture: 'unprobed' },
  };

  const deps = {
    client, hosts, sessions, audit, outputAudit, wazuh, mutex, state, config, logger,
    transport, version, profile, peer,
  };
  const gate = createGate(deps);

  // Everything except the tools that need the finished catalog to describe it.
  const baseTools = [
    ...hostTools(),
    ...execTools(),
    ...fileTools(),
    ...dockerTools(),
    ...systemTools(),
    ...tunnelTools(),
    ...snippetTools(),
    ...observabilityTools(),
  ];
  const catalog = [
    ...baseTools,
    ...policyTools({ catalog: [] }),
    ...metaTools({ catalog: [] }),
    // `mutating` may be a PREDICATE (call_api: GET reads, anything else
    // writes). Passed through, it serialized to undefined, so a consumer
    // parsing the catalog saw a tool with no mutating field at all. Say
    // "conditional" instead -- that is the honest answer.
  ].map((t) => ({
    name: t.name,
    mutating: typeof t.mutating === 'function' ? 'conditional' : t.mutating,
    description: t.description,
  }));
  const allTools = [...baseTools, ...policyTools({ catalog }), ...metaTools({ catalog })];

  const server = new McpServer(
    { name: 'termix-mcp', version },
    { instructions: 'Manage Termix hosts: run commands, read/write files, control Docker and systemd. '
      + 'Mutating tools are disabled until toggle_state enables them. Blocklisted hosts are refused. '
      + 'Call help for the full tool list and current state.' },
  );

  for (const spec of allTools) {
    const { name, config: toolConfig, handler } = gate.wrap(spec);
    server.registerTool(name, toolConfig, handler);
  }

  // Probe whether executeFile captures output on this instance, so run_command
  // and help can report the real capability rather than assume it. Non-fatal.
  async function probeCapabilities() {
    try {
      await client.get('/users/me');
      state.capabilities.reachable = true;
    } catch (error) {
      state.capabilities.reachable = false;
      logger.warn({ err: error.message }, 'Termix not reachable at startup');
      return;
    }
    await warnAboutDeadPatterns();
  }

  // A blocklist entry that matches no host is not defence in depth, it is
  // decoration -- and it looks identical to a working one. TERMIX_BLOCKLIST
  // carried IPs that had drifted (a guest re-addressed, another removed), so
  // only the name entries were load-bearing and "name OR ip" was not actually
  // true. Nothing detects that without comparing against the live inventory,
  // which is exactly what a startup pass can do. Warn, never fail: a host that
  // is merely powered off should not stop the server, and the hosts dimension
  // already fails closed.
  async function warnAboutDeadPatterns() {
    let inventory;
    try {
      inventory = await hosts.list();
    } catch (error) {
      logger.debug({ err: error.message }, 'could not read inventory for pattern check');
      return;
    }
    if (!inventory.length) return;

    const labels = new Set(
      inventory.flatMap((h) => [h.name, h.ip].filter(Boolean).map((s) => String(s).toLowerCase())),
    );
    const dead = config.blocklist.filter((entry) => !labels.has(String(entry).toLowerCase()));
    if (dead.length) {
      logger.warn(
        { entries: dead, hostCount: inventory.length },
        'TERMIX_BLOCKLIST entries match no host in Termix; they block nothing and may be stale',
      );
    }

    // The env blocklist was only half of it. The policy file carries its own
    // hosts.deny per profile, with the same failure mode and worse stakes: a
    // host held out by name AND ip, where the ip has since drifted, is held out
    // by the name alone -- so renaming the record in Termix lapses the block
    // silently. Nothing surfaced that, though access_policy_check already
    // computed exactly this. Warn per profile at boot.
    if (!profile?.summary) return;
    const summary = profile.summary();
    for (const list of ['allow', 'deny']) {
      const dangling = (summary.hosts?.[list] ?? []).filter((pattern) => {
        const rx = globToRegExp(String(pattern).toLowerCase());
        return ![...labels].some((label) => rx.test(label));
      });
      if (dangling.length) {
        logger.warn(
          { profile: summary.profile, list, patterns: dangling },
          `access policy ${list} patterns match no host in Termix; `
          + (list === 'deny'
            ? 'they hold nothing out, so any host they were meant to cover rests on the other entries'
            : 'they grant nothing'),
        );
      }
    }
  }

  return {
    server,
    sessions,
    state,
    client,
    hosts,
    wazuh,
    audit,
    profile,
    probeCapabilities,
    // Exposed so tests can assert the access groups still match the real tool
    // set -- a tool added later must not fall outside every group unnoticed.
    catalog,
    toolCount: allTools.length,
  };
}
