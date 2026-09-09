import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { loadConfig } from './config.mjs';
import { createLogger } from './logging.mjs';
import { buildServer } from './mcp/server.mjs';
import { createPolicyStore, unrestrictedProfile } from './access/policy.mjs';

// stdio transport: Claude Code launches this process and speaks MCP over stdin/
// stdout. The logger therefore MUST stay off fd 1 (stderr or a file) or it would
// corrupt the protocol stream -- createLogger enforces that.
const config = loadConfig('stdio');
const logger = createLogger({ level: config.logLevel, file: config.logFile });

// There is no bearer token on stdio, so the profile is named by configuration.
// A policy file that names no usable profile is a hard startup failure rather
// than a silent fall back to unrestricted access.
let profile = unrestrictedProfile();
if (config.policyFile) {
  const policy = createPolicyStore({ filePath: config.policyFile, logger });
  const name = config.profileName || policy.defaultName();
  if (!name) {
    throw new Error(
      'TERMIX_POLICY_FILE is set but no profile was selected: set TERMIX_PROFILE, '
      + 'or give the policy a defaultProfile.',
    );
  }
  profile = policy.byName(name);
}

const { server, sessions, probeCapabilities, toolCount } = buildServer({
  config, logger, transport: 'stdio', profile,
});

async function shutdown(signal) {
  logger.info({ signal }, 'shutting down');
  await sessions.closeAll();
  process.exit(0);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

await probeCapabilities();
const transport = new StdioServerTransport();
await server.connect(transport);
logger.info(
  {
    toolCount,
    baseUrl: config.baseUrl,
    mutationsEnabled: config.mutationsEnabled,
    profile: profile.name,
  },
  'termix-mcp ready on stdio',
);
