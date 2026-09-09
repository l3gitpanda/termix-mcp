// Read-only live verification against a real Termix instance. Confirms the base
// URL/auth, enumerates hosts (flagging blocklisted ones, never touching them),
// and -- only when a target host is named -- runs a single echo through the
// command path to prove executeFile still captures output on this version.
//
//   TERMIX_BASE_URL=... TERMIX_API_KEY=... node scripts/verify-live.mjs
//   ... node scripts/verify-live.mjs --host 5      # also runs the exec probe
//
// The exec probe writes a temporary script to the host's TERMIX_TMP_DIR and
// deletes it; pass a host you are comfortable running `echo`/`id` on.

import { loadConfig } from '../src/config.mjs';
import { createLogger } from '../src/logging.mjs';
import { createClient } from '../src/termix/client.mjs';
import { createHostRegistry } from '../src/termix/hosts.mjs';
import { createSessionManager } from '../src/termix/sessions.mjs';
import { runScript } from '../src/mcp/tools/exec.mjs';

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const ok = (m) => console.log(`  ✓ ${m}`);
const bad = (m) => console.log(`  ✗ ${m}`);

const config = loadConfig('stdio');
const logger = createLogger({ level: 'warn' });
const client = createClient(config, logger);
const hosts = createHostRegistry(client, config.blocklist, logger);
const sessions = createSessionManager({ client, config, logger });

let failures = 0;

console.log(`\nTermix base URL: ${config.baseUrl}`);

// 1. Auth / reachability.
console.log('\n[1] Auth and reachability');
try {
  const me = await client.get('/users/me');
  ok(`authenticated as ${me?.username ?? me?.id ?? 'unknown user'}`);
} catch (error) {
  failures += 1;
  bad(`GET /users/me failed: ${error.message}`);
  console.log('      The base URL or API key is wrong, or nginx is not serving the API on this origin.');
}

// 2. Host inventory + blocklist.
console.log('\n[2] Host inventory');
let allHosts = [];
try {
  allHosts = await hosts.list();
  ok(`${allHosts.length} hosts registered`);
  for (const h of allHosts) {
    const blocked = hosts.isBlocked(h) ? '  [BLOCKED]' : '';
    console.log(`      #${h.id} ${h.name || '(no name)'} ${h.ip}:${h.port}${blocked}`);
  }
} catch (error) {
  failures += 1;
  bad(`GET /host/db/host failed: ${error.message}`);
}

// 3. Status map + uptime.
console.log('\n[3] Status and uptime');
try {
  await client.get('/status');
  ok('GET /status returned');
} catch (error) {
  bad(`GET /status failed: ${error.message}`);
}
try {
  const uptime = await client.get('/uptime');
  ok(`server uptime: ${uptime?.formatted ?? `${uptime?.uptimeSeconds ?? '?'}s`}`);
} catch (error) {
  bad(`GET /uptime failed: ${error.message}`);
}

// 4. Command-execution probe (opt-in via --host).
const target = arg('--host');
if (target) {
  console.log(`\n[4] Command-execution probe on host ${target}`);
  try {
    const host = await hosts.resolveAllowed(target);
    const result = await runScript({ client, sessions, config, logger }, host, 'echo termix-mcp-ok && id');
    if (result.stdout.includes('termix-mcp-ok') && typeof result.exitCode === 'number') {
      ok(`executeFile captured output (exit ${result.exitCode}); run_command is fully functional`);
      console.log(`      stdout: ${result.stdout.replace(/\n/g, ' ').slice(0, 120)}`);
    } else {
      failures += 1;
      bad('executeFile did not return the expected {exitCode, output} shape');
      console.log('      run_command may need the redirect-to-file fallback on this Termix version.');
      console.log(`      raw: ${JSON.stringify(result).slice(0, 200)}`);
    }
  } catch (error) {
    failures += 1;
    bad(`exec probe failed: ${error.message}`);
  }
} else {
  console.log('\n[4] Command-execution probe skipped (pass --host <id|name> to run it)');
}

await sessions.closeAll();

console.log(`\n${failures === 0 ? 'All checks passed.' : `${failures} check(s) failed.`}\n`);
process.exit(failures === 0 ? 0 : 1);
