// Author and check an access policy from the shell, with no MCP client and no
// Termix connection required.
//
//   node scripts/policy.mjs validate <file>
//   node scripts/policy.mjs explain  <file> [--profile NAME] [--host h1,h2] [--path /a,/b]
//   node scripts/policy.mjs groups
//   node scripts/policy.mjs schema
//   node scripts/policy.mjs init > access-policy.json
//
// `validate` exits non-zero on an invalid policy, so it drops straight into a
// pre-commit hook or CI.

import fs from 'node:fs';
import { createRequire } from 'node:module';
import { parsePolicy } from '../src/access/policy.mjs';
import { TOOL_GROUPS } from '../src/access/groups.mjs';
import { MODES } from '../src/access/match.mjs';

const require = createRequire(import.meta.url);
const [command, file, ...rest] = process.argv.slice(2);

function flag(name, fallback = null) {
  const i = rest.indexOf(`--${name}`);
  return i >= 0 ? rest[i + 1] : fallback;
}

function readPolicy(path) {
  if (!path) {
    console.error('a policy file path is required');
    process.exit(2);
  }
  return parsePolicy(fs.readFileSync(path, 'utf8'));
}

function printProfile(profile, { hosts, paths, tools }) {
  const explained = profile.explain({ hosts, paths, tools });
  const { modes } = explained;
  console.log(`\n${profile.name}${profile.description ? ` -- ${profile.description}` : ''}`);
  console.log(`  hosts      ${modes.hosts}`);
  console.log(`  tools      ${modes.tools}`);
  console.log(`  paths      ${modes.paths}`);
  console.log(`  mutations  ${explained.mutations}`);
  console.log(`  global blocklist  ${explained.globalBlocklist}`);
  console.log(`  token      ${profile.tokenDigest ? 'set' : 'none (stdio only)'}`);

  if (explained.hosts.length) {
    const yes = explained.hosts.filter((h) => h.allowed).map((h) => h.host);
    const no = explained.hosts.filter((h) => !h.allowed).map((h) => h.host);
    console.log(`  reaches    ${yes.join(', ') || '(nothing)'}`);
    if (no.length) console.log(`  refuses    ${no.join(', ')}`);
  }
  for (const entry of explained.tools) {
    console.log(`    tool ${entry.allowed ? 'ALLOW' : 'DENY '} ${entry.tool}`);
  }
  for (const entry of explained.paths) {
    console.log(`    path ${entry.allowed ? 'ALLOW' : 'DENY '} ${entry.path}`);
  }
  for (const warning of explained.warnings ?? []) console.log(`  ! ${warning}`);
}

const TEMPLATE = {
  $schema: './access-policy.schema.json',
  version: 1,
  defaultProfile: 'readonly',
  profiles: {
    readonly: {
      description: 'Look at anything reachable, change nothing.',
      tokenEnv: 'MCP_TOKEN_READONLY',
      hosts: 'all',
      tools: { allow: ['@readonly'] },
      mutations: 'deny',
    },
    ops: {
      description: 'Day-to-day operations on named hosts.',
      tokenEnv: 'MCP_TOKEN_OPS',
      hosts: ['app-main', 'web-proxy'],
      mutations: 'allow',
      tools: { mode: 'blocklist', deny: ['process_signal'] },
    },
  },
};

try {
  switch (command) {
    case 'validate': {
      const policy = readPolicy(file);
      let warnings = 0;
      for (const profile of policy.profiles.values()) {
        for (const warning of profile.warnings ?? []) {
          console.warn(`warning: ${warning}`);
          warnings += 1;
        }
      }
      console.log(
        `OK: ${policy.profiles.size} profile(s) [${[...policy.profiles.keys()].join(', ')}]`
        + `${warnings ? `, ${warnings} warning(s)` : ''}`,
      );
      break;
    }

    case 'explain': {
      const policy = readPolicy(file);
      const hostNames = (flag('host') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
      const hosts = hostNames.map((h) => ({ name: h, ip: h }));
      const paths = (flag('path') ?? '/etc/shadow,/opt').split(',').map((s) => s.trim()).filter(Boolean);
      const tools = (flag('tool') ?? 'read_file,write_file,run_command,call_api')
        .split(',').map((s) => s.trim()).filter(Boolean);
      const only = flag('profile');
      for (const [name, profile] of policy.profiles) {
        if (only && name !== only) continue;
        printProfile(profile, { hosts, paths, tools });
      }
      break;
    }

    case 'groups':
      for (const [group, members] of Object.entries(TOOL_GROUPS)) {
        console.log(`${group.padEnd(16)} ${members.join(', ')}`);
      }
      console.log(`\nmodes: ${MODES.join(', ')}`);
      break;

    case 'schema':
      console.log(JSON.stringify(require('../access-policy.schema.json'), null, 2));
      break;

    case 'init':
      console.log(JSON.stringify(TEMPLATE, null, 2));
      break;

    default:
      console.error('usage: policy.mjs <validate|explain|groups|schema|init> [file] [options]');
      process.exit(2);
  }
} catch (error) {
  console.error(`error: ${error.message}`);
  process.exit(1);
}
