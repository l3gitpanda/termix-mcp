import { z } from 'zod';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { parsePolicy } from '../../access/policy.mjs';
import { TOOL_GROUPS, GROUP_NAMES } from '../../access/groups.mjs';
import { MODES, globToRegExp } from '../../access/match.mjs';

const require = createRequire(import.meta.url);

// `fromFile` used to hand any path the caller named straight to readFileSync,
// from a tool that is mutating:false and a member of both @readonly and
// @policy -- an arbitrary local read inside this container, whose environment
// holds every profile token and whose /data holds the audit trail. The flag
// exists to check a draft sitting beside the live policy, so confine it to that
// directory and nothing else.
export function readPolicyFile(candidate, policyFile) {
  if (!policyFile) {
    throw new Error(
      'fromFile needs TERMIX_POLICY_FILE to be configured: it reads a draft from the directory '
      + 'holding the live policy, and this server has none. Pass the document inline instead.',
    );
  }
  const dir = path.resolve(path.dirname(policyFile));
  const target = path.resolve(dir, candidate);
  if (target !== dir && !target.startsWith(`${dir}${path.sep}`)) {
    throw new Error(`fromFile is confined to ${dir}, and "${candidate}" resolves outside it.`);
  }
  try {
    return fs.readFileSync(target, 'utf8');
  } catch {
    // One message for every failure -- absent, unreadable, a directory. Letting
    // those differ turns this into an existence oracle over the filesystem.
    throw new Error(`could not read a policy file at "${candidate}".`);
  }
}

// A pattern that matches nothing is this tool's whole reason to exist: a typo
// in a DENY list denies nothing and the policy still validates clean, so the
// operator reads a green result and believes a restriction is in force. The
// matcher globs against arbitrary strings, so only a check against the real
// catalog and the live inventory can tell the difference.
function checkPatternsResolve(parsed, { catalog, hosts }) {
  const toolNames = new Set(catalog.map((t) => t.name));
  const hostLabels = hosts.flatMap((h) => [h.name, h.ip].filter(Boolean).map((s) => s.toLowerCase()));
  const problems = { tools: [], hosts: [] };

  const matches = (pattern, candidates) => {
    const rx = globToRegExp(String(pattern).toLowerCase());
    return candidates.some((c) => rx.test(String(c).toLowerCase()));
  };

  for (const [name, profile] of parsed.profiles) {
    const { tools, hosts: hostRules } = profile.summary();
    for (const list of ['allow', 'deny']) {
      for (const pattern of tools?.[list] ?? []) {
        // Groups are validated at parse time; only bare names can dangle.
        if (String(pattern).startsWith('@')) continue;
        if (!matches(pattern, [...toolNames])) {
          problems.tools.push(
            `profile "${name}" ${list}s tool "${pattern}", which matches no registered tool`,
          );
        }
      }
      for (const pattern of hostRules?.[list] ?? []) {
        if (!matches(pattern, hostLabels)) {
          problems.hosts.push(
            `profile "${name}" ${list}s host "${pattern}", which matches no host currently in Termix`,
          );
        }
      }
    }
  }
  return problems;
}

// Tools for authoring an access policy. The point is a closed loop: a model can
// fetch the exact schema and the real vocabulary (live host names, real tool
// names, group definitions), draft a policy, and have it checked -- including
// what it would actually permit -- before anyone trusts it.
//
// Both are read-only and never touch the running policy or the disk. Writing
// the file stays a deliberate human act.
export function policyTools({ catalog }) {
  return [
    {
      name: 'access_policy_schema',
      title: 'Get the access-policy schema and vocabulary',
      description:
        'Return the JSON Schema for the access-policy file, the tool groups, the available modes, '
        + 'the real tool names, and the current hosts by name and IP. Use this before writing or '
        + 'editing a policy so the result is valid and refers to machines and tools that exist. '
        + 'Pair it with access_policy_check to verify a draft.',
      mutating: false,
      hostArg: null,
      inputSchema: {
        includeHosts: z.boolean().default(true)
          .describe('Include the live host inventory as vocabulary for host rules'),
      },
      handler: async (args, ctx) => {
        const schema = require('../../../access-policy.schema.json');
        let hosts;
        if (args.includeHosts) {
          try {
            const all = await ctx.hosts.list();
            hosts = all.map((h) => ({ name: h.name, ip: h.ip, folder: h.folder || undefined }));
          } catch (error) {
            hosts = { error: `could not list hosts: ${error.message}` };
          }
        }
        return {
          schema,
          modes: MODES,
          toolGroups: TOOL_GROUPS,
          groupNames: GROUP_NAMES,
          tools: catalog.map((t) => ({ name: t.name, mutating: t.mutating })),
          hosts,
          activeProfile: ctx.profile?.summary?.() ?? null,
          notes: [
            'Hosts default to allowlist (fail closed); tools and paths default to unrestricted.',
            'A rule set can be "all"/"none", an array (allowlist shorthand), or {mode, allow, deny}.',
            'In allowlist mode deny carves exceptions out; in blocklist mode allow carves them back in.',
            'Path rules bind only the file tools. Deny @escape too, or they are advisory.',
            'Prefer tokenEnv/termixApiKeyEnv so the policy file carries no secrets.',
          ],
        };
      },
    },
    {
      name: 'access_policy_check',
      title: 'Validate an access policy and explain what it permits',
      description:
        'Validate a candidate access policy (as a JSON object or string) without applying it, and '
        + 'report what each profile would actually permit against real hosts, tools, and paths. '
        + 'Returns validation errors, lint warnings, and a per-profile decision table. Use this to '
        + 'check a policy you just drafted before writing it to disk.',
      mutating: false,
      hostArg: null,
      inputSchema: {
        policy: z.union([z.string(), z.record(z.string(), z.any())])
          .describe('The candidate policy document, or a path to read it from with fromFile'),
        fromFile: z.boolean().default(false)
          .describe(
            'Treat `policy` as a path on THIS server and read the file instead. Confined to the '
            + 'directory holding the configured policy file.',
          ),
        probePaths: z.array(z.string()).optional()
          .describe('Paths to test each profile against, e.g. ["/etc/shadow", "/opt/appdata/x"]'),
        probeTools: z.array(z.string()).optional()
          .describe('Tool names to test; defaults to a representative spread'),
      },
      handler: async (args, ctx) => {
        let doc = args.policy;
        if (args.fromFile) {
          if (typeof doc !== 'string') throw new Error('fromFile needs `policy` to be a path');
          doc = readPolicyFile(doc, ctx.config.policyFile);
        }

        let parsed;
        try {
          parsed = parsePolicy(doc);
        } catch (error) {
          // A rejected policy is the normal outcome of a first draft, so this is
          // reported as data to act on rather than thrown as a tool failure.
          //
          // With fromFile, a JSON syntax error is NOT safe to echo: V8 embeds a
          // window of the input in the message, so returning it verbatim handed
          // back the first bytes of whatever file was named. The caller supplied
          // an inline document itself, so echoing that one leaks nothing new.
          const leaky = args.fromFile && error instanceof SyntaxError;
          return {
            valid: false,
            error: leaky ? 'the file at that path is not valid JSON' : error.message,
            profiles: null,
          };
        }

        let hosts = [];
        try {
          hosts = await ctx.hosts.list();
        } catch {
          hosts = [];
        }
        const probeTools = args.probeTools ?? [
          'list_hosts', 'read_file', 'write_file', 'run_command',
          'docker_container_action', 'service_action', 'call_api',
        ];
        const probePaths = args.probePaths ?? ['/etc/shadow', '/opt', '/tmp/x'];

        // The profile's own rules are only half the decision. resolveAllowed
        // checks the global blocklist FIRST, so a profile saying "hosts": "all"
        // still cannot reach a blocklisted host -- and this tool promises what
        // a profile "would actually permit". Reporting allowed:true for exactly
        // the hosts held out on purpose is the worst place to be wrong, and the
        // input was already here: `globalBlocklist` is printed in the same
        // response. Kept as a distinct flag rather than folded into the
        // profile's verdict, because the two denials live in different config
        // and send the reader to different files -- the same distinction the
        // live refusal messages now make.
        // Matches the live rule exactly: name OR ip, exact, case-insensitive.
        // Deliberately not ctx.hosts.isBlocked -- that one bakes in the RUNNING
        // profile's globalBlocklist setting, and each drafted profile carries
        // its own.
        const blocklist = new Set(
          (ctx.config.blocklist ?? []).map((entry) => String(entry).toLowerCase()),
        );
        const byLabel = new Map();
        for (const h of hosts) {
          for (const label of [h.name, h.ip].filter(Boolean)) byLabel.set(label, h);
        }
        const blockedByGlobalFor = (profile, hostLabel) => {
          if (!(profile.enforcesGlobalBlocklist?.() ?? true)) return false;
          const record = byLabel.get(hostLabel);
          if (!record) return false;
          const name = String(record.name ?? '').toLowerCase();
          const ip = String(record.ip ?? '').toLowerCase();
          return Boolean((name && blocklist.has(name)) || (ip && blocklist.has(ip)));
        };

        const profiles = {};
        for (const [name, profile] of parsed.profiles) {
          const explained = profile.explain({ hosts, tools: probeTools, paths: probePaths });
          const decided = explained.hosts.map((h) => {
            const blockedByGlobal = blockedByGlobalFor(profile, h.host);
            return blockedByGlobal
              ? { ...h, allowed: false, blockedByGlobal: true }
              : h;
          });
          profiles[name] = {
            ...explained,
            hosts: decided,
            hasToken: Boolean(profile.tokenDigest),
            // A profile with no token and not named as defaultProfile cannot be
            // selected on either transport: it is dead config, not a restriction.
            unreachableProfile: !profile.tokenDigest && parsed.defaultProfile !== name
              ? 'no token and not the defaultProfile, so nothing can select this profile'
              : undefined,
            reachableHosts: decided.filter((h) => h.allowed).map((h) => h.host),
            unreachableHosts: decided.filter((h) => !h.allowed).map((h) => h.host),
            blockedByGlobalBlocklist: decided.filter((h) => h.blockedByGlobal).map((h) => h.host),
          };
        }

        // A pattern that matches nothing is the failure this tool exists to
        // catch: a typo in a DENY list denies nothing, and the policy still
        // validates clean. The catalog and the inventory are both already in
        // hand, so check against them rather than globbing arbitrary strings.
        const problems = checkPatternsResolve(parsed, { catalog, hosts });

        return {
          valid: true,
          defaultProfile: parsed.defaultProfile,
          profileCount: parsed.profiles.size,
          // Anything a profile cannot reach is only meaningful against the hosts
          // that exist right now; say so rather than implying a static answer.
          evaluatedAgainst: { hostCount: hosts.length, tools: probeTools, paths: probePaths },
          // Errors, because a tool pattern naming nothing real can only be a
          // mistake. Host warnings are softer: a host may legitimately be added
          // to Termix later, which is why the hosts dimension fails closed.
          patternErrors: problems.tools.length ? problems.tools : undefined,
          patternWarnings: problems.hosts.length ? problems.hosts : undefined,
          profiles,
        };
      },
    },
  ];
}
