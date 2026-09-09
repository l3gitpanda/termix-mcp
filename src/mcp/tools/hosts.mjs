import { z } from 'zod';

import { hostArg } from './host-arg.mjs';

// Host inventory and status. list_hosts intentionally includes blocklisted
// hosts, tagged, so the model knows they exist and are off-limits rather than
// being surprised by a refusal later.
export function hostTools() {
  return [
    {
      name: 'list_hosts',
      title: 'List hosts',
      description:
        'List all SSH hosts registered in Termix, with id, name, ip, port, username, folder, and tags. '
        + 'Hosts on the blocklist are included with "blocked": true and cannot be operated on.',
      mutating: false,
      hostArg: null,
      inputSchema: {},
      handler: async (_args, ctx) => {
        const all = await ctx.hosts.list();
        // Hosts the caller cannot reach are still listed, marked, so the model
        // knows they exist and are off-limits rather than being surprised by a
        // refusal later -- but it is told which rule put them out of reach.
        const hosts = all.map((h) => {
          const blocked = ctx.hosts.isBlocked(h);
          const outside = ctx.hosts.isOutsideProfile(h);
          return {
            ...h,
            accessible: !blocked && !outside,
            ...(blocked ? { blocked: true } : {}),
            ...(outside ? { notInProfile: ctx.profile?.name ?? true } : {}),
          };
        });
        return {
          hosts,
          count: all.length,
          accessibleCount: hosts.filter((h) => h.accessible).length,
          profile: ctx.profile?.name ?? null,
        };
      },
    },
    {
      name: 'host_status',
      title: 'Host status',
      description:
        'Get reachability status for one host (by id or name) or, with no argument, the status map for all hosts, '
        + 'plus the Termix server uptime.',
      mutating: false,
      // Declared even though the argument is optional: the gate then resolves
      // and enforces a supplied host and records it as the audit `target`.
      // Resolving inside the handler left a refused attempt logged with
      // target:null and host:null, so a SIEM rule keyed on the host missed
      // precisely the denied attempts worth alerting on.
      hostArg: 'host',
      hostArgOptional: true,
      inputSchema: { host: hostArg.optional() },
      handler: async (args, ctx) => {
        if (ctx.host) return ctx.client.get(`/status/${ctx.host.id}`);

        const [statuses, uptime, known] = await Promise.all([
          ctx.client.get('/status'),
          ctx.client.get('/uptime').catch(() => null),
          ctx.hosts.list().catch(() => []),
        ]);

        // The bare map comes straight from Termix and covers every host the API
        // key can see -- blocklisted and out-of-profile included. list_hosts
        // goes to trouble to mark those; this handed them over unmarked, so the
        // two tools disagreed about what the caller may touch. Annotate rather
        // than drop, matching list_hosts: their existence is visible there too.
        const byId = new Map(known.map((h) => [String(h.id), h]));
        const annotate = (id, value) => {
          const record = byId.get(String(id));
          if (!record) return value;
          const blocked = ctx.hosts.isBlocked(record);
          const notInProfile = ctx.hosts.isOutsideProfile(record);
          const base = value && typeof value === 'object' && !Array.isArray(value)
            ? value
            : { status: value };
          // The name goes on EVERY entry, not just flagged ones. This map is
          // keyed by Termix record id, which is the opaque identifier every
          // host argument's description tells callers not to use -- so without
          // a name the result cannot be read without cross-referencing
          // list_hosts, and the server contradicted its own guidance.
          return {
            ...base,
            name: record.name,
            ip: record.ip || undefined,
            blocked: blocked || undefined,
            notInProfile: notInProfile ? (ctx.profile?.name ?? true) : undefined,
            unreachableByPolicy: (blocked || notInProfile) || undefined,
          };
        };

        const marked = statuses && typeof statuses === 'object' && !Array.isArray(statuses)
          ? Object.fromEntries(Object.entries(statuses).map(([k, v]) => [k, annotate(k, v)]))
          : statuses;

        return { statuses: marked, uptime, profile: ctx.profile?.name ?? null };
      },
    },
    {
      name: 'host_metrics',
      title: 'Host metrics',
      description:
        'Get current CPU, memory, disk, and network metrics for a host, and optionally the historical series '
        + 'over a time range (1h, 24h, 7d).',
      mutating: false,
      hostArg: 'host',
      inputSchema: {
        host: hostArg,
        history: z.boolean().default(false).describe('Include the historical series'),
        range: z.enum(['1h', '24h', '7d']).default('24h').describe('History range when history is true'),
      },
      handler: async (args, ctx) => {
        const current = await ctx.client.get(`/metrics/${ctx.host.id}`);
        if (!args.history) return current;
        const history = await ctx.client
          .get(`/metrics/history/${ctx.host.id}`, { range: args.range })
          .catch((e) => ({ error: e.message }));
        return { current, history };
      },
    },
  ];
}
