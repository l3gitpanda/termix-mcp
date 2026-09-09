import { z } from 'zod';

import { hostArgWith } from './host-arg.mjs';
import { redactContainerDetails } from '../../util/redact.mjs';

const hostArg = hostArgWith('Docker must be enabled for this host.');

// Docker control is session-based: a docker SSH session is opened for the host,
// then container operations reference containers by id within that session.
export function dockerTools() {
  return [
    {
      name: 'docker_containers',
      title: 'List containers',
      description: 'List Docker containers on a host. Set all=true to include stopped containers.',
      mutating: false,
      hostArg: 'host',
      inputSchema: { host: hostArg, all: z.boolean().default(true) },
      handler: (args, ctx) => ctx.sessions.withDockerSession(ctx.host, async (s) => {
        const containers = await ctx.client.get(`/docker/containers/${s.sessionId}`, { all: args.all });
        return { containers };
      }),
    },
    {
      name: 'docker_container_info',
      title: 'Inspect a container',
      description:
        'Get details, logs, or stats for one Docker container on a host. mode selects which: '
        + '"details" (inspect), "logs" (recent output), or "stats" (resource usage). Secret-looking '
        + 'environment variables and labels are redacted from "details"; read them on the host if '
        + 'you genuinely need a value.',
      mutating: false,
      hostArg: 'host',
      inputSchema: {
        host: hostArg,
        containerId: z.string().describe('Container id or name'),
        mode: z.enum(['details', 'logs', 'stats']).default('details'),
        tail: z.number().int().positive().max(2000).default(200).describe('Log lines when mode is logs'),
      },
      handler: (args, ctx) => ctx.sessions.withDockerSession(ctx.host, async (s) => {
        const base = `/docker/containers/${s.sessionId}/${encodeURIComponent(args.containerId)}`;
        if (args.mode === 'logs') return ctx.client.get(`${base}/logs`, { tail: args.tail, timestamps: true });
        if (args.mode === 'stats') return ctx.client.get(`${base}/stats`);
        // Inspect is the one mode that returns the container's environment.
        return redactContainerDetails(await ctx.client.get(base));
      }),
    },
    {
      name: 'docker_container_action',
      title: 'Control a container',
      description:
        'Start, stop, restart, pause, unpause, or remove a Docker container on a host. Mutating.',
      mutating: true,
      hostArg: 'host',
      inputSchema: {
        host: hostArg,
        containerId: z.string().describe('Container id or name'),
        action: z.enum(['start', 'stop', 'restart', 'pause', 'unpause', 'remove']),
        force: z.boolean().default(false).describe('Force removal when action is remove'),
      },
      handler: (args, ctx) => ctx.sessions.withDockerSession(ctx.host, (s) => {
        const base = `/docker/containers/${s.sessionId}/${encodeURIComponent(args.containerId)}`;
        if (args.action === 'remove') {
          return ctx.client.request('DELETE', `${base}/remove`, { query: { force: args.force } });
        }
        return ctx.client.post(`${base}/${args.action}`, {});
      }),
    },
  ];
}
