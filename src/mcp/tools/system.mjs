import { z } from 'zod';

import { hostArg } from './host-arg.mjs';
import { assertUpstreamOk } from '../../util/upstream.mjs';

// systemd and process management via Termix's host-metrics managers. These
// address the host by its Termix id directly (no file/docker session needed).
export function systemTools() {
  return [
    {
      name: 'list_services',
      title: 'List systemd services',
      description: 'List systemd services on a host, with their load/active/sub state.',
      mutating: false,
      hostArg: 'host',
      inputSchema: { host: hostArg },
      handler: (_args, ctx) => ctx.client.get(`/host-metrics/managers/services/${ctx.host.id}`),
    },
    {
      name: 'service_action',
      title: 'Control a systemd service',
      description:
        'Start, stop, restart, enable, or disable a systemd unit on a host. Mutating. '
        + 'NOTE: Termix gates this behind a sudo password set on the host record and refuses with '
        + '403 "requires elevated privileges" without one -- even when the SSH user is already '
        + 'root. If that appears, the fix is in Termix\'s host configuration, not the command; '
        + 'run_command with systemctl is the workaround.',
      mutating: true,
      hostArg: 'host',
      inputSchema: {
        host: hostArg,
        unit: z.string().describe('Unit name, e.g. "nginx.service"'),
        action: z.enum(['start', 'stop', 'restart', 'enable', 'disable']),
      },
      handler: async (args, ctx) => assertUpstreamOk(
        await ctx.client.post(
          `/host-metrics/managers/services/${ctx.host.id}/action`,
          { unit: args.unit, action: args.action },
        ),
        `service ${args.action}`,
      ),
    },
    {
      name: 'list_processes',
      title: 'List processes',
      description: 'List running processes on a host with pid, user, CPU, memory, and command.',
      mutating: false,
      hostArg: 'host',
      inputSchema: { host: hostArg },
      handler: (_args, ctx) => ctx.client.get(`/host-metrics/managers/processes/${ctx.host.id}`),
    },
    {
      name: 'process_signal',
      title: 'Signal a process',
      description: 'Send a signal (TERM, KILL, HUP, or INT) to a process on a host by pid. Mutating.',
      mutating: true,
      hostArg: 'host',
      inputSchema: {
        host: hostArg,
        pid: z.number().int().positive(),
        signal: z.enum(['TERM', 'KILL', 'HUP', 'INT']).default('TERM'),
      },
      handler: async (args, ctx) => assertUpstreamOk(
        await ctx.client.post(
          `/host-metrics/managers/processes/${ctx.host.id}/signal`,
          { pid: args.pid, signal: args.signal },
        ),
        `signal ${args.signal} to pid ${args.pid}`,
      ),
    },
  ];
}
