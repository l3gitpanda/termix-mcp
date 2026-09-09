import { z } from 'zod';
import {
  canonicalizePath, checkForbidden, extractHostIds, extractSessionId,
} from '../../termix/api-policy.mjs';

// Server-control and escape-hatch tools. These are never host-targeted and
// never mutation-gated themselves: toggle_state is the thing that opens the
// gate, and call_api enforces its own read/write rule inline.
export function metaTools({ catalog }) {
  return [
    {
      name: 'toggle_state',
      title: 'Enable or disable mutations',
      description:
        'Enable or disable mutating tools for this session. Mutations start disabled; call this with '
        + '{ enabled: true } after the user authorizes writes, and { enabled: false } to lock them again.',
      mutating: false,
      hostArg: null,
      inputSchema: { enabled: z.boolean().describe('true to allow writes, false to forbid them') },
      handler: (args, ctx) => {
        // Disabling writes is always permitted; only ENABLING them can be pinned
        // off, so a read-only deployment cannot be talked into becoming writable.
        if (args.enabled && !ctx.config.allowToggle) {
          throw new Error(
            'This server is pinned read-only (TERMIX_ALLOW_TOGGLE=false). Writes cannot be enabled at '
            + 'runtime; the operator must change the deployment configuration.',
          );
        }
        ctx.state.mutationsEnabled = args.enabled;
        ctx.logger.info({ mutationsEnabled: args.enabled }, 'mutation state toggled');
        return {
          mutationsEnabled: ctx.state.mutationsEnabled,
          note: args.enabled
            ? 'Writes are now enabled for this session.'
            : 'Writes are now disabled for this session.',
        };
      },
    },
    {
      name: 'call_api',
      title: 'Call a raw Termix API endpoint',
      description:
        'Call any Termix REST endpoint directly, for operations no dedicated tool covers. GET is always '
        + 'allowed; non-GET methods are treated as mutations and refused unless writes are enabled. The path '
        + 'is routed to the correct backend service automatically. The same host blocklist the dedicated '
        + 'tools enforce applies here, and credential, API-key, and session-opening endpoints are refused '
        + 'outright -- use the dedicated tools to reach a host.',
      // Classified per call: a GET is a read, anything else is a write. A static
      // false would let a DELETE be recorded as non-mutating.
      mutating: (args) => (args?.method ?? 'GET') !== 'GET',
      hostArg: null,
      inputSchema: {
        method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']).default('GET'),
        path: z.string().describe('API path beginning with /, e.g. /users/me'),
        query: z.record(z.string(), z.any()).optional().describe('Query parameters'),
        body: z.any().optional().describe('JSON body for non-GET methods'),
      },
      handler: async (args, ctx) => {
        if (!args.path.startsWith('/')) throw new Error('path must begin with /');
        // Canonicalize ONCE, then both check and send this exact form. Matching
        // a raw path and forwarding it unchanged is what let "/Host/DB/Host/2//
        // Password" slip past the rules and reach the route anyway.
        const path = canonicalizePath(args.path);

        const forbidden = checkForbidden(path, args.method);
        if (forbidden) {
          throw new Error(
            `call_api refuses ${path}: it ${forbidden}. This endpoint is off-limits to the escape hatch.`,
          );
        }

        if (args.method !== 'GET' && !ctx.state.mutationsEnabled) {
          throw new Error(
            `call_api ${args.method} is a mutation; enable writes with toggle_state first.`,
          );
        }

        // Apply the blocklist to any host this call targets, exactly as a
        // dedicated tool would. resolveAllowed throws for a blocked host, and
        // recordHost puts the target in the audit record -- without it, a
        // call_api against a host would be invisible to a search by host name.
        const hostIds = extractHostIds(path, args.query, args.body);
        for (const hostId of hostIds) {
          ctx.recordHost(await ctx.hosts.resolveAllowed(hostId));
        }

        // A stateful call must use a session this server opened, so a leaked or
        // guessed session id cannot be used to reach a blocklisted host.
        const sessionId = extractSessionId(path, args.query, args.body);
        if (sessionId && !ctx.sessions.ownsSession(sessionId)) {
          throw new Error(
            `call_api refuses session "${sessionId}": this server did not open it. Use the file or docker `
            + 'tools, which open sessions through the blocklist.',
          );
        }

        return ctx.client.request(args.method, path, { query: args.query, body: args.body });
      },
    },
    {
      name: 'help',
      title: 'Describe this server',
      description:
        'Describe this Termix MCP server: the available tools (with read/write classification), the current '
        + 'mutation state, the blocklist, the resolved Termix base URL, and detected backend capabilities.',
      mutating: false,
      hostArg: null,
      inputSchema: {},
      handler: (_args, ctx) => ({
        server: 'termix-mcp',
        version: ctx.version,
        baseUrl: ctx.config.baseUrl,
        mutationsEnabled: ctx.state.mutationsEnabled,
        blocklist: ctx.config.blocklist,
        // The effective access policy, so the model can see what it may reach
        // instead of discovering the boundary by being refused.
        access: ctx.profile?.summary?.() ?? { profile: null },
        capabilities: ctx.state.capabilities,
        sessions: ctx.sessions.stats(),
        tools: catalog
          .filter((t) => !ctx.profile || ctx.profile.allowsTool(t.name))
          .map((t) => ({
            name: t.name,
            mutating: t.mutating,
            description: t.description,
          })),
      }),
    },
  ];
}
