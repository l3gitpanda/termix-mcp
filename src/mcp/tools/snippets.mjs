import { z } from 'zod';

// Snippet inventory. Execution lives in exec.mjs (run_snippet) because it
// targets a host and shares the mutation gating with run_command.
export function snippetTools() {
  return [
    {
      name: 'list_snippets',
      title: 'List snippets',
      description: 'List saved Termix snippets, or fetch one by id (with its content).',
      mutating: false,
      hostArg: null,
      inputSchema: { id: z.number().optional().describe('Snippet id to fetch in full') },
      handler: (args, ctx) => (args.id !== undefined
        ? ctx.client.get(`/snippets/${args.id}`)
        : ctx.client.get('/snippets')),
    },
  ];
}
