import pino from 'pino';

// stdout is the MCP protocol channel in stdio mode, so the logger must never
// write to fd 1: it goes to a configured file, stderr otherwise. HTTP mode
// keeps the identical wiring so the two transports cannot drift.
export function createLogger({ level = 'info', file = '' } = {}) {
  const destination = file
    ? pino.destination({ dest: file, mkdir: true })
    : pino.destination({ dest: 2 });
  return pino({ level, base: { app: 'termix-mcp' } }, destination);
}
