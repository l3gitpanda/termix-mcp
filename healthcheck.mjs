// Container healthcheck. Runs inside the container, so it talks to the loopback
// listener rather than the published LAN port.
//
// It authenticates. The unauthenticated /healthz answer is a bare {ok:true} by
// design -- it must not tell the LAN anything -- but that is only liveness of
// this process, and liveness is not the same as being able to do the job. On
// 2026-08-14 this server answered ok:true while its API key owned no hosts, so
// every tool call failed target resolution and the container still read healthy.
// Running inside the container, this probe has MCP_HTTP_TOKEN available, so it
// can ask for the detailed answer and fail on what that reveals.
const port = process.env.HTTP_PORT ?? '8080';
const token = process.env.MCP_HTTP_TOKEN ?? '';

try {
  const response = await fetch(`http://127.0.0.1:${port}/healthz`, {
    signal: AbortSignal.timeout(4000),
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  const body = await response.json();

  if (!response.ok || !body.ok) {
    console.error(`unhealthy: ${JSON.stringify(body)}`);
    process.exit(1);
  }

  // Only the authenticated response carries this. Without a token the check
  // degrades to the old liveness-only behaviour rather than failing, so a
  // deployment that has not set one does not flap.
  if (body.termixReachable === false) {
    console.error(`unhealthy: Termix is not reachable: ${body.termixError ?? 'unknown error'}`);
    process.exit(1);
  }

  process.exit(0);
} catch (error) {
  console.error(`healthcheck failed: ${error.message}`);
  process.exit(1);
}
