import http from 'node:http';

// A minimal in-process Termix stand-in: just enough of the API for the session
// manager, run_command, and the reconnect path. Records the call sequence so a
// test can assert write -> chmod -> execute -> delete ordering.
// `delays` maps a path suffix to milliseconds the mock waits before it
// answers, e.g. { executeFile: 400 }. Holding one endpoint open is the only
// way to observe which timeout a given call was dispatched with.
export function startMockTermix({
  dropSessionOnce = false,
  execRc = 0,
  execStdout = 'termix-mcp-ok\nuid=0(root)',
  execStderr = '',
  delays = {},
} = {}) {
  const state = {
    calls: [],
    sessions: new Set(),
    files: new Map(),
    dropped: false,
  };

  let pendingPath = null;

  function json(res, status, body) {
    const text = JSON.stringify(body);
    const send = () => {
      // The client may have aborted on its own timeout while we waited.
      if (res.writableEnded || res.destroyed) return;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(text);
    };
    const key = Object.keys(delays).find((k) => pendingPath?.endsWith(k));
    if (key) setTimeout(send, delays[key]).unref?.();
    else send();
  }

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://mock');
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const body = raw ? JSON.parse(raw) : {};
      const p = url.pathname;
      pendingPath = p;
      state.calls.push({ method: req.method, path: p, body });

      if (p === '/users/me') return json(res, 200, { id: 'u1', username: 'panda' });
      if (p === '/host/db/host' && req.method === 'GET') {
        return json(res, 200, [{ id: 1, name: 'web', ip: '10.0.0.1', port: 22, username: 'root' }]);
      }
      if (p === '/host/db/host/1') {
        return json(res, 200, { id: 1, name: 'web', ip: '10.0.0.1', port: 22, username: 'root' });
      }

      if (p === '/ssh/file_manager/ssh/connect') {
        state.sessions.add(body.sessionId);
        return json(res, 200, { status: 'success' });
      }
      if (p === '/ssh/file_manager/ssh/keepalive') return json(res, 200, { ok: true });
      if (p === '/ssh/file_manager/ssh/disconnect') {
        state.sessions.delete(body.sessionId);
        return json(res, 200, { ok: true });
      }

      if (p === '/ssh/file_manager/ssh/writeFile') {
        // Simulate Termix forgetting the session exactly once, to drive the
        // reconnect-and-retry path.
        if (dropSessionOnce && !state.dropped) {
          state.dropped = true;
          state.sessions.delete(body.sessionId);
          return json(res, 400, { error: 'SSH session not found or not connected' });
        }
        state.files.set(body.path, body.content);
        return json(res, 200, { success: true });
      }
      if (p === '/ssh/file_manager/ssh/changePermissions') {
        return json(res, 200, { success: true });
      }
      if (p === '/ssh/file_manager/ssh/executeFile') {
        // Emulate the REAL Termix, which is where the exit-code bug came from:
        // it always reports exitCode 0 for the API call itself, never fills
        // `error`, merges the script's streams into `output`, and appends the
        // script's true status as a trailing EXIT_CODE line. The previous mock
        // returned a well-behaved shape instead, so the integration test was
        // asserting a contract the real server does not honour -- which is how
        // the bug reached production.
        const script = state.files.get(body.filePath) ?? '';
        const nonce = (script.match(/__TERMIX_MCP_[0-9a-f]+__/) ?? [])[0];
        // Reproduce the wrapper's output byte for byte: `cat` emits each stream
        // verbatim, and each closing marker is printed with one leading newline.
        // Both streams are delimited, so Termix's own EXIT_CODE trailer lands
        // after the final marker rather than inside stderr.
        //
        // Getting this exactly right is load-bearing. A mock that omits the
        // closing marker sends the parser down its legacy fallback, so the
        // integration tests would exercise a path the real server never takes
        // and say nothing about the one it does.
        const output = nonce
          ? `${nonce} rc=${execRc}\n${nonce} stdout\n${execStdout}\n`
            + `${nonce} stderr\n${execStderr}\n${nonce} end\nEXIT_CODE:${execRc}`
          : `${execStdout}\n${execStderr}\nEXIT_CODE:${execRc}`;
        return json(res, 200, {
          success: true,
          exitCode: 0,
          output,
          error: '',
          timestamp: '2026-08-13T00:00:00.000Z',
        });
      }
      if (p === '/ssh/file_manager/ssh/deleteItem') {
        // Termix 2.7.0 semantics, modelled deliberately: WITHOUT `permanent`
        // the item is moved to ~/.termix-trash instead of being removed, so it
        // is still sitting on the host afterwards. Keeping it in `files` under
        // its trash path -- rather than quietly dropping it -- is what makes
        // the "no temp script left behind" assertion a real regression guard
        // for the flag. A mock that deleted either way would pass whether or
        // not the client sent it, which is the whole failure being guarded.
        if (!body.permanent) {
          const content = state.files.get(body.path);
          state.files.delete(body.path);
          state.files.set(`/root/.termix-trash/files${body.path}`, content);
          return json(res, 200, { message: 'Item moved to trash', path: body.path });
        }
        state.files.delete(body.path);
        return json(res, 200, { success: true });
      }
      if (p === '/ssh/file_manager/ssh/readFile') {
        const path = url.searchParams.get('path');
        return json(res, 200, { content: state.files.get(path) ?? '', path, encoding: 'utf8' });
      }

      return json(res, 404, { error: `unmocked ${req.method} ${p}` });
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        state,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}
