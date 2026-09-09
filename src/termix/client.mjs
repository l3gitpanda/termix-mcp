// Thin HTTP client for the Termix backend. One origin by default; optional
// per-service overrides for deployments that do not unify the seven backend
// services behind nginx. Every request carries the bearer key, normalizes
// errors, and never lets the token escape into a thrown message.

// Path-prefix -> service key. Longest-prefix wins, so /ssh/file_manager routes
// to FILES before the bare /ssh could match anything.
const SERVICE_ROUTES = [
  ['/ssh/file_manager', 'files'],
  ['/ssh/tunnel', 'tunnels'],
  ['/docker', 'docker'],
  ['/host-metrics', 'stats'],
  ['/metrics', 'stats'],
  ['/status', 'stats'],
  ['/uptime', 'stats'],
  ['/serial', 'serial'],
];

export class TermixError extends Error {
  constructor({ status, code, message, method, path, body }) {
    super(message);
    this.name = 'TermixError';
    this.status = status ?? 0;
    this.code = code ?? null;
    this.method = method;
    this.path = path;
    this.body = body ?? null;
  }
}

function serviceFor(path) {
  for (const [prefix, service] of SERVICE_ROUTES) {
    if (path === prefix || path.startsWith(`${prefix}/`)) return service;
  }
  return 'main';
}

// Pull the most useful human string out of Termix's error envelope. The backend
// is inconsistent -- some routes return {error}, some {message}, some {toast} --
// so try them in that order before falling back to the status line.
function describeError(status, body) {
  if (body && typeof body === 'object') {
    return body.error || body.message || body.toast || body.detail || `HTTP ${status}`;
  }
  if (typeof body === 'string' && body.trim()) return body.trim().slice(0, 300);
  return `HTTP ${status}`;
}

export function createClient(config, logger) {
  const { baseUrl, serviceUrls, apiKey, timeoutMs, retry } = config;

  function urlFor(path) {
    const origin = serviceUrls[serviceFor(path)] ?? baseUrl;
    return `${origin}${path}`;
  }

  // Defence in depth for the whole tool surface. urlFor CONCATENATES, so any
  // caller that interpolates a value into a path without encoding it can walk
  // out of the endpoint it named: fetch's URL parser resolves "..", and a "?"
  // in the value starts a real query string. session_logs did exactly that,
  // which put every Termix endpoint behind a read-only tool, around call_api's
  // denylist and the host blocklist both.
  //
  // Every caller in this server either encodes its segments or passes numbers,
  // so the resolved pathname must come back byte-identical. When it does not,
  // something traversed, and the request is refused rather than sent to a route
  // no rule was evaluated against.
  function assertPathIntact(method, path, url) {
    const resolved = new URL(url).pathname;
    if (resolved === path) return;
    throw new TermixError({
      status: 0,
      code: 'PATH_NOT_CANONICAL',
      message: `refusing to request ${path}: it resolves to ${resolved}, so a path segment `
        + 'was interpolated without encoding. This is a bug in the calling tool.',
      method,
      path,
    });
  }

  async function once(method, path, { query, body, timeoutMs: overrideMs } = {}) {
    // Per-call override, used only by the executeFile path. Everything else
    // takes the global TERMIX_TIMEOUT_MS, which is what keeps a hung metadata
    // read failing in seconds rather than minutes.
    const callTimeoutMs = overrideMs ?? timeoutMs;
    let url = urlFor(path);
    assertPathIntact(method, path, url);
    if (query) {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined && value !== null) params.append(key, String(value));
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    const headers = { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' };
    const init = { method, headers, signal: AbortSignal.timeout(callTimeoutMs) };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }

    let response;
    try {
      response = await fetch(url, init);
    } catch (error) {
      // Network failure, DNS, or timeout. No status; the caller's retry logic
      // decides whether to try again.
      throw new TermixError({
        status: 0,
        code: error.name === 'TimeoutError' ? 'timeout' : 'network',
        message: error.name === 'TimeoutError' ? `request timed out after ${callTimeoutMs}ms` : `network error: ${error.message}`,
        method,
        path,
      });
    }

    const text = await response.text();
    let parsed = null;
    if (text) {
      try { parsed = JSON.parse(text); } catch { parsed = text; }
    }

    // Termix serves its single-page app on any path the API does not claim, so
    // an unknown endpoint answers with HTML rather than JSON -- 200 and
    // index.html on some paths, 404 and an Express error page on others.
    //
    // Checked BEFORE the !response.ok branch, deliberately. Sitting after it,
    // this never saw an error response at all, so a 404 fell through to
    // describeError and put a full HTML document into the tool result and the
    // container log.
    const contentType = response.headers.get('content-type') ?? '';
    const looksLikeHtml = typeof parsed === 'string'
      && (/^\s*<(!doctype|html)/i.test(parsed) || contentType.includes('text/html'));
    if (looksLikeHtml) {
      throw new TermixError({
        status: response.status,
        code: 'NOT_AN_API_ENDPOINT',
        message: `no such endpoint ${path}: Termix served a web page (HTTP ${response.status}) `
          + 'instead of an API response, so nothing is routed there. Check the path.',
        method,
        path,
        // Dropped on purpose: the page is never the answer, and keeping it puts
        // an HTML document in the audit record too.
        body: null,
      });
    }

    if (!response.ok) {
      throw new TermixError({
        status: response.status,
        code: (parsed && typeof parsed === 'object' && parsed.code) || null,
        message: describeError(response.status, parsed),
        method,
        path,
        body: parsed,
      });
    }

    // `toast` is Termix's UI notification payload -- an icon, a variant, a
    // duration. It means nothing to a model and rides along on every file
    // mutation, so drop it from successful responses. The error path above
    // already read it before this point, so failures keep their message.
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && 'toast' in parsed) {
      const { toast, ...rest } = parsed;
      return rest;
    }

    return parsed;
  }

  // GETs are safe to retry; mutations are not, and are dispatched with retry 0.
  async function request(method, path, opts = {}) {
    const retries = method === 'GET' ? retry : 0;
    let attempt = 0;
    for (;;) {
      try {
        return await once(method, path, opts);
      } catch (error) {
        const retryable = error instanceof TermixError
          && (error.status === 0 || [502, 503, 504].includes(error.status));
        if (!retryable || attempt >= retries) throw error;
        const backoff = [200, 500, 1200][attempt] ?? 1200;
        attempt += 1;
        logger?.warn({ path, attempt, status: error.status, code: error.code }, 'retrying Termix request');
        await new Promise((resolve) => setTimeout(resolve, backoff));
      }
    }
  }

  return {
    get: (path, query) => request('GET', path, { query }),
    // opts carries a per-call { timeoutMs }. Only run_command's executeFile
    // uses it; see config.execTimeoutMs for why it is not global.
    post: (path, body, opts) => request('POST', path, { body, ...opts }),
    put: (path, body) => request('PUT', path, { body }),
    del: (path, body) => request('DELETE', path, { body }),
    // Escape hatch used by the call_api tool. Goes through the same auth,
    // routing, and error normalization as every typed method.
    request: (method, path, opts) => request(method, path, opts),
    urlFor,
    serviceFor,
  };
}
