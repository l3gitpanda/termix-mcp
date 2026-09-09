import crypto from 'node:crypto';

// Audit records must be safe to keep and safe to forward: no secrets, and no
// single call able to bloat the log. Both rules are enforced on VALUES, not on
// a list of blessed field names, because call_api accepts an arbitrary body and
// an allowlist only covers the shapes someone thought of.

// Matched against a normalized key (lowercased, separators stripped), so
// api_key / API-KEY / apiKey all collapse to the same token.
const SECRET_PATTERN = /(pass|secret|token|credential|apikey|privatekey|sshkey|passphrase|auth|cookie|totp|otp|backupcode)/;

// Short names too generic for the pattern but secret in Termix's payloads:
// `key` is the SSH private key on a host record and on /host/quick-connect.
const SECRET_EXACT = new Set(['key', 'pin', 'otp']);

// Keys that look secret by the pattern above but are safe and useful to keep.
const SECRET_EXCEPTIONS = new Set([
  'passwordlogin',      // a boolean setting, not a password
  'authtype',           // "password" | "key" | "none" -- the method, not the secret
  'requiresauth',
  'tokenname',
]);

function normalizeKey(key) {
  return String(key).toLowerCase().replace(/[_\-\s]/g, '');
}

function isSecretKey(key) {
  const normalized = normalizeKey(key);
  if (SECRET_EXCEPTIONS.has(normalized)) return false;
  return SECRET_EXACT.has(normalized) || SECRET_PATTERN.test(normalized);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// Value shapes that carry a secret regardless of the field they arrive in --
// a command line is the common case (`mysql -phunter2`, `curl -H "Authorization: ..."`).
export function scrubValue(text) {
  return text
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[private key redacted]')
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, '$1 [redacted]')
    .replace(/(-p)(?!\s)\S+/g, '$1[redacted]')            // mysql -p<password>
    .replace(/(--?(?:password|token|secret|api[-_]?key)[=\s])\S+/gi, '$1[redacted]');
}

// Docker's inspect payload carries the container's whole environment, and
// docker_container_info is a read-only tool inside @readonly. Returned raw, a
// look-but-do-not-touch profile could read every secret in every container on
// every host it can reach -- including this server's own tokens, since it runs
// as a container too. That is not an information leak, it is an escalation to
// whatever the most privileged profile can do.
//
// Environment and labels are judged on the KEY, the same rule redactArgs uses,
// so FOO_TOKEN is caught wherever it appears and PATH survives intact.
export function redactContainerDetails(details) {
  if (!details || typeof details !== 'object' || Array.isArray(details)) return details;

  const out = { ...details };
  const config = details.Config;
  if (config && typeof config === 'object') {
    out.Config = { ...config };
    if (Array.isArray(config.Env)) out.Config.Env = config.Env.map(redactEnvEntry);
    if (config.Labels && typeof config.Labels === 'object' && !Array.isArray(config.Labels)) {
      out.Config.Labels = Object.fromEntries(
        Object.entries(config.Labels)
          .map(([key, value]) => [key, isSecretKey(key) ? '[redacted]' : value]),
      );
    }
    for (const field of ['Cmd', 'Entrypoint']) {
      if (Array.isArray(config[field])) out.Config[field] = redactArgv(config[field]);
    }
  }
  if (Array.isArray(details.Args)) out.Args = redactArgv(details.Args);
  return out;
}

function redactEnvEntry(entry) {
  if (typeof entry !== 'string') return entry;
  const eq = entry.indexOf('=');
  // A bare name with no "=" carries no value to leak.
  if (eq === -1) return entry;
  const key = entry.slice(0, eq);
  return isSecretKey(key) ? `${key}=[redacted]` : entry;
}

// A command line carries its secrets positionally, so the key rule does not
// reach them. Deliberately NOT scrubValue: that helper's `-p` rule rewrites any
// token starting `-p`, which would turn a published port into "-p[redacted]"
// in output an operator reads to understand a container.
const SECRET_FLAG = /^--?(?:pass(?:word)?|token|secret|api[-_]?key)$/i;
const INLINE_SECRET_FLAG = /^(--?(?:pass(?:word)?|token|secret|api[-_]?key)=)(.+)$/i;

function redactArgv(list) {
  return list.map((item, index) => {
    if (typeof item !== 'string') return item;
    const previous = list[index - 1];
    // `--password hunter2` is two elements, so the value has to be caught by
    // looking at what preceded it.
    if (typeof previous === 'string' && SECRET_FLAG.test(previous)) return '[redacted]';
    return item.replace(INLINE_SECRET_FLAG, '$1[redacted]');
  });
}

// A string is kept verbatim only while it is small; past the cap it becomes a
// bounded preview plus a hash of the whole, which still proves what ran.
function boundString(value, maxBytes) {
  const scrubbed = scrubValue(value);
  const bytes = Buffer.byteLength(scrubbed, 'utf8');
  if (bytes <= maxBytes) return scrubbed;
  return {
    bytes,
    sha256: sha256(scrubbed),
    // Slice by BYTES so the preview cannot exceed the cap on multi-byte text.
    preview: Buffer.from(scrubbed, 'utf8').subarray(0, maxBytes).toString('utf8'),
  };
}

// Arguments that carry a file body rather than describing an operation. These
// are hashed at ANY size -- the size cap is the wrong control for them, since a
// short secret is the dangerous case.
const PAYLOAD_KEYS = new Set(['content']);

// Produce an audit-safe copy of a tool's arguments: secrets removed, every
// oversized value truncated + hashed, recursion depth bounded.
export function redactArgs(args, maxBytes = 512, depth = 0) {
  if (typeof args === 'string') return boundString(args, maxBytes);
  if (args === null || typeof args !== 'object') return args;
  if (depth > 6) return '[nested too deeply]';

  const out = Array.isArray(args) ? [] : {};
  // Arrays from an arbitrary call_api body can be huge; keep the shape, cap the count.
  const entries = Object.entries(args).slice(0, 100);
  for (const [key, value] of entries) {
    if (isSecretKey(key)) {
      out[key] = value === undefined || value === null || value === '' ? null : '[redacted]';
    } else if (PAYLOAD_KEYS.has(String(key).toLowerCase()) && typeof value === 'string') {
      // File CONTENT is payload, not a description of what ran, so it gets the
      // same treatment as tool output: bytes plus a hash, never the bytes. A
      // .env or a private key written through write_file otherwise sat in
      // cleartext in audit.jsonl -- which is bind-mounted for Wazuh to ship, so
      // the secret left the host too. No preview: the interesting part of a key
      // is its beginning. Enable AUDIT_CAPTURE_OUTPUT if you want the bodies.
      out[key] = { bytes: Buffer.byteLength(value, 'utf8'), sha256: sha256(value) };
    } else if (typeof value === 'string') {
      out[key] = boundString(value, maxBytes);
    } else if (value && typeof value === 'object') {
      out[key] = redactArgs(value, maxBytes, depth + 1);
    } else {
      out[key] = value;
    }
  }
  if (Object.keys(args).length > entries.length) {
    out['[truncated]'] = `${Object.keys(args).length - entries.length} more fields`;
  }
  return out;
}
