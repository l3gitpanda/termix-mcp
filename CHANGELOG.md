# Changelog

## 0.6.0

The two timeouts that had to be tuned against each other are now independent:
command execution has its own clock, and a session's idle clock no longer runs
while that session is busy.

### Added
- **`TERMIX_EXEC_TIMEOUT_MS` bounds command execution on its own, so one slow
  command no longer slows every read.** `TERMIX_TIMEOUT_MS` is global to every
  Termix API call, so raising it to 240000 on 2026-08-19 — which is what made
  `run_command` usable for an apt install or a service restart with a long
  `TimeoutStartSec` — widened the failure tail on everything else at the same
  time. GETs retry twice, so a genuinely hung `read_file` or `list_files` took
  roughly **12 minutes** to fail instead of one.

  The long clock now reaches the `executeFile` call and nothing else.
  `writeFile` and `changePermissions`, which bracket it inside `run_command`,
  keep the short global timeout along with every host, file and Docker call.
  `run_snippet` is unaffected: Termix dispatches a snippet and returns without
  waiting for it.

  Defaults are chosen so an in-place upgrade changes nothing —
  `TERMIX_EXEC_TIMEOUT_MS` defaults to 240000 and `TERMIX_TIMEOUT_MS` still
  defaults to 20000. A deployment that raised the global value should now lower
  it back to 20000; the shipped compose file says so at both keys.

### Fixed
- **A session's `lastActive` is refreshed when an operation finishes, and the
  idle sweep skips sessions with work in flight.** It was stamped when the
  session was *acquired* and never again, so the sweep measured from the START
  of a call rather than from the last sign of life. That is the whole reason
  `TERMIX_TIMEOUT_MS` had to be held under `TERMIX_SESSION_IDLE_MS`: a longer
  timeout let the sweep disconnect a session that was still carrying a running
  command, and the 60-second margin between 240000 and 300000 held only because
  the two calls ahead of `executeFile` complete in well under a second.

  An in-flight counter now decouples them. A session carrying work is never
  reaped no matter how long ago it was acquired, and its idle clock restarts
  when the work returns. LRU eviction skips busy sessions for the same reason;
  when every session is busy the pool overshoots `TERMIX_MAX_SESSIONS` rather
  than killing a live command, and says so in the log — each of those sessions
  becomes evictable again the moment its operation returns.

## 0.5.0

Termix 2.7.0 compatibility, and the escape hatch closed over its three new
remote-execution surfaces.

### Fixed
- **`run_command` stopped cleaning up after itself on Termix 2.7.0.** From
  2.7.0 `deleteItem` *moves* an item to `~/.termix-trash` unless the request
  sets `permanent`, so the cleanup in `runScript`'s `finally` deleted nothing.
  Each call writes a script plus two capture files, and the capture files hold
  whatever the command printed — the reason they are created under `umask 077`
  in the first place — so every command was parking its own output in the SSH
  user's home for the trash retention window (7 days by default), on every host
  it touched.

  Where `/tmp` is a tmpfs it failed in a quieter way: the trash move is a
  cross-device rename, which fails outright, and cleanup is best-effort, so the
  files were never removed at all and nothing said so.

  Both call sites now send `permanent`. The field is ignored by 2.6.x, which
  destructures only `sessionId`/`path`/`isDirectory`, so this is safe to deploy
  before the Termix upgrade as well as after. The mock models the 2.7.0
  semantics, so the existing "no temp script left behind" assertion is now a
  real guard for the flag rather than passing either way.

### Added
- **`delete_item` takes a `permanent` argument, defaulted to `true`.** That
  keeps the tool meaning what its name and every previous release said it
  means; 2.7.0 flipped the server-side default the other way, which would have
  silently turned it into "move to trash" — freeing no space, and failing
  outright with `409 trashUnavailable` on hosts where the trash directory
  cannot be created. Pass `false` to use Termix's trash deliberately.

### Changed
- **`call_api` now refuses `/automations`, `/fleet`, and `/ai`.** All three are
  new in Termix 2.7.0 and all three reach a shell without going through
  `resolveAllowed`: an automation step can be a `run_command` action, a fleet
  execute runs across every member host at once, and `/ai/proposals/:id/apply`
  is exactly the human approval that Termix AI's safety model rests on — which
  the hatch could grant to a proposal it had just generated itself through
  `/ai/chat/stream`. `/ai/providers` additionally stores third-party provider
  API keys, which neither the root-anchored rules nor `SENSITIVE_SEGMENTS`
  covered.

  None of them carries a host id in the request — the target is stored
  server-side and used when the automation or fleet job later runs — so
  `extractHostIds` finds nothing and the blocklist never gets a chance to
  apply. They had to be refused by path or not at all.

  Denied by whole prefix, as `/vault` and `/guacamole` already are, because the
  surface is new and unexercised; the rules are anchored with `(\/|$)` so a
  longer route that merely shares the prefix stays reachable. Narrow them once
  the surface has been reviewed against a live 2.7.0 instance.

### Operational note
Established by source comparison against Termix 2.7.0, not yet against a live
instance. Termix's own `executeFile`, `changePermissions`, `readFile` and
`writeFile` handlers are byte-identical across 2.6.0, 2.6.1 and 2.7.0, no
endpoint this server calls was removed or moved, `GET /host/db/host` still
returns a flat array (2.7.0 subhosts are a `parentHostId` field, not nesting),
and the auth path changed only by an error-message refactor. Still run
`npm run verify-live -- --host <id>` after upgrading to confirm the
`executeFile` path on the live instance.

## 0.4.5

The HTTP front end: who called, how many sessions, and what "healthy" means.

### Fixed
- **A rejected token was answered in silence.** Both 401 paths returned without
  logging anything, and the gate — which writes `audit.jsonl` — only runs for a
  request that got *past* authentication. So probing or brute-forcing the one
  credential that reaches a shell on every host produced no line in the app log,
  no audit record, and nothing for the SIEM to alert on. Every other rejection
  on this path was already logged: cross-origin, cross-profile reuse, unknown
  session id. Only the one that matters most was not.

  Rejections now log at `warn` with the caller's address, the request method,
  and an eight-character prefix of the SHA-256 of the presented credential —
  enough to correlate repeated attempts with the same wrong token, never enough
  to recover it.

- **No record said where a call came from.** Audit entries carried the access
  profile but no source address, so two holders of one token were
  indistinguishable in the trail — which is the first question anyone asks after
  a token leaks. Records now carry `peer`, and the session-initialized log line
  carries the client address.

  Behind a reverse proxy the socket peer is always the proxy, so the real
  address is in `X-Forwarded-For` — a caller-supplied header. Believing it
  unconditionally would let anyone reaching the published port forge a source
  address into the audit trail, which is worse than recording none. It is
  therefore read **only** when the direct peer is listed in the new
  `TERMIX_TRUSTED_PROXIES`, and only its rightmost entry, which is the one that
  proxy appended and the one hop it actually vouches for. Unset, the header is
  ignored entirely and the socket peer is recorded.

- **MCP sessions were never released.** An entry left the registry only when its
  transport closed, which a client that simply goes away never does. Since an
  unknown session id correctly gets a 404 and the client re-initializes,
  *ordinary reconnecting* was what accumulated them — one live `McpServer` per
  reconnect, each with its own SSH session pool, which made `TERMIX_MAX_SESSIONS`
  a ceiling per MCP session rather than overall. One deployment logged nine
  initializations in ninety seconds and not a single close.

  The registry is now bounded by `MCP_SESSION_IDLE_MS` (default 30 minutes) and
  `MCP_MAX_SESSIONS` (default 32), swept on each request rather than on a timer.
  Idle entries go first, then least-recently-seen until the cap is met. The
  session serving the current request is never a candidate, so a burst of
  reconnects cannot evict the one it just created. Set either to 0 to disable
  that bound.

- **`/healthz` reported liveness it had not checked.** It answered `ok: true`
  unconditionally, and the container probe asserted exactly that — so on
  2026-08-14 this server read healthy while its API key owned no hosts and every
  tool call failed target resolution.

  The authenticated response now carries `termixReachable`, from a real probe
  with a 15-second cache. `healthcheck.mjs` runs inside the container, so it has
  `MCP_HTTP_TOKEN` and asks for that answer; without a token it degrades to the
  old liveness-only check rather than flapping. The **unauthenticated** response
  is unchanged — still a bare `{ok: true}`, so an unauthenticated caller can
  neither read the state nor make this server generate traffic to Termix on
  demand.

### Changed
- **Authentication is checked before the Origin.** An unauthenticated caller
  could previously tell a rejected Origin (403) from a rejected token (401). The
  Origin check still runs before the request body is read, which is what the
  DNS-rebinding defence actually rests on.
- **Socket bounds.** `HTTP_MAX_CONNECTIONS` (256) and `HTTP_HEADERS_TIMEOUT_MS`
  (20s, the slowloris control). The request timeout is deliberately left at
  Node's default: this transport holds a long-lived SSE stream open, and
  tightening that is how you break it.
- **`MCP_HTTP_TOKEN` says at boot that it is still live.** With a policy file the
  per-profile tokens select access and this one reads like dead config — but it
  still gates the detailed health response, so it belongs in a rotation.

### Added
- `index-http.mjs` now has tests. It is a top-level script, so importing it
  starts a server; the suite spawns it against the mock Termix and drives the
  real request path — health, both 401 branches, a successful initialize, the
  404-for-unknown-session contract, and eviction under a cap of one.

## 0.4.4

Three read-only tools could hand a caller credentials.

### Fixed
- **`docker_container_info` returned the container's environment verbatim.**
  Docker's inspect payload carries `Config.Env`, and the tool is `mutating:
  false` and a member of `@readonly` — so a look-but-do-not-touch profile could
  read every secret in every container on every host it could reach. Including
  this server's own container, whose environment holds `TERMIX_API_KEY` and the
  token for every profile. That is not an information leak but an escalation:
  the read-only caller comes back holding the ops token.

  Environment variables and labels are now judged on the key, by the same rule
  `redactArgs` already applied to audit records, so `FOO_TOKEN` is caught
  wherever it appears and `PATH` survives. `Cmd`, `Entrypoint` and `Args` get a
  positional pass as well, since a command line carries its secrets by position
  rather than by name. `scrubValue` is deliberately *not* used there: its `-p`
  rule would rewrite a published port as `-p[redacted]` in exactly the output
  someone reads to understand a container.

- **`session_logs` could walk out of its own endpoint.** Its `id` was
  interpolated into the API path unencoded. `urlFor` concatenates onto the
  origin and `fetch`'s URL parser resolves `..`, so an id of
  `../users/api-keys` left `/session_logs` entirely and reached any endpoint
  the API key can — around `call_api`'s denylist, around `extractHostIds` and
  the host blocklist, around the session-ownership check. A `?` in the value
  opened a genuine query string too. From a tool in `@readonly`.

  This defeated the deployed `readonly` profile's stated design, which denies
  `call_api` precisely so its path rules are not advisory.

- **`access_policy_check`'s `fromFile` read any path on this server.** It
  passed the caller's string straight to `readFileSync` — an arbitrary local
  read inside a container holding every profile token in its environment and
  the audit trail on its data volume. It is now confined to the directory
  holding the configured policy file, which is what the flag is for, and
  refused outright when no policy file is configured. Absent, unreadable and
  is-a-directory all report the same message, so it cannot be used as an
  existence oracle.

  A JSON syntax error from a file is no longer echoed either: V8 embeds a
  window of the input in the message, so the error handed back the first bytes
  of whatever file was named. An inline document still reports its parse error
  verbatim — that one is the caller's own text, and it is what makes a draft
  fixable.

### Added
- **The Termix client refuses a path that does not resolve to itself.**
  `urlFor` concatenates, so any caller interpolating an unencoded value into a
  path can leave the endpoint it named. Rather than trusting each call site to
  remember, the client now compares the resolved pathname against the requested
  one before opening a socket and refuses the mismatch with
  `PATH_NOT_CANONICAL`. Every existing caller already encoded its segments or
  passed a number, so nothing else changed behaviour — the guard is there for
  the tool nobody has written yet.

## 0.4.3

A restart no longer strands every connected client.

### Fixed
- **A request carrying an unknown session id got `400`; it now gets `404`.**
  The session registry is in memory by design, so a container restart
  terminates every session. Streamable HTTP defines exactly one recovery signal
  for that — `404`, on which a client MUST start a new session with a fresh
  `InitializeRequest`. It recovers on nothing else. Answering `400` told a
  compliant client its request was *malformed*, which is permanent rather than
  recoverable, so it never re-initialized and stayed broken until someone
  reconnected it by hand. The client was behaving correctly; the status was
  wrong.

  The GET path was hit hardest: the SSE stream reconnect carries the session id,
  so every restart broke that too.

  A request with **no** session id that is not an initialize is still `400` —
  that one really is a malformed request. Both directions are pinned by tests.
  Cross-profile session reuse stays `403`: that session exists and the caller is
  not entitled to it, and `404` there would let a caller probe for the existence
  of other profiles' sessions.

  Session persistence across restarts is deliberately *not* the fix. The spec
  does not ask for it, and a durable session store would reintroduce the
  session-fixation risk the cross-profile check exists to prevent.

### Operational note
Until every client is running against this build, treat a restart as requiring a
manual reconnect of each connected client, and batch policy edits into a single
restart. After it, compliant clients reconnect transparently.

## 0.4.2

Escape-hatch hardening, and secrets out of the audit log.

### Fixed
- **A leading `//` ate the first path segment.** `new URL("//users/me")` reads
  `users` as the *host* and yields `/me`, and the slash-collapsing ran after
  that parse — too late. So `//credentials` normalised to `/` and walked past
  the credential denylist. Separators are now collapsed before any URL parsing
  and again after decoding. This is the same class as the canonicalisation flaw
  fixed earlier: the rules judged a path the caller never wrote.
- **The credential denylist only matched at the root.** `/credentials` was
  refused, `/ssh/credentials` was not. A backstop now matches credential terms
  in *any* path segment, so a route remounted under a prefix in some later
  Termix release cannot slip past rules written for today's layout.
- **`call_api` checked host ids in query and body but not in path segments.**
  The known-route list enumerates what Termix has now; any future `/…/:hostId`
  would have reached a blocklisted host through the escape hatch while the
  dedicated tools refused it. Every all-digit segment is now checked. This
  over-matches on purpose — a numeric snippet id is checked as though it were a
  host — because a false refusal on the escape hatch is recoverable and a false
  pass is not.
- **`write_file` content was recorded verbatim in the audit log.** Output was
  deliberately reduced to bytes+sha256; input was not, so writing a `.env` or a
  key put it in cleartext in `audit.jsonl` — which is bind-mounted for Wazuh to
  ship, so it left the host too. File bodies now get the same treatment at *any*
  size: the size cap was the wrong control, since a short secret is the
  dangerous case. No preview either. Enable `AUDIT_CAPTURE_OUTPUT` if you want
  bodies recorded deliberately.
- **`read_file` counted a phantom last line.** A file ending in a newline splits
  to a trailing empty element that `wc -l` does not count, so `totalLines` was
  one high and every negative-offset tail spent one line on it — `offset:-3`
  returned two real lines.

### Changed
- **`@readonly` no longer includes `call_api`.** It is what someone writes when
  they mean "look but do not touch", and it was handing that profile the generic
  API passthrough — the policy checker's own warning fired on it, which is the
  clearest sign the group misled the person reaching for it. Grant `call_api`
  explicitly where a profile needs it.
- The tool catalog reports `mutating: "conditional"` for `call_api` instead of
  serializing its predicate to `undefined`.
- `write_file`'s description records that Termix creates a NEW file as 0666
  regardless of the host umask (an existing file does keep its mode — verified).

### Not a defect
A test pass reported `toggle_state` as process-global state shared between HTTP
clients. It is not: `state` is a local of `buildServer`, and `buildServer` runs
only on the initialize path, after the existing-session branch returns — so each
MCP session gets its own flag, and cross-profile session reuse is refused. The
report's own evidence points the same way: its calls were being refused by the
gate while another client's were running, which is per-session isolation
working. The three toggles in the log are two clients toggling their own
sessions. The deploy-time pin it asks for also already exists
(`TERMIX_ALLOW_TOGGLE=false`).

### Known gaps
Unchanged from 0.4.1: no remote-side timeout, and `access_policy_check` still
fails fast on the first structural error. Newly recorded: `list_processes` and
`host_metrics` cannot be narrowed (both need filter parameters, both are API
additions rather than fixes), host capability flags are surfaced but not
pre-checked so a disabled file manager surfaces as an auth error, and
`read_file` passes through Termix's raw shell error for a missing path.

## 0.4.1

Fixes from the v0.3.5 live test pass. The first two are the ones that matter:
one corrupts data silently, one misreports a security boundary.

### Fixed
- **`run_command` ate a trailing newline from stderr.** `echo to-stderr >&2` and
  `echo -n to-stderr >&2` returned byte-identical results, so the caller could
  not tell them apart. The strip pattern had been loosened to cope with *empty*
  stderr, where Termix's `EXIT_CODE:` trailer lands flush against the marker —
  and that looseness then consumed a newline the command really wrote. The two
  cases pull in opposite directions, which is what made it subtle. The wrapper
  now prints a closing delimiter, so stderr is bounded by markers on both sides
  and nothing is stripped or inferred. Both directions are asserted, together.
- **`access_policy_check` reported blocklisted hosts as reachable.** A profile
  with `"hosts": "all"` listed `app` and `legacy-box` under `reachableHosts`
  while the running server refused both. `resolveAllowed` checks the global
  blocklist first; the decision table did not, despite printing
  `globalBlocklist: enforce` in the same response. Those rows are now
  `blockedByGlobal: true` — kept distinct from the profile's own verdict,
  because the two denials live in different config.
- **`call_api` dumped raw HTML on error statuses.** The HTML sniff sat *after*
  the `!response.ok` throw, so it never saw an error response: a 404 put a full
  `<!DOCTYPE html>` page into the tool result and the container log. Hoisted
  above the throw, and the page body is dropped rather than recorded.
- **Ambiguous host references silently resolved to the first match.** Two
  stopped guests both report `0.0.0.0` today, so a call could land on a machine
  the caller did not name. Ambiguity is now an error listing the candidates and
  their ids. This was the one place the resolver guessed.
- **`tunnel_action` could create a phantom tunnel.** Termix acknowledges
  disconnect/cancel for a name that does not exist — and persists a record for
  it, so an agent typo appended permanent junk to the estate's tunnel list. The
  name is now resolved against the live status first, as `connect` already does
  for its host.

### Added
- **The access policy's own `hosts` patterns are linted at boot**, not just
  `TERMIX_BLOCKLIST`. The deployed policy pinned IPs that had drifted, so two
  hosts were held out **by name alone** — rename either record in Termix and the
  block would lapse silently, with nothing to show for it.
- `access_policy_check` flags a profile with no token that is not the
  `defaultProfile`: nothing can select it, so it is dead config rather than a
  restriction.

### Changed
- `host_status` puts the host's **name on every entry**, not only on flagged
  ones. The map is keyed by Termix record id — the identifier every host
  argument's own description tells callers not to use — so the server had been
  contradicting its own guidance.
- `AUDIT_ARG_MAX` default 512 → **4096**. The command is the point of the
  default audit record, and 512 clipped long ones in exactly the field the trail
  exists for. The per-line cap still bounds the record.
- `MAX_OUTPUT_BYTES` default 128 KiB → **32 KiB**. The old value was tuned for a
  filesystem: a single result could exceed an MCP client's per-result budget and
  spill to a file, arriving unreadable in context. `read_file`'s offset/limit is
  how to ask for more.
- `delete_item`'s description states that it removes a directory's contents
  recursively and without confirmation. It is `rm -rf` and read like `rmdir`.

### Known gaps
- **No remote-side timeout.** `TERMIX_TIMEOUT_MS` bounds the HTTP call, not the
  remote process: a command that outlives the request keeps running on the host,
  unreaped, with its output discarded. The fix is wrapping the body in
  `timeout`, which means re-invoking the script through another shell — that
  changes which interpreter the body runs under and how `pipefail` applies, so
  it wants a live test rather than a blind edit. Temp-file cleanup on the
  timeout path is already correct.
- `access_policy_check` still fails fast on the first structural error, so the
  decision table and pattern diagnostics are unreachable until a draft already
  parses — backwards for a tool meant to check drafts.

## 0.4.0

Optional full output capture, so the trail can answer what the agent *saw* and
not only what it ran.

### Added
- **`AUDIT_CAPTURE_OUTPUT`** (default `false`). The existing audit records what
  ran — tool, profile, host, requested host even when refused, args, exit code,
  duration — plus `bytes` + `sha256` of each result, but never the result. That
  was deliberate: an unbounded record is an audit-*deletion* primitive, because
  a few huge outputs roll real history out of the retained generations using
  only permitted tools.

  Turned on, outputs are also kept verbatim — stdout, stderr, file contents, and
  other tool results — in a **separate** file (`AUDIT_OUTPUT_PATH`, default
  `audit-output.jsonl` beside the main log) with its own rotation budget. That
  separation is what preserves the original property: however much the agent
  reads, it cannot evict the command trail.

  Each copy is joined to its command record by call id and carries that record's
  digest, so editing the output file afterwards makes the two disagree. Records
  are clipped at `AUDIT_OUTPUT_MAX_RECORD_BYTES` (256 KB) so one large read
  cannot flush output history either.

  ⚠ The file becomes a verbatim copy of everything the agent read, secrets
  included. It is created 0600, and the Wazuh `localfile` stanza names
  `audit.jsonl` explicitly, so the sibling is not shipped to the SIEM unless you
  add it. Deliberately not scrubbed: a redacted transcript answers "did it read
  the key?" with a maybe.

## 0.3.5

Fixes from a full live test pass against the deployed server. The first two are
the ones that matter: one loses output, one misattributes a denial.

### Fixed
- **`run_command` discarded all output when the command contained `exit N`.**
  The wrapper used a brace group, which runs in the current shell, so an
  explicit `exit` terminated the script before the trailer that replays the
  captured streams. Both streams were already redirected into files nothing ever
  read back, so `echo hi; exit 7` returned empty stdout and a null status. It is
  a subshell now, and there are tests for `exit` — there were none before.
- **Profile denials claimed the host was blocklisted.** One `blocked` boolean
  covered both refusals and the gate appended a fixed sentence to either, so a
  blocklist denial said so twice and a profile denial named a list the host was
  not on — pointing whoever read it at the wrong config file. The error now
  carries `reason: 'blocklist' | 'profile'` and the message stands alone.
- **`host_status` bypassed the gate.** It declared no `hostArg` and resolved
  inside the handler, so a refused attempt was audited with `target: null` and
  `host: null` — a SIEM rule keyed on the host missed exactly the denials worth
  alerting on. The gate now understands an optional host argument. Its
  no-argument form also returned every host unmarked, including blocklisted and
  out-of-profile ones, disagreeing with `list_hosts`; those are now annotated the
  same way.
- **`process_signal` and `service_action` reported failure as success.** Termix
  answers some endpoints with HTTP 200 and `{success: false}`; that is now an
  error rather than a result the caller has to inspect.
- **Command output files were world-readable** (644) in a world-writable `/tmp`
  while the script itself was 700 — the same secret-bearing content, the weaker
  mode. They are created under `umask 077`, which is then restored so files the
  command creates keep the host's normal permissions. Cleanup also moved to the
  caller's `finally`, which runs however the script ended.
- **`call_api` returned Termix's web UI for unknown paths.** Termix serves its
  SPA on anything the API does not claim, so a wrong path was a 200 with a full
  HTML page. Detected and reported as "no such endpoint".

### Added
- **`read_file` takes `offset` and `limit`** (1-based; a negative offset tails).
  Output is capped at 128 KB and the truncation footer used to suggest grep/tail
  via `run_command` — a *mutating* tool, so a read-only profile had no way to
  narrow a large file at all. The footer now leads with these.
- A **startup warning for blocklist entries matching no host in Termix**. The
  deployed blocklist carried IPs that had drifted, so only its name entries were
  load-bearing and "name OR ip" was not true. Nothing surfaced that; now boot
  does.
- `access_policy_check` **validates that patterns resolve** — tool patterns
  naming no registered tool are errors, host patterns matching no known host are
  warnings. A typo in a `deny` list previously denied nothing and still
  validated clean.

### Changed
- `alert_action` and `tunnel_action` attach an `unconfirmed` note: Termix
  acknowledges both for targets that do not exist, so the acknowledgement is not
  evidence anything happened.
- `service_action`'s description records that Termix demands a sudo password
  configured on the host record and 403s without one, even when the SSH user is
  root.
- `audit_logs` explains a 403 once — Termix's audit endpoint is admin-only and
  this server's key is non-admin, so retrying cannot help.
- Termix's UI `toast` payload is stripped from successful responses.
- `deploy/docker-compose.yml` regenerated from the deployed copy and demoted to
  a reference copy. It had claimed to be authoritative while missing
  `read_only: true` and binding the audit log where the `wazuh-agent` mount
  cannot see it — deploying it would have silently ended SIEM ingestion.
- `access-policy.json` is gitignored; `access-policy.example.json` stays tracked.

### Notes
Not addressed here: `host_metrics` returns every section on every call, and the
list tools use four different empty shapes. Both are real and both are API
changes rather than fixes.

## 0.3.4

Tool calls now name the machine they touched.

### Changed
- **Every `host` argument now asks for the name, not the id.** A Termix host id
  is an internal record id with no relation to the guest's PVE VMID, so a
  numeric argument showed up as an unrecognisable number wherever the call was
  rendered — the MCP client's tool-call view, the audit JSONL, a refusal message
  — and no one could tell which machine had been touched without looking it up.
  `resolve()` has always accepted a name, an IP, or an id equally, so the name
  costs nothing and carries meaning. The six duplicated `'Host id or name'`
  descriptions are now one shared definition in `src/mcp/tools/host-arg.mjs`.
- A test ties every host-taking tool to that shared description, so a tool added
  later cannot quietly hand-roll its own and reintroduce the opaque form. It
  names the offending tools when it fails.

### Notes
`resolve()` reads an all-digits string as an id, so a host literally *named*
`112` cannot be addressed by that name. Documented on the argument rather than
changed, since ids are the older contract.

## 0.3.3

Finishes the 0.3.2 fix, which left the sentinel in `stderr`.

### Fixed
- **`stderr` was `"EXIT_CODE:0"` on every successful command.** 0.3.2 stripped
  Termix's trailer with a pattern that required a newline in front of it. When
  the command writes nothing to stderr, `cat` of the empty stream emits nothing,
  so the trailer arrives flush against the delimiter with no newline to anchor
  on and survived the strip. The newline is now optional.
- **The test fixture and the mock both inserted that newline unconditionally**,
  which made the empty-stderr case impossible to express — so a green suite said
  nothing about the most common path through the code. Both now emit the trailer
  the way a shell actually does, and the regression is covered at the unit and
  integration levels; reintroducing the old pattern fails two tests.

### Changed
- `copy_item`'s description now states that Termix always suffixes the copy
  (`notes.txt` → `notes.txt_copy_34176704`) even with no collision, so callers
  read the destination from the result instead of predicting it.

### Notes
Two findings from the same test pass are upstream, not fixable here — both tools
proxy Termix verbatim: `copy_item`'s forced rename (above), and `host_metrics`
returning `login_stats` entries whose `ip` holds `Fri` or `Aug`, a column
misparse in Termix's own `last` handling. `audit_logs` returning 403 is a
deployment fact rather than a defect: Termix's audit endpoint is admin-only and
the MCP's API key belongs to a non-admin account. The server's own audit JSONL
is unaffected and recorded the refusal.

## 0.3.2

`run_command` now reports whether the command actually succeeded. Until this
release it always reported success.

### Fixed
- **`exitCode` was Termix's, not the command's.** `executeFile` returns `0` for
  the API call itself whatever the script did, and encodes the real status as a
  trailing `EXIT_CODE:N` line in the merged output. The value was passed through
  as-is, so every failure read as a success — silently, and in the unsafe
  direction, since an agent branching on `exitCode` never saw an error.
- **`stdout` and `stderr` are separate again.** Termix merges the two, so
  `stderr` was always empty and anything written to it appeared in `stdout`.
- **The `EXIT_CODE:N` sentinel no longer leaks into output.** `find_file` splits
  `stdout` into matches, so it had been returning `EXIT_CODE:0` as a filesystem
  path on every call.
- The temporary script now redirects each stream to its own file and prints
  both back with delimiters carrying a **per-invocation nonce**, so a command
  whose own output contains a marker cannot forge an exit code. When the markers
  are absent — a shell too broken to reach the trailer — `exitCode` is `null`
  with a note, never `0`: an unknown status must not read as success.
- **The mock Termix now emulates the real one.** It previously returned a
  well-behaved `exitCode`, so the integration test asserted a contract the real
  server does not honour. That is why this bug survived a green suite.

### Notes
- `host_metrics` column misalignment in `login_stats` (an IP field containing
  `Fri` or `Aug`) is upstream: the tool proxies Termix's `/metrics/{id}`
  verbatim and parses nothing.

## 0.3.1

A packaging fix: `access_policy_schema` never worked in a container.

### Fixed
- **`access-policy.schema.json` is now copied into the image.** The tool
  `require()`s it from the repo root, which the Dockerfile did not `COPY`, so
  `access_policy_schema` threw `MODULE_NOT_FOUND` in every container deploy
  while passing over stdio, where the repo root supplies the file. No other
  tool was affected, and nothing about access enforcement changed.
- **A test now guards the image contents.** It walks `src/` for relative loads
  that escape into the repo root and asserts a `COPY` instruction brings each
  one in, parsing the `COPY` sources rather than searching the Dockerfile text
  — a substring search is satisfied by any comment that merely names the file,
  including the one now explaining the rule. CI's existing image smoke test
  missed the original bug because it only loads `src/config.mjs`, and the
  schema is required lazily inside the tool handler rather than at import time.

## 0.3.0

Every restriction is now a choice, and a policy can be generated and checked
rather than hand-written and hoped over.

### Added
- **Per-dimension modes.** Hosts, tools and paths each take
  `allowlist` (fail closed), `blocklist` (fail open), `all` (off) or `none`
  (locked), so the scope of each restriction is decided rather than baked in.
  In `allowlist`, `deny` carves exceptions out of the grant; in `blocklist`,
  `allow` carves them back in. An omitted mode is inferred from the lists, so
  every 0.2.0 policy keeps its exact meaning.
- **Shorthand**: `"hosts": "all"` or `"hosts": ["a","b"]` (allowlist of those).
- **`globalBlocklist`** per profile — `enforce` (default) or `ignore`, so
  `TERMIX_BLOCKLIST` is a default rather than a ceiling no profile can pass.
  Ignoring it is warned about at startup.
- **Tool groups**: `@readonly`, `@files`, `@files.read`, `@files.write`,
  `@exec`, `@docker`, `@system`, `@tunnels`, `@snippets`, `@observability`,
  `@meta`, `@policy`, `@hosts`, `@escape`. An unknown group is an error, not a
  silently empty rule, and tests assert the groups match the real tool set.
- **`access-policy.schema.json`** — a JSON Schema for the policy file.
- **`access_policy_schema`** and **`access_policy_check`** tools, so a model can
  fetch the schema plus the live vocabulary, draft a policy, and have it
  validated and explained before anyone installs it. Both are read-only and
  never write to disk.
- **`scripts/policy.mjs`** — `init`, `validate`, `explain`, `groups`, `schema`
  from the shell. `validate` exits non-zero, so it drops into CI or a hook.

## 0.2.0

Per-profile access control, plus the security hardening from a full adversarial
audit.

### Added
- **Access profiles** (`TERMIX_POLICY_FILE`). A JSON policy defines profiles that
  scope **which machines** a caller may reach (fails closed — a profile reaches
  only what it lists), **read vs write** (`"mutations": "deny"` pins a profile
  read-only and `toggle_state` cannot lift it), **which tools** it may call, and
  **which paths** file operations may touch. Deny beats allow everywhere.
- A profile is chosen by bearer token on HTTP or `TERMIX_PROFILE` on stdio, may
  carry its own Termix API key so Termix enforces the same limits at the source,
  and may reference secrets by env var or SHA-256 so the policy file itself is
  safe to commit. Sessions cannot be reused across profiles.
- `TERMIX_ALLOW_TOGGLE=false` pins a deployment read-only for its whole life.
- `MAX_OUTPUT_BYTES` caps a single tool result so one large read cannot exhaust
  the model's context.

### Fixed
- **`call_api` no longer bypasses the safety model.** It reached any endpoint,
  so the blocklist and mutation gate were advisory; it could read a blocklisted
  host's stored SSH password and open sessions to it. Paths are now canonicalized
  before matching (case, duplicate slashes and percent-encoding were each enough
  to evade the first denylist), credential and session-opening endpoints are
  refused, and host records are read-only so a rename cannot escape the list.
- `find_file` was declared read-only but writes and executes a script on the
  host; `tunnel_action` reached a host the gate never checked.
- An oversized record could roll the audit history out of retention; records are
  capped, fsynced, `0600`, and a failure to summarize no longer loses the entry.
- Audit records now carry the profile, the hosts and SSH sessions touched, an
  accurate per-call `mutating` flag, and output digests; session open and close
  are audited.

## 0.1.0

First release. An MCP server for [Termix](https://github.com/Termix-SSH/Termix)
modeled on the XPipe MCP, with a real SSH session manager and full audit logging.

- **33 tools** across hosts, command execution, file operations, Docker, systemd
  and processes, tunnels, snippets, and Termix's own audit/session logs/alerts,
  plus a `call_api` escape hatch and a `help` tool.
- **Command execution with captured output** (`run_command`): writes a temporary
  script to the host, makes it executable, runs it via Termix's file manager, and
  deletes it — returning exit code, stdout, and stderr.
- **Stateful SSH session manager**: lazy per-host connect, keepalive, idle
  teardown, LRU cap, one transparent reconnect when Termix forgets a session,
  and per-host serialization.
- **Safety**: mutating tools are disabled by default and enabled per session with
  `toggle_state`; a configurable host blocklist refuses reads and writes to named
  hosts or IPs.
- **Logging**: pino JSON to stderr (never stdout in stdio mode), an append-only
  rotated `audit.jsonl` recording every tool call with secrets redacted, and an
  optional Wazuh syslog forwarder.
- **Dual transport**: stdio for a workstation, streamable-HTTP (bearer-guarded,
  with `/healthz`) for a container.
