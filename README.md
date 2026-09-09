# termix-mcp

An [MCP](https://modelcontextprotocol.io) server for
[Termix](https://github.com/Termix-SSH/Termix), the self-hosted SSH and
server-management platform. It gives an MCP client (Claude Code, Claude Desktop)
the ability to list hosts, run commands, read and write files, control Docker and
systemd, manage tunnels, and read Termix's own logs — modeled on the XPipe MCP,
with a proper SSH session manager and full audit logging.

## What it can do

36 tools, grouped:

| Group | Tools |
|---|---|
| Hosts | `list_hosts`, `host_status`, `host_metrics` |
| Command execution | `run_command` (captures output), `run_snippet` |
| Files | `read_file`, `list_files`, `get_file_info`, `find_file`, `write_file`, `create_file`, `create_directory`, `delete_item`, `move_item`, `copy_item`, `change_permissions` |
| Docker | `docker_containers`, `docker_container_info`, `docker_container_action` |
| System | `list_services`, `service_action`, `list_processes`, `process_signal` |
| Tunnels & snippets | `list_tunnels`, `tunnel_action`, `list_snippets` |
| Termix observability | `audit_logs`, `session_logs`, `recent_activity`, `alerts` |
| Access policy | `access_policy_schema`, `access_policy_check` |
| Meta | `call_api`, `toggle_state`, `help` |

`run_command` deserves a note: Termix has no direct run-a-command endpoint, so it
is implemented by writing a temporary script to the host through the file manager,
making it executable, executing it (Termix's `executeFile` returns the captured
output), and deleting it. It therefore runs in a **non-login shell with a minimal
environment** — set any variables you need explicitly.

## Safety model

- **Mutations are disabled by default.** Every tool that changes state
  (`run_command`, `write_file`, `service_action`, `docker_container_action`, …)
  refuses until the client calls `toggle_state { enabled: true }` for the session.
  Read tools always work. This mirrors the read-only-by-default posture of the
  XPipe MCP.
- **Host blocklist.** `TERMIX_BLOCKLIST` is a comma list of Termix host names
  and/or IPs that this server refuses to touch **for reads and writes alike**.
  Empty by default — it names machines in *your* estate, so there is no sane
  value to ship.
  Matching is exact and case-insensitive (so `app` blocks a host named
  `app` without also blocking `app-main`). Blocklisted hosts still appear
  in `list_hosts`, tagged `"blocked": true`.
- **Secrets never leave Termix.** File-manager and Docker sessions are opened by
  host id; Termix resolves the stored SSH credentials server-side. This server
  never handles SSH passwords or keys.
- **The `call_api` escape hatch is contained.** It reaches the ~240 endpoints
  with no dedicated tool, but it is not a way around the rules: the blocklist is
  applied to any host id in the path, query, or body; non-GET counts as a
  mutation; endpoints that hand out credentials or mint access are refused
  outright (`/host/db/host/{id}/password`, `/credentials`, `/vault`,
  `/users/api-keys`, `/users/me/token`, host exports, `/host/quick-connect`,
  `/guacamole`, RBAC sharing); and session-opening endpoints are refused so a
  session can only be created through a tool that checked the blocklist first.
  A stateful call must present a session this server opened.

### Per-profile access control

A single global blocklist cannot express "this token may touch these machines."
Set `TERMIX_POLICY_FILE` to a JSON policy defining **profiles**, each scoping:

| Scope | Behaviour |
|---|---|
| **Machines** | Which hosts the profile may reach. Matches a host's name or IP, `*` wildcard, case-insensitive. |
| **Read vs write** | `"mutations": "deny"` pins the profile read-only. `toggle_state` cannot lift it. |
| **Tools** | Which tools it may call, by name, glob, or `@group`. |
| **Paths** | Which paths the file tools may touch. Canonicalized first, so `/opt/appdata/../../etc/shadow` is refused. |
| **Global blocklist** | `"globalBlocklist": "enforce"` (default) or `"ignore"`, so `TERMIX_BLOCKLIST` is a default for most profiles rather than a ceiling none can be granted past. |

#### Choosing the scope: modes

Each dimension carries its own **mode**, so you decide how strict it is rather
than accepting a posture baked into the server:

| Mode | Meaning |
|---|---|
| `allowlist` | Default **deny**. Permits what `allow` matches; `deny` carves exceptions *out* of the grant. **Fails closed** — a host added later is unreachable until granted. |
| `blocklist` | Default **allow**. Refuses what `deny` matches; `allow` carves exceptions *back in*. **Fails open.** |
| `all` | No restriction on this dimension. |
| `none` | Nothing passes. |

The list that names the mode is the intent; the other list is the exceptions to
it — which is why the tie-breaker flips with the mode.

Omit `mode` and it is inferred: `allowlist` if you wrote `allow`, `blocklist` if
you wrote only `deny`, otherwise the dimension default (**hosts** `allowlist`,
**tools** and **paths** `all`). Shorthand is accepted anywhere a rule set is:

```jsonc
"hosts": "all",                                   // a mode on its own
"hosts": ["app-main", "web-proxy"],                // array = allowlist of these
"tools": { "mode": "blocklist", "deny": ["@escape"] }
```

#### Tool groups

So a policy need not enumerate 34 names — miss one and the restriction has a
hole. `@readonly` `@hosts` `@files` `@files.read` `@files.write` `@exec`
`@docker` `@system` `@tunnels` `@snippets` `@observability` `@meta` `@policy`
`@escape`. Run `node scripts/policy.mjs groups` to list members. An unknown
group is an error, never a silently empty rule, and the test suite asserts the
groups still match the real tool set.

See `access-policy.example.json` for five worked profiles.

#### Generating and checking a policy

The format is designed to be written *by a model* and verified before it is
trusted. `access-policy.schema.json` is the JSON Schema; from a session, two
read-only tools close the loop:

- **`access_policy_schema`** — returns the schema, the modes, the group
  definitions, the real tool names, and your live host inventory, so a draft
  refers to machines and tools that actually exist.
- **`access_policy_check`** — validates a candidate policy *without applying it*
  and reports what each profile would permit: reachable hosts, per-tool and
  per-path decisions, and lint warnings.

Neither writes anything; installing a policy stays a deliberate human act. The
same checks are available from the shell:

```bash
node scripts/policy.mjs init > access-policy.json   # starting template
node scripts/policy.mjs validate access-policy.json # exits non-zero if invalid
node scripts/policy.mjs explain  access-policy.json --profile ops \
     --host app-main,legacy-box --path /etc/shadow,/opt/appdata/x
node scripts/policy.mjs groups                      # group members and modes
```

Use `node scripts/policy.mjs` rather than `npm run policy` when redirecting to a
file — npm prints its banner to stdout and would corrupt the output.

A profile is selected by the **bearer token** on the HTTP transport (so each
token gets its own access), or by **`TERMIX_PROFILE`** on stdio. A session may
only be reused by the profile that created it. A profile may also carry its own
`termixApiKey`, in which case Termix's native host ownership enforces the same
restriction at the source — a bug here cannot then grant what Termix denies.

Tokens and keys can be given inline, as `tokenSha256`, or as `tokenEnv` /
`termixApiKeyEnv` naming an environment variable — so the policy file itself can
be committed alongside your compose config while the secrets stay in the env
file.

Enforcement lives in the gate and in `resolveAllowed`, the one function every
host-targeting path already goes through, so a new tool cannot reach a forbidden
machine by forgetting to ask.

> **Path rules only bind the file tools.** A shell command reads and writes
> wherever the SSH user can, so a path-restricted profile that still grants
> `run_command`, `find_file`, `run_snippet`, or `call_api` is not actually
> restricted. The server logs a warning at startup when a policy does this.

### Prompt injection is the threat that matters

Everything this server reads — a file, a container log, a terminal transcript —
flows into the model's context, and the model can run shell commands. So content
on a managed host can, in principle, instruct the agent. `toggle_state` is a lock
the model itself holds the key to: nothing stops it calling
`toggle_state { enabled: true }` except its own judgement.

If nobody is watching the session, set **`TERMIX_ALLOW_TOGGLE=false`**. That pins
the server read-only for its whole life — writes then require an operator
changing the deployment config, not a model changing its mind. Locking writes
back down at runtime always works; only enabling them is blocked.

### What the blocklist does and does not protect

The blocklist is a **guardrail, not a security boundary.** It stops this server
from *addressing* a forbidden host. It cannot stop a command that reaches one by
another route: `run_command` on a Proxmox node can `pct stop` a blocklisted
container, and a command on any host can SSH onward. Anyone with `run_command`
and writes enabled effectively has the access the target host's credentials
carry. Treat the blocklist as protection against mistakes, not against a
determined agent — and use a Termix account whose stored credentials only reach
what you are willing to have touched.

## Logging

- **App log**: pino JSON. In stdio mode it goes to **stderr** (stdout is the MCP
  channel) or to `LOG_FILE`.
- **Audit log**: every tool call is appended to `audit.jsonl` (under `DATA_DIR`)
  as one JSON line — tool, target host, redacted arguments, result summary, exit
  code, duration, success/error, the SSH sessions used, and the mutation state
  at the time. Refusals are recorded too, naming the host that was attempted, so
  a denied attempt on a blocklisted host leaves a trace. Command output is
  recorded as byte counts plus a SHA-256 rather than stored, so the record can
  be checked against a transcript without becoming a copy of everything the
  agent read. Opening and closing an SSH session are their own `session.open` /
  `session.close` events, since a session outlives the call that created it.
  Written `0600`, fsynced per record, size-capped per line, and rotated by size.
- **Wazuh (optional)**: set `WAZUH_ENABLED=true` to also emit each audit record
  as an RFC 5424 syslog line with an `@cee:` JSON payload over UDP. UDP is lossy
  and unauthenticated; for a durable feed, prefer a **Wazuh agent tailing
  `audit.jsonl`** with `log_format json` over the TLS agent channel:

  ```xml
  <localfile>
    <log_format>json</log_format>
    <location>/data/audit.jsonl</location>
  </localfile>
  ```

## Configuration

Copy `.env.example` and fill in `TERMIX_BASE_URL` and `TERMIX_API_KEY`. Create the
API key in Termix under **User Profile → API Keys**; the key's user must own the
hosts you intend to manage. Every variable and its default is documented in
`.env.example`. The most important ones:

| Variable | Default | Purpose |
|---|---|---|
| `TERMIX_BASE_URL` | *(required)* | Origin nginx serves the Termix API from |
| `TERMIX_API_KEY` | *(required)* | Bearer key from the Termix UI |
| `TERMIX_MUTATIONS_ENABLED` | `false` | Start with writes on |
| `TERMIX_BLOCKLIST` | *(empty)* | Hosts to refuse, by name or IP |
| `MCP_HTTP_TOKEN` | *(required for HTTP)* | Bearer guarding the `/mcp` endpoint |
| `WAZUH_ENABLED` | `false` | UDP syslog forwarding |

If the Termix backend services are **not** unified behind one origin, set the
per-service `TERMIX_URL_*` overrides.

## Running

### stdio (workstation)

```bash
npm install
TERMIX_BASE_URL=https://termix.example TERMIX_API_KEY=... npm run start:stdio
```

Register it with an MCP client. For Claude Code on Windows, add to the project
entry in `~/.claude.json` under `mcpServers`:

```json
"termix": {
  "command": "node",
  "args": ["C:\\path\\to\\termix-mcp\\src\\index-stdio.mjs"],
  "env": {
    "TERMIX_BASE_URL": "https://termix.example.com",
    "TERMIX_API_KEY": "<key>",
    "DATA_DIR": "C:\\path\\to\\termix-mcp\\data"
  }
}
```

### streamable-HTTP (container)

The container runs the HTTP transport. `deploy/docker-compose.yml` is the
source-of-truth compose. It needs an env_file holding `TERMIX_API_KEY` and
`MCP_HTTP_TOKEN`. Clients connect to `http://<host>:<port>/mcp` with
`Authorization: Bearer <MCP_HTTP_TOKEN>`. `GET /healthz` is unauthenticated for
the container probe.

Nothing about one deployment is baked into that file. Two variables shape the
compose itself, read from the `.env` beside it:

| Variable | Default | Purpose |
|---|---|---|
| `MCP_IMAGE` | *(placeholder)* | The image to run. Set it to what your CI publishes |
| `MCP_BIND_ADDR` | `127.0.0.1` | Address the published port binds to. Set it to this host's LAN address to reach the server from elsewhere |

Everything the server itself reads — including `TERMIX_TRUSTED_PROXIES`, which
you want set to your reverse proxy — goes in the `env_file`, not in the compose
`environment:` block. Compose's `environment:` **overrides** `env_file:`, so a
`${VAR:-}` entry there silently blanks the env file's value whenever the
variable is missing from the `.env` beside the compose.

`MCP_BIND_ADDR` defaults to loopback on purpose: publishing a port that can run
commands on real servers should be a decision, not a default. Bind an explicit
address rather than `0.0.0.0` so a re-IPed host fails loudly instead of quietly
listening somewhere unexpected.

## Verifying against a live instance

```bash
TERMIX_BASE_URL=... TERMIX_API_KEY=... npm run verify-live
# add --host <id|name> to also run the command-execution probe on a host
```

This confirms auth and the base URL, enumerates hosts (flagging blocklisted ones,
never touching them), and — with `--host` — proves that `executeFile` still
captures output on your Termix version.

## Development

```bash
npm install
npm test          # unit + integration (in-process mock Termix), no network
```

## Releasing

Two equivalent pipelines ship with the repo — use whichever forge you host on.
Keeping both costs nothing: GitHub reads only `.github/workflows`, and Forgejo
prefers `.forgejo/workflows` when it is present.

| | GitHub | Forgejo |
|---|---|---|
| Workflow | `.github/workflows/release.yml` | `.forgejo/workflows/release.yaml` |
| Registry | `ghcr.io/<owner>/<repo>` | the Forgejo instance itself |
| Credential | the built-in `GITHUB_TOKEN` | a `PACKAGERUNNER_TOKEN` secret |
| Setup | none | add the secret |

**On GitHub** nothing needs configuring: the workflow publishes to GHCR with the
token Actions already provides. Note that a package published this way starts
**private** — make it public from the package's settings page if you want others
to pull it.

**On Forgejo** the registry is taken from a `REGISTRY` repository variable, then
a `REGISTRY` repository secret, then the forge the workflow runs on — first
non-empty wins. Set one of the first two to the public name your registry is
reachable at, e.g. `git.example.com`.

Two things make this fiddlier than it looks, and both are why the fallback
chain exists:

- Some forges do not populate the `vars` context. An unset variable yields an
  empty string rather than an error, so a variable you *did* set can silently
  read as blank. If that happens, set the same value as a **secret** instead —
  secrets are carried reliably. Its value is masked in the run log.
- `GITHUB_SERVER_URL` is the **internal** origin on a proxied instance — an
  address and port serving plain HTTP, not the public name. Pushing there fails
  with `server gave HTTP response to HTTPS client` unless every daemon that
  pulls has an `insecure-registries` entry. The resolve step warns when the host
  it picked carries a port, which is the tell.

Both behave identically. On every push to `main` they install, test, and publish
`:main` plus an immutable `:sha-<short>` image. On a `v*` tag they additionally
verify that `package.json` and the tag agree and that `CHANGELOG.md` has a
matching `## <version>` section, then publish `:latest` and create the release
**with that changelog section as its body**, attaching `docker-compose.yml`,
`env.example`, and a source tarball. Both guards fail the build *before* an image
is pushed, so a release can never ship with notes that say nothing or a version
that lies about itself. The source tarball comes from `git archive` of the commit,
not the workspace, so an untracked `.env` or `audit.jsonl` physically cannot be
shipped in it.

To cut a release:

```bash
# 1. add a "## 0.2.0" section to CHANGELOG.md describing what changed
# 2. set the same version in package.json
git commit -am "release: 0.2.0" && git push
git tag v0.2.0 && git push origin v0.2.0
```

**`backfill-changelog.yaml`** — manual (`workflow_dispatch`) repair pass for
releases published before their changelog entry existed, or whose entry was
edited afterwards. It rewrites existing release bodies from `CHANGELOG.md` using
the same builder the release job uses, so a backfilled release is byte-identical
to a freshly cut one. **Dry run by default** — run it with `apply: false` first
to see what it would change, then `apply: true` to write. It patches only the
body; tags, target commits, and attached assets are untouched.

On Forgejo both jobs need a `PACKAGERUNNER_TOKEN` repository secret with package
and release write scope. Forgejo's automatic Actions token cannot write packages
(`unauthorized: reqPackageAccess`), and the `FORGEJO_`/`GITHUB_` secret-name
prefixes are reserved, which is why it carries this name. The GitHub workflow
needs no equivalent — `GITHUB_TOKEN` with `packages: write` covers it.

Verified live against Termix 2.6.0, and against 2.7.0 and 2.7.1 by source
comparison — every endpoint this server calls still exists at the same path,
and the `executeFile`, `changePermissions`, `readFile` and `writeFile` handlers
are byte-identical across 2.6.0, 2.6.1, 2.7.0 and 2.7.1. 2.7.0 changed one
behaviour that matters here: `deleteItem` moves to `~/.termix-trash` unless the
request sets `permanent`, which this server now always does for its own temp
files. 2.7.1 adds exactly one endpoint (`POST /credentials/{id}/duplicate`,
already refused by `call_api`'s `/credentials` rule) and removes or renames
none; its handler changes are confined to SSH connect-time key validation and
jump-host errors, both in shapes this server already parses. Two upstream
behaviours shifted, visibly but harmlessly: hosts with metrics polling disabled
are now SSH-probed each status cycle, so `host_status` can say `online` where
2.7.0 said `reachable` (Termix itself now generates periodic SSH logins on
those hosts — expect auth-log noise), and a failed connect through a jump host
can take ~65 s per hop server-side instead of ~30 s, which only matters when
`TERMIX_TIMEOUT_MS` is raised past its 20 s default. Run `verify-live` against
2.7.1 to confirm it on a live instance.

The API can drift between versions; if a Termix upgrade changes the
`executeFile`, `connect`, or `readFile` response shapes, re-run `verify-live`
and check the `run_command` path. A Termix release that adds an endpoint
reaching a shell also needs a look at `FORBIDDEN` in `src/termix/api-policy.mjs`,
since `call_api` is guarded by a denylist. Licensed Apache-2.0.
