# smoker

`smoker` is a reverse-proxy WAF written in Go. It sits between the Internet and
an existing web server (nginx/Apache/any HTTP backend), filtering all inbound
HTTP and HTTPS traffic before it reaches the backend. It ships as a single
static Linux binary with no external runtime dependencies.

> Purely defensive: it inspects traffic directed at the server it protects. It
> performs no offensive scanning and sends no collected data anywhere without
> explicit configured consent.

## Filesystem layout (mandatory)

| Path                     | Purpose                                             |
|--------------------------|-----------------------------------------------------|
| `/sbin/smoker`           | main executable                                     |
| `/etc/smoker/`           | configuration (read-only at runtime)                |
| `/etc/smoker/templates/` | Nuclei templates (CVE feeds + custom rules)         |
| `/var/log/smoker/`       | all logs + `reputation.db` runtime state            |
| `/var/www/smoker/`       | static challenge/captcha/block assets               |

Every component references these as hardcoded defaults (see
[`internal/paths`](internal/paths/paths.go)). Flags/env overrides exist **only
for testing** — never in production.

## Architecture

```
        :80/:443                 nftables DNAT/redirect            :18080/:18443
Internet ────────► [Firewall Controller] ─────────────────────► [Reverse Proxy core]
                    google/nftables                                    │
                                                                       ▼
                                             (1) IP Reputation check (fail-fast, O(1))
                                                                       │ clean/greylist
                                                                       ▼
                                             (2) Detection Engine  (Nuclei templates:
                                                  CVE signatures + custom behavioral)
                                                                       │
                                          ┌────────────────────────────┼───────────────┐
                                          ▼                            ▼               ▼
                                    session-matchers            action: block     clean →
                                    → Session/Behavior          / challenge /     backend
                                      Tracker                    log-only /       127.0.0.1:80
                                                                  rate-limit
```

Components (each an independent package under `internal/`):

- **[firewall](internal/firewall)** — nftables DNAT/redirect of public 80/443 to
  the proxy's internal high ports; runtime enable/disable for fail-open bypass.
- **[proxy](internal/proxy)** — `httputil.ReverseProxy` core; recovers the real
  pre-NAT destination via `SO_ORIGINAL_DST`; sets `X-Forwarded-For`/`X-Real-IP`.
- **[tlsterm](internal/tlsterm)** — TLS termination; SNI cert store built by
  parsing nginx/Apache vhosts, with ACME/autocert fallback.
- **[detect](internal/detect)** — the Detection Engine. Loads Nuclei templates
  and **inverts** their use: instead of actively probing a target, it extracts
  the *request signature* of a known exploit and matches inbound requests
  against it, blocking before the backend is touched. Custom rules are written
  as Nuclei templates with an added `session-matchers` block.
- **[session](internal/session)** — Session/Behavior Tracker backing the
  stateful `session-matchers` checks (seen-before, prior-pageviews, rate-limit).
- **[reputation](internal/reputation)** — IP Reputation Manager: in-memory
  O(1) lookups, BoltDB persistence, greylist/block state machine with TTLs.
- **[challenge](internal/challenge)** — interstitial JS/captcha verification and
  block pages, served from operator-editable assets in `/var/www/smoker`.
- **[logging](internal/logging)** — four structured JSON log streams; no
  dashboard or management API by design.

### Detection Engine: scanner → inline filter

Nuclei is an *active scanner*: it sends a probe and evaluates matchers on the
**response**. smoker never generates traffic to "test" the backend. The Template
Loader/Converter ([`loader.go`](internal/detect/loader.go),
[`signature.go`](internal/detect/signature.go)) instead:

1. Parses each template's `http:` block (`method`, `path`, `raw`, `body`,
   `headers`, request-side `matchers`).
2. Extracts one or more **signatures** and compiles them into efficient Go
   matchers (exact/prefix for static paths, precompiled `regexp` otherwise) —
   **all compilation happens at load/reload time**, never per request.
3. Keeps template metadata (CVE id, severity, target plugin/theme) to enrich
   `blocked.log`.

Pure CVE feeds have no `session-matchers` block, so they are treated as
stateless HTTP signatures with the default action (`block`). The template repo
(`templates.git`, default `codeberg.org/ostap-mykhaylyak/templates`) is
periodically **overlaid directly onto `/etc/smoker/templates/`** — repo files
overwrite same-named ones, local custom templates are kept — and recompiled hot,
with no proxy restart.

### Custom rules in extended Nuclei syntax

Custom behavioral rules are ordinary Nuclei templates plus a smoker extension:

```yaml
session-matchers:      # evaluated by the Session/Behavior Tracker
  condition: and
  checks:
    - type: session-seen-before
      negate: true
    - type: min-prior-pageviews
      value: 1
      negate: true
      window: 30m
action: log-only       # block | challenge | log-only | rate-limit | ban
action-response-code: 403
```

New behavioral templates default to `log-only` so an operator can measure how
many requests a rule *would* block (visible in `blocked.log`) before promoting
it to `block`. For a full, copy-pasteable spec to hand to an LLM when authoring
new rules, see [`docs/RULE_AUTHORING_PROMPT.md`](docs/RULE_AUTHORING_PROMPT.md).

**Actions:** `block` (403/`action-response-code`), `challenge` (interstitial
verification), `log-only` (observe, don't enforce), `rate-limit` (429), `ban`
(blacklist the client IP in reputation for `block_ttl` — every later request is
dropped fast).

**Challenge grace (no loops).** Once a session solves a challenge, the proxy
grants a grace period for that session's lifetime: `challenge` actions are
skipped for it, so a `challenge` rule matching normal navigation can never trap
a verified visitor in a challenge→pass→challenge loop (regardless of how the
rule is written). `block`/`ban`/`rate-limit` still enforce. The signed session
cookie is issued on the challenge page itself, so the session identity is stable
across the whole flow (it does not switch from an IP+UA fingerprint to a cookie
mid-visit, which would otherwise reset behavioral history). The challenge page
also carries a `<noscript>` fallback so it is not a dead end without JS.

**`session-matchers` check types** (evaluated by the Session/Behavior Tracker):
`session-seen-before`, `min-prior-pageviews` (value/window), `rate-limit`
(value/window, all endpoints for the session), `endpoint-rate-limit`
(value/window, counts only requests to *this* request's path — the per-endpoint
flood check), `challenge-passed`, `last-path-matches` (glob). Each supports
`negate: true`.

### Rule packs (external)

Detection rules are **not** bundled in the binary. The templates directory
(`/etc/smoker/templates/`) is created empty on first run and populated entirely
by the git-synced templates repo (`templates.git`, default
`codeberg.org/ostap-mykhaylyak/templates`) — curate all CVE feeds and custom
rules there, in the Nuclei-template format described above.

The guiding design rule when authoring rules: **`block` only for signatures that
never occur in legitimate traffic**; ship everything ambiguous (API access,
recon, behavioral) as `log-only`/`challenge` so you observe it in `blocked.log`
and promote after tuning. New behavioral templates default to `log-only`.

To generate new rules with an LLM, hand it the self-contained spec in
[`docs/RULE_AUTHORING_PROMPT.md`](docs/RULE_AUTHORING_PROMPT.md).

### Hot reload

Templates recompile without a restart: an fsnotify watch on
`/etc/smoker/templates/` (recursive) recompiles the signature set within a
moment of any add/edit/remove, in addition to the periodic git sync and the
config-reload trigger. Edit a rule's `action:` and it takes effect live.

### Static allow / deny lists

Whitelisted IPs (trusted integrations, monitoring, payment gateways, office
ranges) bypass reputation, detection and challenge and stream straight to the
backend. Blocklisted IPs are denied (403) before any inspection. Both accept
IPv4/IPv6 addresses and CIDRs, evaluated before everything else.

Each list is a **git repo mirrored into a directory**: every `*.ips` file under
`dir` (one IP/CIDR per line, `#` comments) is merged, plus any inline `ips`.

```yaml
whitelist:
  dir: "/etc/smoker/whitelist"           # repo mirrored here
  git: { url: "https://codeberg.org/ostap-mykhaylyak/whitelist", branch: "main" }
```

Each repo (defaults: `codeberg.org/ostap-mykhaylyak/{whitelist,blocklist}`) is
pulled on its **own** `sync_interval` — templates, whitelist and blocklist run
independently (e.g. `whitelist: 10m`, `blocklist: 30m`, `templates: 6h`) — and
overlaid onto its `dir`: repo files overwrite same-named ones, local hand-added
`.ips` files are kept. Non-`.ips` files (README, LICENSE) are ignored and invalid
lines are skipped (logged), never fatal. Set `git.url: ""` to disable syncing.
Manage entries by pushing to the repo, or drop a `.ips` file into the directory.

### Trusted proxies (real client IP behind a CDN)

By default smoker is the edge and ignores inbound `X-Forwarded-For` — the
connection source IP is the real client. When smoker instead runs **behind a CDN
or reverse proxy (e.g. Cloudflare)**, the connection source is the CDN, so the
real visitor IP must be read from a forwarding header. List the CDN's IP ranges
in the `trusted_proxies` directory (same `dir` / inline `ips` / `git` structure
as the access lists) and, only when the direct peer is one of them, smoker takes
the real client IP from **`CF-Connecting-IP`**, then the leftmost
**`X-Forwarded-For`**, then **`X-Real-IP`**. That recovered IP is what
reputation, the whitelist/blocklist and every log line use, so you track the
visitor and not the CDN.

```yaml
trusted_proxies:
  dir: "/etc/smoker/trusted-proxies"
  ips: ["173.245.48.0/20", "103.21.244.0/22", "2400:cb00::/32"]   # e.g. Cloudflare
  git: { url: "", branch: "main" }     # or mirror a published ranges repo
```

Because the header is trusted **only** when the direct connection comes from a
listed proxy, a client connecting directly cannot spoof its IP. With
`trusted_proxies` empty (default), behavior is unchanged. Drop Cloudflare's
published ranges into a `.ips` file (or point `git.url` at a repo mirroring
them, refreshed on `sync_interval`).

> **File names must end in `.ips`.** Only `*.ips` files under `dir` are read
> (so `README`/`LICENSE` in a synced repo are ignored). Cloudflare publishes its
> ranges as files named `ips-v4` and `ips-v6` — rename them (e.g.
> `cloudflare-v4.ips`, `cloudflare-v6.ips`) or they will be silently skipped.
> smoker logs the loaded counts at startup (`access lists loaded … trusted_proxies N`)
> and reloads the lists live when you add or edit a `.ips` file, so a count of
> `0` there means the files were not picked up — check the extension.

## Logs (`/var/log/smoker/`)

| File             | Contents                                                        |
|------------------|-----------------------------------------------------------------|
| `access.log`     | every request forwarded to the backend: **req_id**, ip, method, host, path, query, **status** (200/301/404/…), bytes, ua, duration |
| `blocked.log`    | every blocked/challenged request: **req_id**, ip, path/method, **status**, template-id, severity, action, reason |
| `backend.log`    | backend errors only: **req_id**, ip, method, host, path, **status** (5xx), reason, err — both backend `5xx` responses and unreachable/transport failures (502) |
| `reputation.log` | IP state transitions (clean ⇄ greylisted ⇄ blocked)             |
| `smoker.log`     | operational logs (startup, config/template reload, errors)      |

The `status` field makes scanner activity easy to spot — e.g. an IP generating a
burst of `404`s hunting for vulnerable plugins:

```sh
# top IPs by 404 count in access.log
jq -r 'select(.status==404) | .ip' /var/log/smoker/access.log | sort | uniq -c | sort -rn | head
```

Every request carries a **`req_id`** (also returned in the `X-Request-Id`
response header and printed on the block/challenge page, next to the visitor's
IP). When a user reports being blocked, ask for the request id shown on the page
and grep for it directly:

```sh
grep <req_id> /var/log/smoker/*.log        # or: jq 'select(.req_id=="<req_id>")'
```

Rotation is delegated to external `logrotate` (no rotation logic in the binary):
a policy is installed at `/etc/logrotate.d/smoker` (embedded, provisioned on
first run / `--init` / `make install`). It rotates `/var/log/smoker/*.log` daily
(keeps 14, compressed) and runs `systemctl reload smoker` in `postrotate`, which
sends `SIGHUP` so smoker reopens its files. `reputation.db` is left untouched.

## Build & install

```sh
go mod tidy            # fetch pinned deps, generate go.sum (needs network)
make static            # CGO_ENABLED=0 static linux/amd64 binary -> bin/smoker
sudo make install      # lays down /sbin/smoker, /etc/smoker, /var/log/smoker, /var/www/smoker
sudo systemctl daemon-reload && sudo systemctl enable --now smoker
```

### First run / self-provisioning

The default `config.yaml`, challenge assets **and the systemd unit** are
**embedded in the binary** (`internal/bootstrap`), so a bare host needs no extra
files. Detection templates are the exception — they are fetched at runtime from
the templates git repo, so the templates directory starts empty.

- `sudo ./smoker` — if `/etc/smoker/config.yaml` is missing, provisions the
  data layout (config, assets, empty templates dir, `/var/log/smoker`) and then
  runs in the foreground. Does **not** register a service.
- `sudo ./smoker --init` — full turnkey installer, then exits: provisions the
  data layout, copies the running binary to `/sbin/smoker`, and installs the
  systemd unit at `/etc/systemd/system/smoker.service`. Run this before
  `systemctl enable`:

```sh
sudo ./smoker --init
sudo systemctl daemon-reload
sudo systemctl enable --now smoker
```

Existing files are never overwritten (the binary is refreshed to match the one
you ran). Writing under `/etc` and `/var` needs root, so the first run must be
as root (`sudo`). For local testing against a writable prefix, point `--config`
elsewhere:

```sh
./smoker --config ./config.yaml   # writes the default config there on first run
```

The systemd unit ([`smoker.service`](internal/bootstrap/smoker.service)) runs with
`CAP_NET_ADMIN` (nftables) + `CAP_NET_BIND_SERVICE`, `ReadOnlyPaths=/etc/smoker`
and `ReadWritePaths=/var/log/smoker`. Because `/etc/smoker` is read-only for the
service, `smoker --init` (or `sudo make install`) must run **once** before
enabling the unit. `sudo make install` is the equivalent path when building from
source.

### Deployment modes: edge vs. redirect

smoker supports two topologies:

**Edge mode (recommended, simplest).** smoker binds the public `:80`/`:443`
directly and nginx moves to loopback. There is no nftables redirect and no
internal ports, so the firewall's existing 80/443 rules are all you need —
nothing extra to open. A ready-to-use edge config (with HTTP/3 + zstd) and a
step-by-step procedure are in
[`examples/config.edge.yaml`](examples/config.edge.yaml) and
[`examples/DEPLOY.md`](examples/DEPLOY.md).

```yaml
# /etc/smoker/config.yaml
listen:
  http:  "0.0.0.0:80"
  https: "0.0.0.0:443"
backend:
  http:  "127.0.0.1:80"    # nginx, loopback only
  https: "127.0.0.1:443"
  use_tls: true            # nginx serves the sites over TLS on 443
firewall:
  enabled: false           # no DNAT redirect in edge mode
```

Move nginx off the public ports (in every vhost) and reload it *before* starting
smoker, so the public ports are free to bind:

```nginx
listen 127.0.0.1:80;
listen 127.0.0.1:443 ssl;
```

```sh
sudo nginx -t && sudo systemctl reload nginx   # nginx now on loopback
sudo systemctl restart smoker                  # smoker takes public 80/443
```

smoker routes per inbound listener: plaintext `:80` → nginx `:80` (so nginx's own
`http→https` redirect is preserved), TLS `:443` → nginx `:443`. It needs
`CAP_NET_BIND_SERVICE` (the unit has it); `CAP_NET_ADMIN` is unnecessary here and
can be dropped. Note: in edge mode smoker is a hard dependency for the sites — if
it stops, the public ports have no listener, so rely on the unit's
`Restart=on-failure`.

**Redirect mode** (nftables DNAT of 80/443 to internal 18080/18443) is the
alternative when you cannot move nginx; it requires the firewall note below.

### Host firewall (redirect mode)

nftables DNAT rewrites the destination port of inbound traffic **before** it
reaches the `INPUT`/filter stage: a request to `:443` arrives at the filter with
dport **18443**. If a host firewall (ufw/firewalld/iptables) only allows 80/443,
the redirected packet is dropped and clients see a **connection timeout**. Allow
the internal ports:

```sh
sudo ufw allow 18080/tcp && sudo ufw allow 18443/tcp
# or nftables:  nft add rule inet filter input tcp dport { 18080, 18443 } accept
```

If **HTTP/3** is enabled (`listen.http3: true`), QUIC is redirected from public
`443/udp` to the internal `18443/udp`, so that UDP port must be allowed too:

```sh
sudo ufw allow 18443/udp
```

(Also open public `443/udp` at the provider/cloud firewall.) Opening these does
not bypass the WAF — those ports *are* smoker. Keep the public 80/443 open as
usual; the redirect steers them to smoker.

### Fail-open and the backend listener

`firewall.fail_open` removes the DNAT redirect if smoker stops, so traffic falls
through to the backend directly. For that to keep **HTTPS** working, the backend
web server must still listen on the public `:443` (e.g. nginx `listen 443 ssl;`
on `0.0.0.0`), not only on `127.0.0.1:443`. With the redirect active, external
`:443` is intercepted by smoker anyway and forwarded to `127.0.0.1:443`; if
smoker dies, the redirect is dropped and clients reach nginx's public `:443`
directly. If nginx binds only loopback on 443, fail-open covers plaintext `:80`
but not HTTPS.

## Performance: HTTP/3 and compression

Both are opt-in in `config.yaml`:

- **HTTP/3 (QUIC)** — `listen.http3: true` starts a QUIC/UDP listener on the
  HTTPS address (via `quic-go`) and advertises it with `Alt-Svc` on the TCP
  responses, so browsers upgrade automatically. TLS 1.3 only; 0-RTT is
  **disabled on purpose** (early-data is replayable — unsafe past a WAF). Open
  the same **UDP** port in the firewall (edge mode).
- **zstd** — `compression.zstd: true` compresses uncompressed, compressible
  backend responses (`text/*`, JSON, JS, SVG, …) for clients that send
  `Accept-Encoding: zstd`, streamed (never fully buffered), skipping bodies
  under `compression.min_size`.

The signed session cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` when the
client connection is HTTPS.

**Post-quantum key exchange.** smoker requires **Go 1.24+** (see `go.mod`) so the
TLS 1.3 server offers the hybrid `X25519MLKEM768` group by default (Go's default
`CurvePreferences`), negotiating PQC key exchange with capable clients — no
configuration needed. Building with an older Go only offers classical ECDH.

## Test

```sh
make test              # go test ./... -race
```

Covered: template parsing/compilation and inline matching, the behavioral
`block-cold-add-to-cart` rule end-to-end (cold vs. warm session), the reputation
state machine + BoltDB persistence, the access lists and trusted-proxy real-IP
recovery, and an end-to-end proxy test (clean passthrough, SQLi block,
blocked-IP fail-fast, greylist→challenge, request-id header/page, backend 5xx +
unreachable logging to `backend.log`, real client IP behind a trusted CDN).

## Non-goals

No SSH/FTP/mail handling (HTTP/HTTPS only); no management dashboard or API (logs
are the only interface); no offensive scanning; no exfiltration of collected
data without explicit configured consent.

## Note on the Nuclei dependency

This skeleton implements a self-contained parser for the relevant subset of the
Nuclei HTTP template schema (`internal/detect`) rather than importing the full
`github.com/projectdiscovery/nuclei/v3` module. The template files stay valid
Nuclei YAML — the trade-off is a small, static, dependency-light binary vs. the
large transitive dependency tree of the upstream engine. Swapping in the
upstream `pkg/templates` parser is localized to `template.go`/`loader.go`.
