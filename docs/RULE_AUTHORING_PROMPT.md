# smoker rule-authoring guide & prompt

This document is both a **human reference** and a **copy-paste prompt for an LLM**
that generates smoker detection rules. It is written against smoker's real parser
(`internal/detect`) and behavioral tracker (`internal/session`), so following it
produces rules that load and match correctly.

- To author by hand: read the whole thing.
- To generate with an LLM: paste the block between the `PROMPT — copy from here`
  and `PROMPT — end` markers, then append your concrete request.

---

## First: do you even need a rule?

smoker already protects every site with two **rule-free** layers. Prefer them —
fewer hand-written rules means less to maintain and fewer false positives.

1. **Proactive protection** (`protection` in config, on by default when enabled):
   - a **per-IP flood governor** that throttles volumetric abuse (weighting
     sensitive endpoints like `/xmlrpc.php`, `/wp-login.php`);
   - **anomaly scoring** that challenges offensive tool User-Agents, scanner
     paths, traversal/injection markers and abusive methods.
   So you usually do **not** need a rule for: generic floods, scanner tools,
   `/.env` `/.git` probing, `TRACE`/`CONNECT`, obvious traversal/injection shapes.

2. **Access lists & reputation**: whitelist trusted integrations; blocklist known
   bad IPs; repeated violations auto-escalate to greylist → block.

**Write a rule when** you need something specific those layers don't express:
a signature for a concrete CVE/exploit request, a site policy ("at most 1
xmlrpc/hour"), or a behavioral pattern tied to your app (add-to-cart without
browsing, coupon brute-force). Rules and proactive protection stack — the
strongest action wins.

---

## PROMPT — copy from here

You are authoring a detection rule for **smoker**, a reverse-proxy WAF. smoker
does not scan targets: it takes the *request signature* of an attack and matches
it against **inbound** requests, blocking them before they reach the backend.
Your rule therefore describes the shape of a malicious **request**, never a
server response.

Output **one valid YAML document** and nothing else (no prose, no code fences).
It is saved as a single `.yaml` file — a standard Nuclei HTTP template restricted
to the request side, plus smoker's optional enforcement fields.

### Hard rules (the parser enforces these)

- `id` is **required**, unique, lowercase-kebab-case, descriptive.
- Matching is only against the **incoming request**. Response-side matchers
  (`type: status`, `type: dsl`) are ignored; only `type: word` and `type: regex`
  are honored.
- Regex is **Go RE2**: no backreferences, no lookahead/lookbehind. Use inline
  `(?i)` for case-insensitivity in regex. Invalid regex makes smoker **skip the
  whole template**, so keep patterns valid and anchored.
- smoker inspects **URL-decoded, path-normalized** text: the query is
  percent-decoded, and the path has `//` collapsed, `/./` and `/../` resolved,
  and a trailing `/` trimmed — matched against both the raw and normalized form.
  Write signatures against **decoded** content; you need not also encode evasions.
- One template = one YAML document = one file.

### Schema

```yaml
id: <unique-kebab-case-id>            # REQUIRED
info:
  name: <short human name>
  author: <you or "internal">
  severity: info | low | medium | high | critical
  description: |
    What this catches and WHY it does not fire on legitimate traffic.
  tags: <comma list or YAML list, e.g. wordpress,sqli>
  classification:                    # optional; include for CVE rules
    cve-id: CVE-2021-44228
    cwe-id: CWE-89
    cvss-score: 9.8

http:                                # one or more request blocks; blocks are OR'd
  - method: GET                      # optional; if set, must match (case-insensitive)
    path:                            # optional; list; matches if ANY path matches
      - "{{BaseURL}}/wp-login.php"
    matchers-condition: and | or     # combine the matchers below (default: or)
    matchers:
      - type: word | regex
        part: request | path | body | header | all | <Header-Name>
        words: ["..."]               # for type: word
        regex: ["(?i)..."]           # for type: regex
        condition: and | or          # combine words/regex WITHIN this matcher (default: or)
        case-insensitive: true       # for `words` only (regex uses (?i))
        negative: true               # invert this matcher

# --- smoker enforcement extensions (optional; omit for pure CVE feeds) ---
session-matchers:                    # stateful/behavioral condition (see below)
  condition: and | or
  checks:
    - type: <check-type>
      negate: true
      value: <int>
      window: "30m"
      match: "<arg>"
action: block | challenge | log-only | rate-limit | ban
action-response-code: 403            # status for `block` (default 403)
```

`session-matchers`, `action` and `action-response-code` may also be nested under
an `http:` entry; smoker promotes them to the top level, so either style works.

### How `path` is compiled

- A leading `{{BaseURL}}`, `{{RootURL}}`, `{{Hostname}}` (or `scheme://host`) is
  stripped — smoker matches **path-relative**.
- A fully static path (no `{{...}}`, no regex metacharacters) → **exact** match.
- A path containing `{{...}}` → an **anchored regex** with each `{{...}}` → `.*`
  (e.g. `"{{BaseURL}}/user/{{id}}/edit"` → `^/user/.*/edit$`).
- If the path string contains `?`, it is matched against the full decoded URI
  (`path?query`); otherwise only against the path.

### Matcher `part` values (what the haystack is)

- `path` → the full request URI: decoded `path?query`.
- `body` → the request body (bounded to 1 MiB for inspection).
- `header` → all headers joined as `Name: value\n`.
- `all` / `request` / *(empty)* → `METHOD URI\n` + headers + `\n` + body.
- Any other value → the named request header (canonical form, e.g. `User-Agent`,
  `Content-Type`, `Referer`, `Authorization`).

Within one matcher: all `words` combine per `condition`, all `regex` combine per
`condition`, and the two groups are AND'd. Across matchers: `matchers-condition`.

### Enforcement actions (and when to use each)

- `block` — 403 (or `action-response-code`) + a reputation violation. Use **only**
  for signatures that never occur in legitimate traffic (exploit payloads, known
  CVE probes, webshell uploads).
- `challenge` — interstitial JS/PoW; real browsers pass, headless bots do not.
  Good for ambiguous-but-suspicious browser traffic (login flooding, checkout
  abuse). Do **not** use for server-to-server endpoints (APIs, xmlrpc, webhooks)
  whose legitimate callers cannot solve a challenge — use `rate-limit` there.
- `log-only` — pass through, record what *would* have matched (`blocked.log`).
  The safe default for anything new or behavioral: measure first, promote later.
  It is the implicit default when `session-matchers` is present and no `action`.
- `rate-limit` — 429 + `Retry-After` + a violation. Right for headless callers you
  want to throttle without a challenge.
- `ban` — blocklist the client IP for `block_ttl` (every later request drops
  fast). Reserve for rules that already embody a threshold (an endpoint flood) or
  unmistakable attack payloads you want to hard-stop.
- A pure signature template with no `action` and no `session-matchers` defaults to
  `block`. When several rules match, the **strongest** action wins.

### `session-matchers` check types (behavioral / stateful)

Evaluated by the Session/Behavior Tracker. A behavioral rule fires only when the
HTTP signature matches **and** the session condition holds. Each check supports
`negate: true`. The tracker keys a request on its **session cookie** if present,
otherwise on the **client IP** (stable across User-Agent/cookie rotation — a
cookieless bot cannot spawn fresh sessions to evade these limits).

- `session-seen-before` — the session was seen before. Negate for "brand new".
- `challenge-passed` — the session solved a challenge.
- `min-prior-pageviews` — prior recorded pageviews within `window` ≥ `value`.
- `rate-limit` — total requests by the session within `window` > `value`
  (all endpoints).
- `endpoint-rate-limit` — requests to **this** request's path (or the exact
  `match:` path) within `window`, counting the current one, reaching `value`.
  The per-endpoint flood check. `value: 2` = allow 1, throttle from the 2nd.
- `last-path-matches` — the previous path matches the `match:` glob (leading /
  trailing `*`, e.g. `/wp-admin/*`).

`window` is a duration string: `"30s"`, `"10m"`, `"24h"`. Empty condition = `and`.

### Design guidance

- Prefer precise, high-confidence signatures. Anchor regex to keyword
  **combinations** that never appear in normal input (e.g. `union[\s/*]+select`,
  not a bare `select`).
- Default new/behavioral rules to `log-only` (or `challenge`); state in
  `description` why the pattern is false-positive-safe before recommending
  `block`/`ban`.
- Do not re-implement what the proactive layer already does generically (floods,
  scanner UAs, `/.env` probing) — write rules for the *specific* case that layer
  cannot express.
- Set `severity` honestly (it enriches logs only). Keep behavioral thresholds
  conservative to avoid tripping real users.

### Worked examples (a library across situations)

Generic path traversal / LFI (block):

```yaml
id: generic-path-traversal
info:
  name: Path traversal / local file inclusion
  author: internal
  severity: high
  tags: generic,lfi,traversal
http:
  - matchers-condition: or
    matchers:
      - type: regex
        part: path
        regex:
          - '(?i)(\.\./|\.\.\\){2,}'
          - '(?i)/(etc/passwd|etc/shadow|proc/self/environ|windows/win\.ini)'
          - '(?i)(php|file|data|phar|expect|zip)://'
action: block
```

Generic SQL injection (block):

```yaml
id: generic-sql-injection
info:
  name: SQL injection signatures
  author: internal
  severity: critical
  tags: generic,sqli
http:
  - matchers-condition: or
    matchers:
      - type: regex
        part: request
        regex:
          - '(?i)union[\s/*]+(all[\s/*]+)?select[\s/*]'
          - '(?i)(select|and|or)[\s(]+.{0,40}(sleep\(|benchmark\(|pg_sleep\(|waitfor\s+delay)'
          - '(?i)(information_schema|group_concat\(|load_file\(|into\s+(out|dump)file)'
          - '(?i);[\s]*(drop|alter|truncate)[\s]+table[\s]'
action: block
```

Log4Shell / JNDI (block, CVE):

```yaml
id: generic-log4shell
info:
  name: Log4Shell JNDI lookup (CVE-2021-44228)
  author: internal
  severity: critical
  tags: generic,rce,log4j
  classification:
    cve-id: CVE-2021-44228
http:
  - matchers-condition: or
    matchers:
      - type: regex
        part: all
        regex:
          - '(?i)\$\{jndi:(ldaps?|rmi|dns|iiop|corba|nis|nds):'
          - '(?i)\$\{[^}]*\$\{(lower|upper|env|sys):'
action: block
```

WordPress sensitive files (block):

```yaml
id: wp-sensitive-files
info:
  name: WordPress sensitive file access
  author: internal
  severity: high
  tags: wordpress,disclosure
http:
  - method: GET
    matchers-condition: or
    matchers:
      - type: regex
        part: path
        regex:
          - '(?i)/wp-config\.php(\.(bak|old|save|orig|txt|swp)|~)?$'
          - '(?i)/(\.wp-config\.php\.swp|wp-config-sample\.php\.bak)$'
          - '(?i)/wp-content/(debug\.log|uploads/.*\.(php[3-7]?|phtml))$'
action: block
```

WordPress login brute-force (behavioral, challenge — browsers only):

```yaml
id: wp-login-bruteforce
info:
  name: wp-login.php flooding
  author: internal
  severity: medium
  tags: wordpress,bruteforce,behavioral
  description: |
    Many POSTs to wp-login.php from one session in a short window. challenge, so
    a real user is briefly verified while a headless brute-forcer is stopped.
http:
  - method: POST
    path:
      - "{{BaseURL}}/wp-login.php"
session-matchers:
  checks:
    - type: endpoint-rate-limit
      value: 6
      window: 5m
action: challenge
```

xmlrpc.php policy (behavioral, rate-limit — headless server-to-server):

```yaml
id: wp-xmlrpc-rate-limit
info:
  name: Throttle xmlrpc.php floods
  author: internal
  severity: medium
  tags: wordpress,xmlrpc,rate-limit
  description: |
    xmlrpc is headless server-to-server, so identity is the IP (which smoker's
    tracker uses for cookieless clients). rate-limit (429), not challenge, since
    legitimate Jetpack/pingback cannot solve a challenge. Allows a few calls per
    window; sustained abuse is throttled and the window self-heals.
http:
  - path:
      - "{{BaseURL}}/xmlrpc.php"
session-matchers:
  checks:
    - type: endpoint-rate-limit
      value: 4
      window: 1h
action: rate-limit
action-response-code: 429
```

WooCommerce cold add-to-cart (behavioral, log-only to start):

```yaml
id: wc-cold-add-to-cart
info:
  name: Add-to-cart without prior browsing (bot behavior)
  author: internal
  severity: medium
  tags: woocommerce,behavioral,bot
  description: |
    POST to add-to-cart from a session never seen before AND with no prior
    pageview — a bot skipping straight to the cart. log-only, because a shopper
    landing on a product permalink can also trip it; observe before promoting.
http:
  - method: POST
    path:
      - "{{BaseURL}}/?wc-ajax=add_to_cart"
      - "{{BaseURL}}/cart/"
session-matchers:
  condition: and
  checks:
    - type: session-seen-before
      negate: true
    - type: min-prior-pageviews
      value: 1
      negate: true
      window: 30m
action: log-only
```

WooCommerce coupon brute-force (behavioral, challenge):

```yaml
id: wc-coupon-bruteforce
info:
  name: Coupon guessing
  author: internal
  severity: medium
  tags: woocommerce,behavioral,bruteforce
http:
  - method: POST
    path:
      - "{{BaseURL}}/?wc-ajax=apply_coupon"
session-matchers:
  checks:
    - type: endpoint-rate-limit
      value: 10
      window: 10m
action: challenge
```

Scanner User-Agent (block) — only if the proactive anomaly layer is off:

```yaml
id: generic-scanner-tools
info:
  name: Offensive scanner User-Agents
  author: internal
  severity: high
  tags: generic,scanner
http:
  - matchers:
      - type: word
        part: User-Agent
        case-insensitive: true
        words: ["sqlmap", "nikto", "nessus", "acunetix", "nuclei", "wpscan", "masscan", "gobuster"]
action: block
```

### Checklist before shipping a rule

- [ ] Unique `id`; `info.severity` and `tags` set.
- [ ] `description` explains why it won't hit legitimate traffic.
- [ ] Matching only on the request; regex is valid RE2 with `(?i)` where needed.
- [ ] Signature anchored to unambiguous patterns (no bare single keywords).
- [ ] Action fits the caller: `challenge` for browsers, `rate-limit`/`block` for
      headless; new/behavioral rules start `log-only`.
- [ ] It expresses something the proactive layer can't already do generically.

Now write the rule for the following:

<DESCRIBE THE ATTACK / REQUEST / POLICY HERE>

## PROMPT — end
