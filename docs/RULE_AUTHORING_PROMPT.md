# smoker rule-authoring prompt

Hand the block below to an LLM (verbatim) whenever you want it to generate a new
smoker detection rule. It is a **self-contained specification** of the exact
subset of the Nuclei template schema that smoker's parser understands, plus
smoker's own enforcement extensions. It is written against smoker's real parser
(`internal/detect`), so following it produces rules that load and match
correctly.

Append your concrete request at the end (e.g. *"Write a rule that blocks
`/wp-content/debug.log` access"*).

---

## PROMPT — copy from here

You are authoring a detection rule for **smoker**, a reverse-proxy WAF. smoker
does **not** scan targets: it takes the *request signature* of an attack and
matches it against **inbound** requests, blocking them before they reach the
backend. Your rule therefore describes the shape of a malicious **request**,
never a server response.

Output **one valid YAML document** and nothing else (no prose, no code fences).
It is saved as a single `.yaml` file. The file is a standard Nuclei HTTP
template restricted to the request side, plus smoker's optional enforcement
fields.

### Hard rules (the parser enforces these)

- `id` is **required** and must be unique, lowercase-kebab-case, descriptive
  (e.g. `wp-xmlrpc-abuse`, `generic-path-traversal`).
- Matching is evaluated only against the **incoming request**. Do **not** use
  response-side matchers: `type: status`, `type: dsl`, and any `part` referring
  to a response are ignored. Only `type: word` and `type: regex` are honored.
- Regex is **Go RE2**: no backreferences, no lookahead/lookbehind. Use the
  inline flag `(?i)` for case-insensitivity in regex. Any invalid regex makes
  smoker **skip the whole template**, so keep patterns valid and anchored.
- smoker inspects **URL-decoded** text (the query is percent-decoded and the
  path is normalized: collapsed `//`, resolved `/./` and `/../`, trimmed
  trailing `/`). Write signatures against **decoded** content; you do not need
  to also match `%2e%2e` if you match `..`, but matching common encodings as
  alternatives is still good defense.
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
    path:                            # optional; list; a request matches if ANY path matches
      - "{{BaseURL}}/wp-login.php"
    matchers-condition: and | or     # how the matchers below combine (default: or)
    matchers:
      - type: word | regex
        part: request | path | body | header | all | <Header-Name>
        words:                       # for type: word
          - "..."
        regex:                       # for type: regex
          - "(?i)..."
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

`session-matchers`, `action` and `action-response-code` may also be authored
nested under an `http:` entry; smoker promotes them to the top level, so either
indentation works. Prefer top-level for clarity.

### How `path` is compiled

- The leading `{{BaseURL}}`, `{{RootURL}}` or `{{Hostname}}` (or a full
  `scheme://host`) is stripped — smoker matches **path-relative**.
- A fully static path (no `{{...}}`, no regex metacharacters) becomes an
  **exact** match: `"{{BaseURL}}/wp-login.php"` matches the path
  `/wp-login.php` exactly (and its normalized form).
- A path containing `{{...}}` becomes an **anchored regex** with each `{{...}}`
  turned into `.*`. Example: `"{{BaseURL}}/user/{{id}}/edit"` →
  `^/user/.*/edit$`.
- If the path string contains `?`, the pattern is matched against the full
  decoded URI (`path?query`); otherwise only against the path.

### Matcher `part` values (what the haystack is)

- `path` → the full request URI: decoded `path?query`.
- `body` → the request body (bounded to 1 MiB).
- `header` → all headers joined as `Name: value\n`.
- `all` / `request` / *(empty)* → `METHOD URI\n` + headers + `\n` + body.
- Any other value → the named request header (canonical form, e.g.
  `User-Agent`, `Content-Type`, `Referer`). Empty string if absent.

Within one matcher: all `words` combine per `condition` (and/or), all `regex`
combine per `condition`, and the two groups are AND'd together. Across matchers
in a block: `matchers-condition` (and/or).

### Enforcement actions

- `block` — return `action-response-code` (default 403) and register a
  reputation violation. Use **only** for signatures that never occur in
  legitimate traffic.
- `challenge` — serve the interstitial JS/PoW challenge; the client can prove
  it is a browser and continue. Good for ambiguous-but-suspicious traffic.
- `log-only` — pass the request through and only record what *would* have been
  blocked (`blocked.log`). The safe default for new/behavioral rules; measure
  first, promote later. This is the implicit default when `session-matchers` is
  present and no `action` is given.
- `rate-limit` — return 429 with `Retry-After` and register a violation.
- `ban` — immediately blocklist the client IP for `block_ttl` (every later
  request is dropped fast). Reserve for rules that already embody a threshold
  (e.g. an endpoint flood).
- A pure CVE template with no `action` and no `session-matchers` defaults to
  `block`. When several rules match one request, the **strongest** action wins.

### `session-matchers` check types (behavioral / stateful)

Evaluated by the Session/Behavior Tracker; a behavioral rule fires only when the
HTTP signature matches **and** the session condition holds. Each check supports
`negate: true`.

- `session-seen-before` — the client session has been seen before. Negate for
  "brand-new session".
- `challenge-passed` — the session has solved a challenge.
- `min-prior-pageviews` — prior recorded pageviews within `window` ≥ `value`.
- `rate-limit` — total requests by the session within `window` > `value`
  (all endpoints).
- `endpoint-rate-limit` — requests to **this** request's path within `window`
  (optionally overridden by an exact `match:` path), including the current one,
  reaching `value`. The per-endpoint flood check.
- `last-path-matches` — the session's previous path matches the `match:` glob
  (supports leading/trailing `*`, e.g. `/wp-admin/*`).

`window` is a duration string: `"30s"`, `"10m"`, `"24h"`.

### Design guidance

- Prefer precise, high-confidence signatures. Anchor regex to keyword
  combinations that do not appear in normal input (e.g. `union[\s/*]+select`,
  not a bare `select`).
- Default new rules to `log-only` (or `challenge`), and say in `description`
  why the pattern is safe from false positives before recommending `block`.
- Set `severity` honestly; it only enriches logs, it does not change
  enforcement.
- Keep behavioral thresholds conservative to avoid tripping real users.

### Worked examples

Stateless CVE-style block:

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
action-response-code: 403
```

Behavioral, log-only:

```yaml
id: wc-cold-add-to-cart
info:
  name: Add-to-cart without prior browsing (bot behavior)
  author: internal
  severity: medium
  tags: woocommerce,behavioral,bot
  description: |
    POST to add-to-cart from a session never seen before AND with no prior
    pageview in the window — a bot skipping straight to the cart. log-only
    because a real shopper landing on a product permalink can also trip it.
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
action-response-code: 403
```

Now write the rule for the following request pattern:

<DESCRIBE THE ATTACK / REQUEST TO BLOCK HERE>

## PROMPT — end
