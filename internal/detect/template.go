// Package detect implements the Nuclei-template-based Detection Engine.
//
// Design inversion vs. Nuclei: Nuclei is an ACTIVE scanner — it sends a probe
// request to a target and evaluates matchers against the RESPONSE. smoker never
// generates traffic toward the backend to "test" anything. Instead it extracts
// the *request signature* of a known exploit already encoded in the template
// (path, method, raw request, body, headers, request-side matchers) and uses it
// to recognize incoming real-world requests that match a known attack pattern,
// blocking them before they reach the backend.
//
// The template YAML remains valid Nuclei: CVE feeds like nuclei-wordfence-cve
// parse via the standard fields, and smoker's enforcement-only extensions
// (`session-matchers`, `action`, `action-response-code`) are optional additions
// that pure CVE templates simply omit.
package detect

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Severity mirrors Nuclei info.severity values.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Action is smoker's enforcement decision (not native to Nuclei).
type Action string

const (
	// ActionBlock returns ActionResponseCode (default 403) immediately.
	ActionBlock Action = "block"
	// ActionChallenge serves the interstitial challenge/captcha page.
	ActionChallenge Action = "challenge"
	// ActionLogOnly records what WOULD have been blocked; used for tuning and
	// is the safe default for new custom behavioral templates.
	ActionLogOnly Action = "log-only"
	// ActionRateLimit throttles the offending key instead of hard-blocking.
	ActionRateLimit Action = "rate-limit"
	// ActionBan blacklists the client IP outright (reputation -> blocked for
	// block_ttl), so every subsequent request from it is dropped fast. Use for
	// rules that already embody a threshold (e.g. an endpoint flood).
	ActionBan Action = "ban"
)

// Template is the parsed on-disk representation of a Nuclei template plus
// smoker's enforcement extensions. It is unmarshalled directly from YAML; the
// standard blocks (id, info, http) coexist with the extended blocks so the same
// file is parsable by both Nuclei and smoker.
type Template struct {
	ID   string `yaml:"id"`
	Info Info   `yaml:"info"`
	HTTP []HTTP `yaml:"http"`

	// --- smoker enforcement extensions (optional; absent in pure CVE feeds) ---

	// SessionMatchers, when present, routes the template to the Session/Behavior
	// Tracker in addition to the stateless HTTP match.
	SessionMatchers *SessionMatchers `yaml:"session-matchers"`
	// Action overrides the default enforcement action for the template.
	Action Action `yaml:"action"`
	// ActionResponseCode is the status code for ActionBlock (default 403).
	ActionResponseCode int `yaml:"action-response-code"`

	// SourcePath records where the template was loaded from (for logs).
	SourcePath string `yaml:"-"`
}

// Info holds Nuclei metadata used to enrich incidents/logs.
type Info struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    Severity `yaml:"severity"`
	Description string   `yaml:"description"`
	Tags        Strings  `yaml:"tags"`
	// Classification carries CVE ids etc. when present.
	Classification struct {
		CVEID     Strings `yaml:"cve-id"`
		CWEID     Strings `yaml:"cwe-id"`
		CVSSScore float64 `yaml:"cvss-score"`
	} `yaml:"classification"`
}

// HTTP is a single Nuclei http request block (subset relevant to signatures).
type HTTP struct {
	Method  string            `yaml:"method"`
	Path    Strings           `yaml:"path"`
	Raw     []string          `yaml:"raw"`
	Body    string            `yaml:"body"`
	Headers map[string]string `yaml:"headers"`

	MatchersCondition string    `yaml:"matchers-condition"` // "and" | "or"
	Matchers          []Matcher `yaml:"matchers"`

	// Enforcement extensions may also be authored nested under the http entry
	// (as in the spec's example); ParseTemplate promotes them to the template
	// level so both indentation styles work.
	SessionMatchers    *SessionMatchers `yaml:"session-matchers"`
	Action             Action           `yaml:"action"`
	ActionResponseCode int              `yaml:"action-response-code"`
}

// Matcher is a Nuclei matcher restricted to request-side evaluation. smoker
// evaluates matchers against the INCOMING request (path/query/header/body),
// never against a backend response.
type Matcher struct {
	Type      string  `yaml:"type"` // word | regex | status(ignored) | dsl(subset)
	Part      string  `yaml:"part"` // request | path | header | body | all
	Words     Strings `yaml:"words"`
	Regex     Strings `yaml:"regex"`
	Condition string  `yaml:"condition"` // "and" | "or" (within a matcher)
	Negative  bool    `yaml:"negative"`
	// CaseInsensitive applies to `word` matchers.
	CaseInsensitive bool `yaml:"case-insensitive"`
}

// SessionMatchers is smoker's stateful extension, evaluated by the
// Session/Behavior Tracker. Absent block == "no behavioral condition".
type SessionMatchers struct {
	Condition string         `yaml:"condition"` // "and" | "or"
	Checks    []SessionCheck `yaml:"checks"`
}

// SessionCheck is one behavioral predicate.
type SessionCheck struct {
	// Type: session-seen-before | min-prior-pageviews | rate-limit |
	//       challenge-passed | last-path-matches
	Type   string   `yaml:"type"`
	Negate bool     `yaml:"negate"`
	Value  int      `yaml:"value"`
	Window Duration `yaml:"window"`
	// Match is an optional argument (e.g. path regex for last-path-matches).
	Match string `yaml:"match"`
}

// Duration is a yaml wrapper mirroring config.Duration but local to avoid an
// import cycle between detect and config.
type Duration = yamlDuration

// EffectiveAction returns the action to apply, defaulting to block for pure
// CVE templates (no explicit action) and log-only for templates that declare a
// session-matchers block but no explicit action (safe default for behavioral).
func (t *Template) EffectiveAction() Action {
	if t.Action != "" {
		return t.Action
	}
	if t.SessionMatchers != nil {
		return ActionLogOnly
	}
	return ActionBlock
}

// ResponseCode returns the configured block status, defaulting to 403.
func (t *Template) ResponseCode() int {
	if t.ActionResponseCode != 0 {
		return t.ActionResponseCode
	}
	return 403
}

// ParseTemplate unmarshals a single YAML document into a Template.
func ParseTemplate(data []byte) (*Template, error) {
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("unmarshal template: %w", err)
	}
	if t.ID == "" {
		return nil, fmt.Errorf("template missing required 'id'")
	}
	// Promote enforcement extensions authored nested under an http entry to the
	// template level (tolerant of both indentation styles).
	for i := range t.HTTP {
		if t.SessionMatchers == nil && t.HTTP[i].SessionMatchers != nil {
			t.SessionMatchers = t.HTTP[i].SessionMatchers
		}
		if t.Action == "" && t.HTTP[i].Action != "" {
			t.Action = t.HTTP[i].Action
		}
		if t.ActionResponseCode == 0 && t.HTTP[i].ActionResponseCode != 0 {
			t.ActionResponseCode = t.HTTP[i].ActionResponseCode
		}
	}
	return &t, nil
}

// Strings accepts either a single scalar or a YAML list, matching Nuclei's
// tolerant schema (e.g. tags can be "a,b" or [a, b]).
type Strings []string

func (s *Strings) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var single string
		if err := node.Decode(&single); err != nil {
			return err
		}
		*s = splitCSV(single)
	case yaml.SequenceNode:
		var list []string
		if err := node.Decode(&list); err != nil {
			return err
		}
		*s = list
	default:
		return fmt.Errorf("unsupported node kind for Strings: %d", node.Kind)
	}
	return nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{}
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, trimSpace(cur))
			cur = ""
			continue
		}
		cur += string(r)
	}
	out = append(out, trimSpace(cur))
	return out
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
