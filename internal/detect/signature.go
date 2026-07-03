package detect

import (
	"path"
	"regexp"
	"strings"
)

// RequestView is the read-only slice of an incoming request the matcher engine
// evaluates. It is populated once per request (path is caller-normalized, body
// is bounded) and reused across all signatures to avoid re-parsing in the hot
// path.
type RequestView struct {
	Method   string
	Path     string            // decoded path, no query
	PathNorm string            // normalized path (collapsed //, resolved ./..)
	RawQuery string            // raw query string
	FullURI  string            // path + "?" + decoded query
	FullURINorm string         // PathNorm + "?" + decoded query
	Headers  map[string]string // canonicalized keys, joined values
	Body     []byte            // bounded copy of request body
}

// NormalizePath canonicalizes a request path to defeat common WAF evasions:
// duplicate slashes (//wp-config.php), dot segments (/./x, /a/../wp-config.php)
// and trailing slashes (/wp-config.php/). It never decodes encoding — the caller
// passes an already-decoded path.
func NormalizePath(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean(p)
	if c == "." {
		return "/"
	}
	return c
}

// CompiledSignature is a single template compiled into fast matchers. All regex
// compilation happens at load/reload time — never per request.
type CompiledSignature struct {
	TemplateID string
	Severity   Severity
	CVE        []string
	Tags       []string
	Action     Action
	RespCode   int
	Session    *SessionMatchers
	Source     string

	blocks []compiledBlock
}

type compiledBlock struct {
	methods  map[string]bool // empty == any method
	paths    []pathMatcher
	matchers []compiledMatcher
	// condition: true == AND (all matchers must hit), false == OR (any).
	matchersAnd bool
}

type pathMatcher struct {
	// exact/prefix fast paths avoid regexp when the template path is static.
	exact  string
	prefix string
	re     *regexp.Regexp
	// matchQuery indicates the pattern includes a query string to test.
	matchQuery bool
}

type compiledMatcher struct {
	part      string // request | path | header | body | all
	words     []string
	res       []*regexp.Regexp
	condAnd   bool // within-matcher AND across words/regex
	negative  bool
	caseFold  bool
}

// Compile turns a parsed Template into a CompiledSignature. Errors are returned
// for invalid regex so a bad template is skipped rather than crashing the load.
func Compile(t *Template) (*CompiledSignature, error) {
	cs := &CompiledSignature{
		TemplateID: t.ID,
		Severity:   t.Info.Severity,
		CVE:        t.Info.Classification.CVEID,
		Tags:       t.Info.Tags,
		Action:     t.EffectiveAction(),
		RespCode:   t.ResponseCode(),
		Session:    t.SessionMatchers,
		Source:     t.SourcePath,
	}
	for _, h := range t.HTTP {
		cb := compiledBlock{
			methods:     map[string]bool{},
			matchersAnd: strings.EqualFold(h.MatchersCondition, "and"),
		}
		if h.Method != "" {
			cb.methods[strings.ToUpper(h.Method)] = true
		}
		for _, p := range h.Path {
			pm, err := compilePath(p)
			if err != nil {
				return nil, err
			}
			cb.paths = append(cb.paths, pm)
		}
		// Raw requests: extract the request line path as an additional matcher.
		for _, raw := range h.Raw {
			if m, p, ok := parseRawRequestLine(raw); ok {
				if m != "" {
					cb.methods[strings.ToUpper(m)] = true
				}
				pm, err := compilePath(p)
				if err == nil {
					cb.paths = append(cb.paths, pm)
				}
			}
		}
		for _, m := range h.Matchers {
			cm, err := compileMatcher(m)
			if err != nil {
				return nil, err
			}
			cb.matchers = append(cb.matchers, cm)
		}
		cs.blocks = append(cs.blocks, cb)
	}
	return cs, nil
}

// compilePath converts a Nuclei path template into a matcher. It strips the
// {{BaseURL}} / {{RootURL}} prefix (smoker matches path-relative), then:
//   - if fully static -> exact match (fast)
//   - if it ends in a wildcard var -> prefix match
//   - otherwise -> anchored regexp with {{...}} placeholders as .*
func compilePath(p string) (pathMatcher, error) {
	rel := stripBaseURL(p)
	q := strings.IndexByte(rel, '?')
	matchQuery := q >= 0

	if !strings.Contains(rel, "{{") && !hasRegexMeta(rel) {
		return pathMatcher{exact: rel, matchQuery: matchQuery}, nil
	}
	// Build a regexp: escape literals, turn {{...}} into .*
	var b strings.Builder
	b.WriteString("^")
	i := 0
	for i < len(rel) {
		if strings.HasPrefix(rel[i:], "{{") {
			end := strings.Index(rel[i:], "}}")
			if end < 0 {
				b.WriteString(regexp.QuoteMeta(rel[i:]))
				break
			}
			b.WriteString(".*")
			i += end + 2
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(rel[i])))
		i++
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return pathMatcher{}, err
	}
	return pathMatcher{re: re, matchQuery: matchQuery}, nil
}

func stripBaseURL(p string) string {
	for _, v := range []string{"{{BaseURL}}", "{{RootURL}}", "{{Hostname}}"} {
		if strings.HasPrefix(p, v) {
			return p[len(v):]
		}
	}
	// Also handle absolute URLs by trimming scheme://host.
	if i := strings.Index(p, "://"); i >= 0 {
		rest := p[i+3:]
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			return rest[slash:]
		}
		return "/"
	}
	return p
}

func hasRegexMeta(s string) bool {
	return strings.ContainsAny(s, "[](){}.*+?^$|\\")
}

func compileMatcher(m Matcher) (compiledMatcher, error) {
	cm := compiledMatcher{
		part:     defaultPart(m.Part),
		condAnd:  strings.EqualFold(m.Condition, "and"),
		negative: m.Negative,
		caseFold: m.CaseInsensitive,
	}
	for _, w := range m.Words {
		if m.CaseInsensitive {
			w = strings.ToLower(w)
		}
		cm.words = append(cm.words, w)
	}
	for _, r := range m.Regex {
		re, err := regexp.Compile(r)
		if err != nil {
			return compiledMatcher{}, err
		}
		cm.res = append(cm.res, re)
	}
	return cm, nil
}

func defaultPart(p string) string {
	if p == "" {
		return "request"
	}
	return strings.ToLower(p)
}

// parseRawRequestLine extracts METHOD and PATH from the first line of a Nuclei
// raw request block (e.g. "POST /wp-admin/admin-ajax.php HTTP/1.1").
func parseRawRequestLine(raw string) (method, path string, ok bool) {
	raw = strings.TrimLeft(raw, "\r\n \t")
	nl := strings.IndexAny(raw, "\r\n")
	if nl >= 0 {
		raw = raw[:nl]
	}
	parts := strings.Fields(raw)
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
