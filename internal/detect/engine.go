package detect

import (
	"strings"
	"sync/atomic"
)

// Incident is published when a request matches an exploit/behavioral signature.
// It carries enough metadata to enrich blocked.log and drive reputation.
type Incident struct {
	TemplateID string
	Severity   Severity
	CVE        []string
	Tags       []string
	Action     Action
	RespCode   int
	Source     string
	Reason     string
}

// Decision is the outcome of inspecting a request.
type Decision struct {
	Matched  bool
	Action   Action
	RespCode int
	Incident *Incident
}

// SessionEvaluator is implemented by the Session/Behavior Tracker. Evaluate
// reports whether the stateful condition in sm holds for the given session key
// and request — i.e. whether the behavioral attack pattern is present.
type SessionEvaluator interface {
	Evaluate(sm *SessionMatchers, sessionKey string, view *RequestView) bool
}

// Engine is the unified Detection Engine interface (mockable in tests).
type Engine interface {
	// Inspect evaluates a request against all active signatures in one pass and
	// returns the first matching decision. sessionKey identifies the client
	// session for templates that carry session-matchers.
	Inspect(view *RequestView, sessionKey string) Decision
	// Reload atomically swaps the active signature set (hot template reload).
	Reload(sigs []*CompiledSignature)
	// Count returns the number of active signatures.
	Count() int
}

// engine is the default Engine. The signature slice is swapped atomically so
// Inspect is lock-free on the hot path.
type engine struct {
	sigs    atomic.Pointer[[]*CompiledSignature]
	session SessionEvaluator
}

// NewEngine builds an Engine. session may be nil if behavioral rules are unused
// (session-matchers templates then never fire their stateful condition).
func NewEngine(session SessionEvaluator) Engine {
	e := &engine{session: session}
	empty := []*CompiledSignature{}
	e.sigs.Store(&empty)
	return e
}

func (e *engine) Reload(sigs []*CompiledSignature) {
	cp := sigs
	e.sigs.Store(&cp)
}

func (e *engine) Count() int {
	return len(*e.sigs.Load())
}

func (e *engine) Inspect(view *RequestView, sessionKey string) Decision {
	sigs := *e.sigs.Load()
	var best *CompiledSignature
	bestRank := 0
	for _, sig := range sigs {
		if !e.httpMatch(sig, view) {
			continue
		}
		// Behavioral extension: if present, the stateful condition must also
		// hold. Absent block == pure HTTP signature, act immediately.
		if sig.Session != nil {
			if e.session == nil || !e.session.Evaluate(sig.Session, sessionKey, view) {
				continue
			}
		}
		// Multiple rules can match one request; enforce the STRONGEST action so
		// a weak log-only/observe rule can never shadow a block/ban rule.
		if r := actionRank(sig.Action); r > bestRank {
			bestRank, best = r, sig
			if r == maxActionRank {
				break // nothing can beat a ban; stop early
			}
		}
	}
	if best == nil {
		return Decision{Matched: false}
	}
	return Decision{
		Matched:  true,
		Action:   best.Action,
		RespCode: best.RespCode,
		Incident: &Incident{
			TemplateID: best.TemplateID,
			Severity:   best.Severity,
			CVE:        best.CVE,
			Tags:       best.Tags,
			Action:     best.Action,
			RespCode:   best.RespCode,
			Source:     best.Source,
			Reason:     reasonFor(best),
		},
	}
}

// actionRank orders actions by enforcement strength (higher = stronger).
const maxActionRank = 5

func actionRank(a Action) int {
	switch a {
	case ActionBan:
		return maxActionRank
	case ActionBlock:
		return 4
	case ActionChallenge:
		return 3
	case ActionRateLimit:
		return 2
	case ActionLogOnly:
		return 1
	default:
		return 1
	}
}

func reasonFor(sig *CompiledSignature) string {
	if len(sig.CVE) > 0 {
		return "matched " + sig.TemplateID + " (" + strings.Join(sig.CVE, ",") + ")"
	}
	return "matched " + sig.TemplateID
}

// httpMatch returns true if any http block of the signature matches the request.
func (e *engine) httpMatch(sig *CompiledSignature, view *RequestView) bool {
	for i := range sig.blocks {
		if matchBlock(&sig.blocks[i], view) {
			return true
		}
	}
	return false
}

func matchBlock(b *compiledBlock, view *RequestView) bool {
	if len(b.methods) > 0 && !b.methods[strings.ToUpper(view.Method)] {
		return false
	}
	if len(b.paths) > 0 {
		hit := false
		for i := range b.paths {
			if matchPath(&b.paths[i], view) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(b.matchers) == 0 {
		return true
	}
	if b.matchersAnd {
		for i := range b.matchers {
			if !matchMatcher(&b.matchers[i], view) {
				return false
			}
		}
		return true
	}
	// OR
	for i := range b.matchers {
		if matchMatcher(&b.matchers[i], view) {
			return true
		}
	}
	return false
}

func matchPath(p *pathMatcher, view *RequestView) bool {
	// Test both the raw and the normalized target so evasions like
	// //wp-config.php, /./wp-config.php or /wp-config.php/ are caught.
	if p.matchQuery {
		return matchTarget(p, view.FullURI) ||
			(view.FullURINorm != "" && view.FullURINorm != view.FullURI && matchTarget(p, view.FullURINorm))
	}
	return matchTarget(p, view.Path) ||
		(view.PathNorm != "" && view.PathNorm != view.Path && matchTarget(p, view.PathNorm))
}

func matchTarget(p *pathMatcher, target string) bool {
	switch {
	case p.exact != "":
		return target == p.exact
	case p.prefix != "":
		return strings.HasPrefix(target, p.prefix)
	case p.re != nil:
		return p.re.MatchString(target)
	}
	return false
}

func matchMatcher(m *compiledMatcher, view *RequestView) bool {
	hay := partValue(m.part, view)
	if m.caseFold {
		hay = strings.ToLower(hay)
	}
	res := evalMatcher(m, hay)
	if m.negative {
		return !res
	}
	return res
}

func evalMatcher(m *compiledMatcher, hay string) bool {
	// words
	wordsOK := len(m.words) == 0
	if len(m.words) > 0 {
		if m.condAnd {
			wordsOK = true
			for _, w := range m.words {
				if !strings.Contains(hay, w) {
					wordsOK = false
					break
				}
			}
		} else {
			for _, w := range m.words {
				if strings.Contains(hay, w) {
					wordsOK = true
					break
				}
			}
		}
	}
	// regex
	reOK := len(m.res) == 0
	if len(m.res) > 0 {
		if m.condAnd {
			reOK = true
			for _, re := range m.res {
				if !re.MatchString(hay) {
					reOK = false
					break
				}
			}
		} else {
			for _, re := range m.res {
				if re.MatchString(hay) {
					reOK = true
					break
				}
			}
		}
	}
	return wordsOK && reOK
}

func partValue(part string, view *RequestView) string {
	switch part {
	case "path":
		return view.FullURI
	case "body":
		return string(view.Body)
	case "header":
		return headersString(view.Headers)
	case "all", "request", "":
		var b strings.Builder
		b.WriteString(view.Method)
		b.WriteByte(' ')
		b.WriteString(view.FullURI)
		b.WriteByte('\n')
		b.WriteString(headersString(view.Headers))
		b.WriteByte('\n')
		b.Write(view.Body)
		return b.String()
	default:
		// treat unknown parts as a named header
		if v, ok := view.Headers[part]; ok {
			return v
		}
		return ""
	}
}

func headersString(h map[string]string) string {
	var b strings.Builder
	for k, v := range h {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return b.String()
}
