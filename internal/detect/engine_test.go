package detect

import "testing"

const sqliTemplate = `
id: wp-example-sqli
info:
  name: Example SQLi
  author: test
  severity: critical
  tags: wordpress,sqli
  classification:
    cve-id: CVE-2023-99999
http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-admin/admin-ajax.php?action=example_export&order_by={{payload}}"
    matchers-condition: and
    matchers:
      - type: regex
        part: request
        regex:
          - "(?i)union\\s+select"
`

func mustCompile(t *testing.T, yaml string) *CompiledSignature {
	t.Helper()
	tmpl, err := ParseTemplate([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sig, err := Compile(tmpl)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return sig
}

const nestedBehavioral = `
id: nested-behavioral
info:
  severity: medium
http:
  - method: POST
    path:
      - "{{BaseURL}}/x"
    session-matchers:
      condition: and
      checks:
        - type: session-seen-before
          negate: true
    action: log-only
    action-response-code: 403
`

// session-matchers/action authored nested under the http entry (as in the
// spec's example) must be promoted to the template level.
func TestNestedEnforcementPromoted(t *testing.T) {
	tmpl, err := ParseTemplate([]byte(nestedBehavioral))
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.SessionMatchers == nil || len(tmpl.SessionMatchers.Checks) != 1 {
		t.Fatal("nested session-matchers was not promoted to template level")
	}
	if tmpl.EffectiveAction() != ActionLogOnly {
		t.Errorf("action = %q, want log-only", tmpl.EffectiveAction())
	}
	if tmpl.ResponseCode() != 403 {
		t.Errorf("response code = %d, want 403", tmpl.ResponseCode())
	}
}

func TestParseTemplateMetadata(t *testing.T) {
	tmpl, err := ParseTemplate([]byte(sqliTemplate))
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.ID != "wp-example-sqli" {
		t.Errorf("id = %q", tmpl.ID)
	}
	if tmpl.Info.Severity != SevCritical {
		t.Errorf("severity = %q", tmpl.Info.Severity)
	}
	if got := tmpl.Info.Classification.CVEID; len(got) != 1 || got[0] != "CVE-2023-99999" {
		t.Errorf("cve = %v", got)
	}
	// A pure CVE template (no session-matchers, no explicit action) defaults to
	// block.
	if tmpl.EffectiveAction() != ActionBlock {
		t.Errorf("effective action = %q, want block", tmpl.EffectiveAction())
	}
}

func TestEngineBlocksSQLi(t *testing.T) {
	e := NewEngine(nil)
	e.Reload([]*CompiledSignature{mustCompile(t, sqliTemplate)})

	view := &RequestView{
		Method:  "GET",
		Path:    "/wp-admin/admin-ajax.php",
		FullURI: "/wp-admin/admin-ajax.php?action=example_export&order_by=1 union select pass from users",
		Headers: map[string]string{},
	}
	dec := e.Inspect(view, "")
	if !dec.Matched {
		t.Fatal("expected SQLi to be blocked")
	}
	if dec.Action != ActionBlock || dec.RespCode != 403 {
		t.Errorf("action=%q code=%d", dec.Action, dec.RespCode)
	}
	if dec.Incident == nil || dec.Incident.TemplateID != "wp-example-sqli" {
		t.Errorf("incident = %+v", dec.Incident)
	}
}

func TestEnginePassesBenign(t *testing.T) {
	e := NewEngine(nil)
	e.Reload([]*CompiledSignature{mustCompile(t, sqliTemplate)})

	view := &RequestView{
		Method:  "GET",
		Path:    "/wp-admin/admin-ajax.php",
		FullURI: "/wp-admin/admin-ajax.php?action=example_export&order_by=name",
		Headers: map[string]string{},
	}
	if e.Inspect(view, "").Matched {
		t.Fatal("benign request must not match")
	}
}

const obsTemplate = `
id: obs-x
info:
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
action: log-only
`

const blockTemplate = `
id: block-x
info:
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
action: block
`

// A weak log-only rule must never shadow a block rule for the same request,
// regardless of load order.
func TestStrongestActionWins(t *testing.T) {
	obs := mustCompile(t, obsTemplate)
	blk := mustCompile(t, blockTemplate)
	view := &RequestView{Method: "GET", Path: "/x", FullURI: "/x", Headers: map[string]string{}}

	for name, order := range map[string][]*CompiledSignature{
		"obs-first":   {obs, blk},
		"block-first": {blk, obs},
	} {
		e := NewEngine(nil)
		e.Reload(order)
		dec := e.Inspect(view, "")
		if !dec.Matched || dec.Action != ActionBlock {
			t.Fatalf("%s: got matched=%v action=%q, want block", name, dec.Matched, dec.Action)
		}
		if dec.Incident.TemplateID != "block-x" {
			t.Errorf("%s: incident = %q, want block-x", name, dec.Incident.TemplateID)
		}
	}
}

// fakeEvaluator lets us test the session-matchers routing without the tracker.
type fakeEvaluator struct{ fire bool }

func (f fakeEvaluator) Evaluate(_ *SessionMatchers, _ string, _ *RequestView) bool {
	return f.fire
}

const behavioralTemplate = `
id: cold-cart
info:
  name: Cold add to cart
  severity: medium
http:
  - method: POST
    path:
      - "{{BaseURL}}/cart/add"
session-matchers:
  condition: and
  checks:
    - type: session-seen-before
      negate: true
action: log-only
`

func TestSessionMatchersGate(t *testing.T) {
	sig := mustCompile(t, behavioralTemplate)
	view := &RequestView{Method: "POST", Path: "/cart/add", FullURI: "/cart/add", Headers: map[string]string{}}

	// Evaluator returns false -> behavioral condition not met -> no match even
	// though the HTTP signature matches.
	eNo := NewEngine(fakeEvaluator{fire: false})
	eNo.Reload([]*CompiledSignature{sig})
	if eNo.Inspect(view, "sid:x").Matched {
		t.Error("should not match when session condition is false")
	}

	// Evaluator returns true -> match, action log-only.
	eYes := NewEngine(fakeEvaluator{fire: true})
	eYes.Reload([]*CompiledSignature{sig})
	dec := eYes.Inspect(view, "sid:x")
	if !dec.Matched || dec.Action != ActionLogOnly {
		t.Errorf("expected log-only match, got matched=%v action=%q", dec.Matched, dec.Action)
	}
}
