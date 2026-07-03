package session

import (
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/smoker/internal/detect"
)

// The shipped block-cold-add-to-cart rule, verified end-to-end through the real
// engine + tracker.
const coldCartTemplate = `
id: block-cold-add-to-cart
info:
  name: Block add-to-cart without prior browsing session
  severity: medium
  tags: custom,behavioral,woocommerce
http:
  - method: POST
    path:
      - "{{BaseURL}}/?wc-ajax=add_to_cart"
      - "{{BaseURL}}/cart/add"
    matchers-condition: and
    matchers:
      - type: word
        part: request
        words:
          - "POST"
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
`

func newEngine(t *testing.T, tr Tracker) detect.Engine {
	t.Helper()
	tmpl, err := detect.ParseTemplate([]byte(coldCartTemplate))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := detect.Compile(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	e := detect.NewEngine(tr)
	e.Reload([]*detect.CompiledSignature{sig})
	return e
}

func addToCartView() *detect.RequestView {
	return &detect.RequestView{
		Method:  "POST",
		Path:    "/cart/add",
		FullURI: "/cart/add",
		Headers: map[string]string{},
	}
}

func TestColdAddToCartFires(t *testing.T) {
	tr, err := New(1000, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(t, tr)

	// First-ever request from this session is a POST add-to-cart: no prior
	// browsing -> behavioral rule fires.
	dec := e.Inspect(addToCartView(), "sid:new-visitor")
	if !dec.Matched {
		t.Fatal("cold add-to-cart should match the behavioral rule")
	}
	if dec.Action != detect.ActionLogOnly {
		t.Errorf("action = %q, want log-only", dec.Action)
	}
}

func TestWarmAddToCartPasses(t *testing.T) {
	tr, err := New(1000, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(t, tr)
	key := "sid:real-shopper"

	// Simulate genuine prior browsing: a product page view is recorded.
	tr.Record(key, &detect.RequestView{Method: "GET", Path: "/product/widget", FullURI: "/product/widget"})

	dec := e.Inspect(addToCartView(), key)
	if dec.Matched {
		t.Fatal("add-to-cart after prior browsing must NOT match")
	}
}

func TestRateLimitCheck(t *testing.T) {
	tr, err := New(1000, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	concrete := tr.(*tracker)
	base := time.Unix(1_700_000_000, 0)
	concrete.now = func() time.Time { return base }

	key := "sid:spammer"
	view := addToCartView()
	for i := 0; i < 3; i++ {
		tr.Record(key, view)
	}

	sm := &detect.SessionMatchers{
		Condition: "and",
		Checks: []detect.SessionCheck{
			{Type: "rate-limit", Value: 2, Window: mustDur(t, "1m")},
		},
	}
	if !tr.Evaluate(sm, key, view) {
		t.Error("3 requests within window should exceed rate-limit value=2")
	}
}

func TestEndpointRateLimitIsolatesPath(t *testing.T) {
	tr, err := New(1000, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	concrete := tr.(*tracker)
	base := time.Unix(1_700_000_000, 0)
	concrete.now = func() time.Time { return base }

	key := "fp:bot"
	ajax := &detect.RequestView{Method: "POST", Path: "/wp-admin/admin-ajax.php", FullURI: "/wp-admin/admin-ajax.php"}
	other := &detect.RequestView{Method: "GET", Path: "/shop", FullURI: "/shop"}

	// 4 prior admin-ajax hits, plus lots of noise to a different endpoint.
	for i := 0; i < 4; i++ {
		tr.Record(key, ajax)
	}
	for i := 0; i < 20; i++ {
		tr.Record(key, other)
	}

	fireAt := func(v int) *detect.SessionMatchers {
		return &detect.SessionMatchers{Condition: "and", Checks: []detect.SessionCheck{
			{Type: "endpoint-rate-limit", Value: v, Window: mustDur(t, "15m")},
		}}
	}

	// 4 prior + current = 5 admin-ajax hits -> fires at value 5.
	if !tr.Evaluate(fireAt(5), key, ajax) {
		t.Fatal("5th admin-ajax hit should fire endpoint-rate-limit")
	}
	// The 20 hits to /shop must NOT count toward admin-ajax: value 6 must not fire.
	if tr.Evaluate(fireAt(6), key, ajax) {
		t.Fatal("other-endpoint hits must not leak into admin-ajax count")
	}
}

func mustDur(t *testing.T, s string) detect.Duration {
	t.Helper()
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatal(err)
	}
	return detect.Duration(d)
}
