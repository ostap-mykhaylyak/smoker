package protect

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ostap-mykhaylyak/smoker/internal/detect"
)

func TestRateGovernorTrips(t *testing.T) {
	g, err := New(16)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return base } // frozen clock: no refill

	opt := Options{Rate: RateOptions{
		Enabled: true, Window: time.Minute, Burst: 3, SensitiveWeight: 1,
		Action: detect.ActionRateLimit, RespCode: 429,
	}}
	r := httptest.NewRequest("GET", "http://x/page", nil)

	for i := 0; i < 3; i++ {
		if _, ok := g.Assess(r, "1.2.3.4", opt); ok {
			t.Fatalf("request %d within burst should be allowed", i)
		}
	}
	dec, ok := g.Assess(r, "1.2.3.4", opt)
	if !ok {
		t.Fatal("4th request over burst must trip the governor")
	}
	if dec.Action != detect.ActionRateLimit || dec.RespCode != 429 {
		t.Errorf("verdict = %q/%d, want rate-limit/429", dec.Action, dec.RespCode)
	}
	// A different IP has its own budget.
	if _, ok := g.Assess(r, "9.9.9.9", opt); ok {
		t.Error("a fresh IP must not be throttled")
	}
}

func TestRateGovernorSensitiveWeight(t *testing.T) {
	g, _ := New(16)
	base := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return base }
	opt := Options{Rate: RateOptions{
		Enabled: true, Window: time.Minute, Burst: 40, SensitiveWeight: 20,
		SensitivePaths: []string{"/xmlrpc.php"}, Action: detect.ActionRateLimit, RespCode: 429,
	}}
	r := httptest.NewRequest("POST", "http://x/xmlrpc.php", nil)

	// Cost 20 each: 2 allowed, 3rd tripped.
	for i := 0; i < 2; i++ {
		if _, ok := g.Assess(r, "1.2.3.4", opt); ok {
			t.Fatalf("sensitive request %d should be allowed", i)
		}
	}
	if _, ok := g.Assess(r, "1.2.3.4", opt); !ok {
		t.Fatal("3rd sensitive request should trip the weighted budget")
	}
}

func TestRateGovernorRefills(t *testing.T) {
	g, _ := New(16)
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	opt := Options{Rate: RateOptions{Enabled: true, Window: time.Minute, Burst: 2, SensitiveWeight: 1, Action: detect.ActionRateLimit}}
	r := httptest.NewRequest("GET", "http://x/", nil)

	g.Assess(r, "1.1.1.1", opt)
	g.Assess(r, "1.1.1.1", opt)
	if _, ok := g.Assess(r, "1.1.1.1", opt); !ok {
		t.Fatal("bucket should be empty after burst")
	}
	// Advance a full window: the bucket refills to capacity.
	now = now.Add(time.Minute)
	if _, ok := g.Assess(r, "1.1.1.1", opt); ok {
		t.Error("after a full-window refill a request should be allowed again")
	}
}

func TestAnomalyScoring(t *testing.T) {
	acc := "*/*"
	lang := "en"

	// Benign browser: no signals.
	r := httptest.NewRequest("GET", "http://x/shop/product", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "en-US")
	if s, why := anomalyScore(r); s != 0 {
		t.Errorf("benign browser scored %d (%s), want 0", s, why)
	}

	// Offensive tool UA alone reaches the default threshold.
	r = httptest.NewRequest("GET", "http://x/", nil)
	r.Header.Set("User-Agent", "sqlmap/1.7.2")
	r.Header.Set("Accept", acc)
	r.Header.Set("Accept-Language", lang)
	if s, _ := anomalyScore(r); s < 100 {
		t.Errorf("offensive UA scored %d, want >= 100", s)
	}

	// Abusive method alone reaches the threshold.
	r = httptest.NewRequest("TRACE", "http://x/", nil)
	if s, _ := anomalyScore(r); s < 100 {
		t.Errorf("TRACE scored %d, want >= 100", s)
	}

	// Scanner path + empty UA + missing browser headers combine over threshold.
	r = httptest.NewRequest("GET", "http://x/.git/config", nil)
	if s, _ := anomalyScore(r); s < 100 {
		t.Errorf("scanner probe scored %d, want >= 100", s)
	}
}
