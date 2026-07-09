package proxy

import "testing"

func TestSignedSIDRoundtrip(t *testing.T) {
	secret := []byte("a-sufficiently-long-test-secret")

	v := newSignedSID(secret)
	if v == "" {
		t.Fatal("newSignedSID returned empty")
	}
	id, ok := verifySID(secret, v)
	if !ok || id == "" {
		t.Fatalf("valid signed sid failed to verify: %q", v)
	}
}

// A forged or rotated cookie must NOT verify, so the caller falls back to keying
// on the connection IP (which a client cannot rotate) — closing the behavioral
// rate-limit evasion.
func TestSignedSIDRejectsForgery(t *testing.T) {
	secret := []byte("a-sufficiently-long-test-secret")
	v := newSignedSID(secret)

	forged := []string{
		"randomattackervalue",   // no separator
		"abc.def",               // bad mac
		"abc.",                  // empty mac
		".def",                  // empty id
		v + "x",                 // tampered mac
	}
	for _, f := range forged {
		if _, ok := verifySID(secret, f); ok {
			t.Errorf("forged cookie %q must not verify", f)
		}
	}
	// Correct value but wrong secret must also fail.
	if _, ok := verifySID([]byte("different-secret-value"), v); ok {
		t.Error("cookie signed with a different secret must not verify")
	}
}
