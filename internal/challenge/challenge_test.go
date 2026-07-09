package challenge

import (
	"crypto/sha256"
	"strconv"
	"testing"
)

func TestVerifyPoW(t *testing.T) {
	const bits = 12
	token := "exp.mac"

	// Solve the PoW the way the browser would.
	var nonce int
	for {
		sum := sha256.Sum256([]byte(token + ":" + strconv.Itoa(nonce)))
		if leadingZeroBits(sum[:]) >= bits {
			break
		}
		nonce++
	}
	if !verifyPoW(token, strconv.Itoa(nonce), bits) {
		t.Fatal("a correctly solved PoW must verify")
	}
	// Wrong/absent nonce must fail; bits<=0 disables the check.
	if verifyPoW(token, "0", bits) && nonce != 0 {
		t.Error("an unsolved nonce must not verify")
	}
	if !verifyPoW(token, "", 0) {
		t.Error("pow_bits=0 must disable the check")
	}
	if verifyPoW(token, "", bits) {
		t.Error("empty nonce must not verify when bits>0")
	}
}

func TestSafeReturnBlocksOpenRedirect(t *testing.T) {
	cases := map[string]string{
		"/dashboard":        "/dashboard",
		"/a/b?c=d":          "/a/b?c=d",
		"":                  "/",
		"//evil.com":        "/", // protocol-relative
		"/\\evil.com":       "/", // backslash variant
		"https://evil.com":  "/", // absolute
		"javascript:alert1": "/", // not path-rooted
		"/":                 "/",
	}
	for in, want := range cases {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}
