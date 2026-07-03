package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestAccessListFromDir(t *testing.T) {
	dir := t.TempDir()
	wlDir := filepath.Join(dir, "wl")
	if err := os.MkdirAll(wlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A .ips file is read; a non-.ips file (README) must be ignored, not parsed.
	if err := os.WriteFile(filepath.Join(wlDir, "trusted.ips"),
		[]byte("# header\n203.0.113.5\n10.0.0.0/8   # trailing comment\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wlDir, "README.md"), []byte("this is not an ip\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML := fmt.Sprintf("listen:\n  http: \"127.0.0.1:0\"\nbackend:\n  http: \"127.0.0.1:80\"\nwhitelist:\n  dir: %q\nblocklist:\n  dir: \"\"\n", wlDir)
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Whitelisted("203.0.113.5") || !c.Whitelisted("10.9.9.9") {
		t.Error("entries from the .ips file were not applied")
	}
	if c.Whitelisted("203.0.113.6") {
		t.Error("unexpected whitelist match")
	}
	if len(c.AccessListWarnings()) != 0 {
		t.Errorf("non-.ips files must be ignored; got warnings %v", c.AccessListWarnings())
	}
}

func TestAccessLists(t *testing.T) {
	c := Default()
	c.Whitelist.IPs = []string{"203.0.113.5", "10.0.0.0/8", "2001:db8::/32"}
	c.Blocklist.IPs = []string{"198.51.100.7", "192.0.2.0/24"}
	if err := c.compileAccessLists(); err != nil {
		t.Fatalf("compile: %v", err)
	}

	whitelisted := []string{"203.0.113.5", "10.1.2.3", "10.255.255.255", "2001:db8::1"}
	for _, ip := range whitelisted {
		if !c.Whitelisted(ip) {
			t.Errorf("%s should be whitelisted", ip)
		}
	}
	notWhitelisted := []string{"203.0.113.6", "11.0.0.1", "2001:dead::1"}
	for _, ip := range notWhitelisted {
		if c.Whitelisted(ip) {
			t.Errorf("%s should NOT be whitelisted", ip)
		}
	}

	if !c.Blocklisted("198.51.100.7") || !c.Blocklisted("192.0.2.42") {
		t.Error("expected blocklist matches")
	}
	if c.Blocklisted("192.0.3.1") {
		t.Error("192.0.3.1 should not be blocklisted")
	}
}

func TestAccessListInvalidEntryIsLenient(t *testing.T) {
	// A stray line (e.g. in a synced repo) must be skipped, not fatal.
	c := Default()
	c.Whitelist.IPs = []string{"not-an-ip", "203.0.113.5"}
	if err := c.compileAccessLists(); err != nil {
		t.Fatalf("compile must be lenient: %v", err)
	}
	if !c.Whitelisted("203.0.113.5") {
		t.Error("valid entry alongside an invalid one should still apply")
	}
	if len(c.AccessListWarnings()) != 1 {
		t.Errorf("expected 1 skipped-entry warning, got %v", c.AccessListWarnings())
	}
}

func TestEmptyAccessListsAllowAll(t *testing.T) {
	c := Default()
	if err := c.compileAccessLists(); err != nil {
		t.Fatal(err)
	}
	if c.Whitelisted("203.0.113.1") || c.Blocklisted("203.0.113.1") {
		t.Error("empty lists must not match any IP")
	}
}
