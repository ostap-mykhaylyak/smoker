// Package bootstrap makes smoker self-provisioning: the default configuration
// and challenge assets are embedded in the binary, so a fresh host with no
// /etc/smoker can be initialized on first run.
//
// The embedded tree under skel/ mirrors the real filesystem layout:
//
//	skel/etc/smoker/config.yaml         -> /etc/smoker/config.yaml
//	skel/var/www/smoker/*.html          -> /var/www/smoker/*.html
//
// Detection templates are deliberately NOT bundled: the templates directory is
// created empty and populated at runtime from the git-synced templates repo
// (see templates.git in config.yaml). Ensure never overwrites existing files,
// so it is safe to run repeatedly and to fill in only what is missing.
package bootstrap

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ostap-mykhaylyak/smoker/internal/paths"
)

//go:embed all:skel
var skel embed.FS

//go:embed smoker.service
var unitFile []byte

// SystemdUnitPath is where the service unit is installed.
const SystemdUnitPath = "/etc/systemd/system/smoker.service"

// Report summarizes what Install performed.
type Report struct {
	Files       []string // data files created by Ensure
	Binary      string   // path the binary was installed to ("" if unchanged)
	Unit        string   // unit file path
	UnitWritten bool     // whether the unit file was newly written
}

// Ensure creates the standard directory layout and writes any missing default
// files. cfgPath receives the default config (use paths.ConfigFile for the
// standard location; a different value redirects only the config file, e.g. for
// local testing). It returns the list of files it created.
//
// Writing under /etc and /var requires root; on a server the first run is
// expected to be `sudo smoker` (or `sudo smoker --init`).
func Ensure(cfgPath string) ([]string, error) {
	if cfgPath == "" {
		cfgPath = paths.ConfigFile
	}
	var created []string

	// Base directories with their intended permissions.
	dirs := []struct {
		path string
		mode os.FileMode
	}{
		{paths.ConfigDir, 0o755},
		{paths.TemplatesDir, 0o755},
		{paths.WhitelistDir, 0o755}, // git-synced access-list repos
		{paths.BlocklistDir, 0o755},
		{paths.TrustedProxiesDir, 0o755}, // trusted front-proxy IPs (e.g. Cloudflare)
		{paths.LogDir, 0o750}, // runtime state + logs (writable at runtime)
		{paths.AssetsDir, 0o755},
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return created, fmt.Errorf("mkdir %s: %w", d.path, err)
		}
	}

	// Materialize each embedded file at its real location (skip existing).
	err := fs.WalkDir(skel, "skel", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(p, "skel/") // e.g. etc/smoker/config.yaml
		target := "/" + rel                   // e.g. /etc/smoker/config.yaml
		if rel == "etc/smoker/config.yaml" {
			target = cfgPath
		}
		if _, statErr := os.Stat(target); statErr == nil {
			return nil // never overwrite an operator's file
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		data, err := skel.ReadFile(p)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if strings.HasSuffix(target, "config.yaml") {
			mode = 0o640 // config may hold the challenge secret
		}
		if err := os.WriteFile(target, data, mode); err != nil {
			return err
		}
		created = append(created, target)
		return nil
	})
	return created, err
}

// NeedsInit reports whether the config file is absent (first run).
func NeedsInit(cfgPath string) bool {
	_, err := os.Stat(cfgPath)
	return os.IsNotExist(err)
}

// Install performs a full turnkey install: provisions the data layout (Ensure),
// copies the running binary to /sbin/smoker, and writes the systemd unit. It is
// what `smoker --init` runs. Requires root. Existing files are not overwritten,
// except the binary which is refreshed to match the one being run.
func Install(cfgPath string) (Report, error) {
	var r Report
	created, err := Ensure(cfgPath)
	if err != nil {
		return r, err
	}
	r.Files = created

	bin, err := installBinary()
	if err != nil {
		return r, fmt.Errorf("install binary to %s: %w", paths.Binary, err)
	}
	r.Binary = bin

	u, wrote, err := writeUnit()
	if err != nil {
		return r, fmt.Errorf("install unit: %w", err)
	}
	r.Unit = u
	r.UnitWritten = wrote
	return r, nil
}

// installBinary copies the currently running executable to /sbin/smoker so the
// unit's ExecStart is valid. Returns the destination, or "" if already in place.
func installBinary() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	dst := paths.Binary
	if self == dst {
		return "", nil // already running from the install location
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	// Write to a temp file then rename over the target: replacing a running
	// binary is safe on Linux (the old inode stays open for the live process).
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return dst, nil
}

// writeUnit installs the embedded systemd unit if not already present.
func writeUnit() (string, bool, error) {
	if _, err := os.Stat(SystemdUnitPath); err == nil {
		return SystemdUnitPath, false, nil // never clobber operator edits
	}
	if err := os.MkdirAll(filepath.Dir(SystemdUnitPath), 0o755); err != nil {
		return SystemdUnitPath, false, err
	}
	if err := os.WriteFile(SystemdUnitPath, unitFile, 0o644); err != nil {
		return SystemdUnitPath, false, err
	}
	return SystemdUnitPath, true, nil
}
