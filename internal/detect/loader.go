package detect

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// LoadResult reports the outcome of a template load pass.
type LoadResult struct {
	Signatures []*CompiledSignature
	Loaded     int
	Skipped    int
	Errors     []error
}

// LoadDir walks dir recursively, parsing every *.yaml/*.yml as a Nuclei
// template and compiling it into a signature. Templates that fail to parse or
// compile are counted in Skipped/Errors but do not abort the load — a single
// bad CVE template from an external feed must not take down the WAF.
func LoadDir(dir string) (*LoadResult, error) {
	res := &LoadResult{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable entry: record and continue.
			res.Errors = append(res.Errors, err)
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir // don't walk the git clone's internals
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			res.Skipped++
			res.Errors = append(res.Errors, rerr)
			return nil
		}
		tmpl, perr := ParseTemplate(data)
		if perr != nil {
			res.Skipped++
			res.Errors = append(res.Errors, wrap(path, perr))
			return nil
		}
		tmpl.SourcePath = path
		sig, cerr := Compile(tmpl)
		if cerr != nil {
			res.Skipped++
			res.Errors = append(res.Errors, wrap(path, cerr))
			return nil
		}
		// A template with no usable HTTP block (e.g. network-only Nuclei
		// template) yields no signature blocks; skip it silently.
		if len(sig.blocks) == 0 {
			res.Skipped++
			return nil
		}
		res.Signatures = append(res.Signatures, sig)
		res.Loaded++
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return res, err
	}
	return res, nil
}

func wrap(path string, err error) error {
	return errors.New(filepath.Base(path) + ": " + err.Error())
}

// GitSource identifies a repo/branch to mirror; kept in this package so detect
// stays dependency-free of config.
type GitSource struct {
	Name   string
	URL    string
	Branch string
	Subdir string
}

// SyncRepo mirrors a single git repo's branch directly into dest (no
// subdirectory). Used for the templates and whitelist/blocklist repos. It shells
// out to git so the binary stays free of a Go git implementation; git is an
// install-time dependency, not a runtime library. A blank url is a no-op.
func SyncRepo(dest, url, branch string) error {
	if url == "" {
		return nil
	}
	return syncOne(dest, GitSource{URL: url, Branch: branch})
}

// syncOne overlays the repo's branch onto dest: files present in the repo
// overwrite same-named files in dest, while local files NOT in the repo are
// kept (custom/hand-added templates or *.ips lists survive). It uses
// init + fetch + `checkout FETCH_HEAD -- .` (rather than `git clone`, which
// requires an empty dir, or `reset --hard`+`clean`, which would delete the
// local-only files). The repo content lands directly in dest, no subdirectory.
func syncOne(dest string, s GitSource) error {
	branch := s.Branch
	if branch == "" {
		branch = "main"
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	if err := run(dest, "git", "init", "-q"); err != nil {
		return err
	}
	// Point origin at the URL (add if missing, else update).
	_ = run(dest, "git", "remote", "add", "origin", s.URL)
	if err := run(dest, "git", "remote", "set-url", "origin", s.URL); err != nil {
		return err
	}
	if err := run(dest, "git", "fetch", "--depth", "1", "-q", "origin", branch); err != nil {
		return err
	}
	// Path-checkout forcefully writes every file in FETCH_HEAD (overwriting
	// same-named local files) and leaves files not in the repo untouched.
	return run(dest, "git", "checkout", "-q", "FETCH_HEAD", "--", ".")
}

func run(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(err.Error() + ": " + strings.TrimSpace(string(out)))
	}
	return nil
}
