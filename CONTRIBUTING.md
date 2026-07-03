# Contributing to smoker

Thanks for your interest in improving smoker.

## Development setup

Requirements: Go 1.23+ and `git`. Most of the code builds and tests on any OS;
the nftables firewall layer and `SO_ORIGINAL_DST` recovery are Linux-only and
sit behind build tags, with no-op stubs elsewhere so the project builds
everywhere.

```sh
go mod tidy        # first checkout: fetch deps and generate go.sum
go test ./...      # run the test suite
make static        # build a static linux/amd64 binary into bin/smoker
```

## Before opening a PR

- `gofmt -s -w .` — code must be gofmt-clean.
- `go vet ./...` — no vet warnings.
- `go test ./... -race` — tests pass with the race detector.
- Add or update tests for behavior changes.
- Keep the mandated filesystem layout (`internal/paths`) intact; new runtime
  paths go through that package.

## Templates

Detection templates live in `templates/` and use the Nuclei YAML schema plus the
smoker `session-matchers` / `action` extensions (see the README). New behavioral
templates should default to `action: log-only` so operators can measure impact
via `blocked.log` before enforcing.

## Commit / PR conventions

- One logical change per PR; keep diffs focused.
- Describe the security impact of the change when relevant.
- Reference related issues (`Fixes #123`).

## Reporting security issues

Do **not** use public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).
