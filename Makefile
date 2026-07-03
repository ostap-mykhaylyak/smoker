# smoker — reverse-proxy WAF. Static Linux binary, no runtime deps.

BINARY      := smoker
PKG         := ./cmd/smoker
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)

# Install locations (mandated layout).
SBIN_DIR    := /sbin
CONF_DIR    := /etc/smoker
TMPL_DIR    := /etc/smoker/templates
LOG_DIR     := /var/log/smoker
WWW_DIR     := /var/www/smoker
UNIT_DIR    := /etc/systemd/system

SMOKER_USER := smoker
SMOKER_GRP  := smoker

.PHONY: all build static test vet fmt clean install uninstall dirs

all: static

build:
	go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY) $(PKG)

# Fully static binary for Linux (no libc), suitable for any distro.
static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) $(PKG)

test:
	go test ./... -race -count=1

vet:
	go vet ./...

fmt:
	gofmt -s -w .

clean:
	rm -rf bin

# --- Installation -----------------------------------------------------------

# Create the runtime user and the mandated directory layout.
dirs:
	@id -u $(SMOKER_USER) >/dev/null 2>&1 || \
		useradd --system --no-create-home --shell /usr/sbin/nologin $(SMOKER_USER)
	install -d -m 0755 $(SBIN_DIR)
	install -d -m 0750 -o root          -g $(SMOKER_GRP) $(CONF_DIR)
	install -d -m 0755 -o root          -g $(SMOKER_GRP) $(TMPL_DIR)
	install -d -m 0755 -o root          -g $(SMOKER_GRP) $(CONF_DIR)/whitelist
	install -d -m 0755 -o root          -g $(SMOKER_GRP) $(CONF_DIR)/blocklist
	install -d -m 0750 -o $(SMOKER_USER) -g $(SMOKER_GRP) $(LOG_DIR)
	install -d -m 0755 -o root          -g $(SMOKER_GRP) $(WWW_DIR)

SKEL := internal/bootstrap/skel

install: static dirs
	# Binary -> /sbin/smoker
	install -m 0755 bin/$(BINARY) $(SBIN_DIR)/$(BINARY)
	# Config (do not clobber an existing config.yaml)
	test -f $(CONF_DIR)/config.yaml || install -m 0640 -o root -g $(SMOKER_GRP) $(SKEL)/etc/smoker/config.yaml $(CONF_DIR)/config.yaml
	# Access-list dirs are populated by the git sync at runtime (see config.yaml).
	# Templates are NOT bundled: the templates dir (created above) is populated
	# entirely by the git-synced repo at runtime (see templates.git in config.yaml).
	# Static challenge/block assets
	install -m 0644 $(SKEL)/var/www/smoker/*.html $(WWW_DIR)/
	# systemd unit
	install -m 0644 internal/bootstrap/smoker.service $(UNIT_DIR)/smoker.service
	# logrotate policy
	install -d -m 0755 /etc/logrotate.d
	install -m 0644 $(SKEL)/etc/logrotate.d/smoker /etc/logrotate.d/smoker
	@echo
	@echo "Installed. Next steps:"
	@echo "  1) edit $(CONF_DIR)/config.yaml (set challenge.secret!)"
	@echo "  2) systemctl daemon-reload && systemctl enable --now smoker"

uninstall:
	-systemctl disable --now smoker 2>/dev/null || true
	rm -f $(SBIN_DIR)/$(BINARY)
	rm -f $(UNIT_DIR)/smoker.service
	rm -f /etc/logrotate.d/smoker
	@echo "Left $(CONF_DIR), $(LOG_DIR), $(WWW_DIR) in place (remove manually if desired)."
