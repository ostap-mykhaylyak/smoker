// Package paths centralizes the hardcoded production filesystem layout used by
// every smoker component. Defaults follow the FHS layout mandated by the spec:
//
//	/sbin/smoker            main executable
//	/etc/smoker/            configuration (read-only at runtime)
//	/etc/smoker/templates/  Nuclei templates (CVE + custom)
//	/var/log/smoker/        all runtime logs + reputation.db
//	/var/www/smoker/        static challenge/captcha/block assets
//
// Overrides exist ONLY for testing (via flags/env in cmd/smoker); production
// deployments must rely on these constants.
package paths

const (
	// Binary is the canonical install location of the executable.
	Binary = "/sbin/smoker"

	// ConfigDir holds configuration; mounted read-only by the systemd unit.
	ConfigDir = "/etc/smoker"

	// ConfigFile is the primary YAML configuration file.
	ConfigFile = "/etc/smoker/config.yaml"

	// TemplatesDir holds Nuclei templates (CVE feeds + custom behavioral rules).
	TemplatesDir = "/etc/smoker/templates"

	// WhitelistDir / BlocklistDir hold git-synced repos of IP/CIDR *.ips files
	// (every such file is merged into the list). Writable at runtime for sync.
	WhitelistDir = "/etc/smoker/whitelist"
	BlocklistDir = "/etc/smoker/blocklist"

	// LogDir holds all structured log files and runtime state (reputation.db).
	LogDir = "/var/log/smoker"

	// ReputationDB is the BoltDB file. It is runtime state, not configuration,
	// hence it lives under LogDir (the only ReadWritePath in the unit).
	ReputationDB = "/var/log/smoker/reputation.db"

	// AssetsDir holds the operator-editable challenge/captcha/block pages.
	AssetsDir = "/var/www/smoker"

	// Log file names (joined with LogDir).
	AccessLog     = "access.log"
	BlockedLog    = "blocked.log"
	ReputationLog = "reputation.log"
	ServiceLog    = "smoker.log"
)
