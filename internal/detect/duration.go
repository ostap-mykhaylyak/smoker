package detect

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// yamlDuration parses Go duration strings ("30m", "24h") from YAML. Aliased to
// detect.Duration; kept separate to avoid importing internal/config here.
type yamlDuration time.Duration

func (d *yamlDuration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = yamlDuration(parsed)
	return nil
}

// Std returns the standard library duration.
func (d yamlDuration) Std() time.Duration { return time.Duration(d) }
