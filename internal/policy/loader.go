package policy

import (
	"fmt"
	"os"
	"time"

	"github.com/smilebank7/anti-scrapling/internal/types"
	"gopkg.in/yaml.v3"
)

var validActions = map[string]bool{
	"allow":     true,
	"challenge": true,
	"deny":      true,
}

// Load reads the YAML policy file at path, validates its schema, and returns
// the parsed PolicyConfig. Errors include friendly messages with field context.
func Load(path string) (*types.PolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: cannot read %q: %w", path, err)
	}
	return parse(data)
}

func parse(data []byte) (*types.PolicyConfig, error) {
	var cfg types.PolicyConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("policy: YAML parse error: %w", err)
	}
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateConfig(cfg *types.PolicyConfig) error {
	if cfg.Version == 0 {
		return fmt.Errorf("policy: missing required field \"version\"")
	}

	if !validActions[cfg.Policy.Default] {
		return fmt.Errorf("policy: policy.default %q is invalid (must be \"allow\", \"challenge\", or \"deny\")", cfg.Policy.Default)
	}

	if cfg.Token.TTL != "" {
		if _, err := time.ParseDuration(cfg.Token.TTL); err != nil {
			return fmt.Errorf("policy: token.ttl %q is not a valid duration (e.g. \"24h\", \"30m\"): %w", cfg.Token.TTL, err)
		}
	}

	for i := range cfg.Policy.Rules {
		rule := &cfg.Policy.Rules[i]
		if !validActions[rule.Action] {
			return fmt.Errorf("policy: rules[%d] %q: action %q is invalid (must be \"allow\", \"challenge\", or \"deny\")", i, rule.Name, rule.Action)
		}
		if _, err := compileRule(rule); err != nil {
			return fmt.Errorf("policy: rules[%d] %q: %w", i, rule.Name, err)
		}
	}

	return nil
}
