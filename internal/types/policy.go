package types

// PolicyConfig is the top-level YAML unmarshal target for a policy file.
type PolicyConfig struct {
	Version   int             `yaml:"version"`
	Listener  ListenerConfig  `yaml:"listener"`
	Token     TokenConfig     `yaml:"token"`
	Policy    PolicySection   `yaml:"policy"`
	Scoring   ScoringConfig   `yaml:"scoring"`
	Challenge ChallengeConfig `yaml:"challenge"`
	Cache     CacheConfig     `yaml:"cache,omitempty"`
}

// ListenerConfig describes the proxy bind address, upstream target, and optional TLS.
type ListenerConfig struct {
	Bind   string     `yaml:"bind"`
	Target string     `yaml:"target"`
	TLS    *TLSConfig `yaml:"tls,omitempty"`
}

// TLSConfig holds paths to the TLS certificate and private key.
type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// TokenConfig controls JWT pass-token issuance.
type TokenConfig struct {
	// SecretFile is the path to a file containing the HMAC secret.
	SecretFile string `yaml:"secret_file"`

	// TTL is a duration string parsed at load time, e.g. "1h".
	TTL string `yaml:"ttl"`

	// BindTo lists the request attributes to bind the token to: ip, ua, ja3.
	BindTo []string `yaml:"bind_to"`
}

// PolicySection contains the default action and the ordered rule list.
type PolicySection struct {
	// Default is the fallback action when no rule matches: "allow", "challenge", or "deny".
	Default string       `yaml:"default"`
	Rules   []PolicyRule `yaml:"rules"`
}

// PolicyRule is a single named match+action entry in the policy.
type PolicyRule struct {
	Name string `yaml:"name"`
	// Match is a map of match conditions (path, ja3_in, score, etc.)
	// or a raw CEL expression stored under the "expr" key.
	Match  map[string]any `yaml:"match"`
	Action string         `yaml:"action"` // allow, challenge, deny
	Reason string         `yaml:"reason,omitempty"`
}

// ScoringConfig configures signal weights and verdict thresholds.
type ScoringConfig struct {
	Weights            map[string]int `yaml:"weights"`
	ChallengeThreshold int            `yaml:"challenge_threshold"` // default 50
	DenyThreshold      int            `yaml:"deny_threshold"`      // default 80
}

// ChallengeConfig controls the proof-of-work difficulty and fingerprint collection.
type ChallengeConfig struct {
	PowDifficulty      int  `yaml:"pow_difficulty"`
	CollectFingerprint bool `yaml:"collect_fingerprint"`
}

// CacheConfig selects the decision cache backend.
type CacheConfig struct {
	// Backend is "memory" or "redis".
	Backend string `yaml:"backend"`
	Redis   *struct {
		Addr string `yaml:"addr"`
		DB   int    `yaml:"db"`
	} `yaml:"redis,omitempty"`
	TTLSeconds int `yaml:"ttl_seconds"`
}
