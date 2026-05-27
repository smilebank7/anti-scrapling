package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anti-scrapling/anti-scrapling/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const examplePolicy = `
version: 1
listener:
  bind: ":8080"
  target: "http://upstream:3000"
  tls:
    cert: /etc/anti-scrapling/cert.pem
    key:  /etc/anti-scrapling/key.pem

token:
  secret_file: /etc/anti-scrapling/token.key
  ttl: 24h
  bind_to: [ip, ua, ja3]

policy:
  default: challenge

  rules:
    - name: allow-healthcheck
      match: { path: "/healthz" }
      action: allow

    - name: deny-known-scrapers
      match: { ja3_in: ["@curl_cffi/*", "@python-requests"] }
      action: deny
      reason: "TLS signature matches known scraper library"

    - name: deny-datacenter-ip
      match: { ip_category: datacenter, score: ">=80" }
      action: deny

    - name: challenge-suspicious
      match: { score: ">=50" }
      action: challenge

    - name: allow-verified
      match: { has_valid_token: true }
      action: allow

scoring:
  weights:
    ja3_mismatch: 40
    h2_mismatch: 35
    header_order_anomaly: 20
    ua_ch_mismatch: 25
    datacenter_ip: 30
    no_referer: 5
    google_referer_anomaly: 10
    fingerprint_lie: 50
    headless_signal: 60
    behavior_anomaly: 15

challenge:
  pow_difficulty: 4
  collect_fingerprint: true
`

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "policy-*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestLoad_ExamplePolicy(t *testing.T) {
	p := writePolicy(t, examplePolicy)
	cfg, err := policy.Load(p)
	require.NoError(t, err)

	assert.Equal(t, 1, cfg.Version)
	assert.Equal(t, "challenge", cfg.Policy.Default)
	assert.Len(t, cfg.Policy.Rules, 5)

	rules := cfg.Policy.Rules
	assert.Equal(t, "allow-healthcheck", rules[0].Name)
	assert.Equal(t, "allow", rules[0].Action)
	assert.Equal(t, "deny-known-scrapers", rules[1].Name)
	assert.Equal(t, "deny", rules[1].Action)
	assert.Equal(t, "TLS signature matches known scraper library", rules[1].Reason)
	assert.Equal(t, "deny-datacenter-ip", rules[2].Name)
	assert.Equal(t, "deny", rules[2].Action)
	assert.Equal(t, "challenge-suspicious", rules[3].Name)
	assert.Equal(t, "challenge", rules[3].Action)
	assert.Equal(t, "allow-verified", rules[4].Name)
	assert.Equal(t, "allow", rules[4].Action)

	assert.Equal(t, "24h", cfg.Token.TTL)
	assert.Equal(t, 4, cfg.Challenge.PowDifficulty)
	assert.True(t, cfg.Challenge.CollectFingerprint)
	assert.Equal(t, 40, cfg.Scoring.Weights["ja3_mismatch"])
	assert.Equal(t, 60, cfg.Scoring.Weights["headless_signal"])
}

func TestLoad_MissingVersion(t *testing.T) {
	p := writePolicy(t, `
policy:
  default: challenge
  rules: []
`)
	_, err := policy.Load(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version")
}

func TestLoad_InvalidDefaultAction(t *testing.T) {
	p := writePolicy(t, `
version: 1
policy:
  default: bad-action
  rules: []
`)
	_, err := policy.Load(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad-action")
}

func TestLoad_InvalidRuleAction(t *testing.T) {
	p := writePolicy(t, `
version: 1
policy:
  default: challenge
  rules:
    - name: bad-rule
      match: { path: "/foo" }
      action: block
`)
	_, err := policy.Load(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "block")
	assert.Contains(t, err.Error(), "bad-rule")
}

func TestLoad_BadDuration(t *testing.T) {
	p := writePolicy(t, `
version: 1
token:
  ttl: "not-a-duration"
policy:
  default: challenge
  rules: []
`)
	_, err := policy.Load(p)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-a-duration")
}

func TestLoad_UnparseableCEL(t *testing.T) {
	p := writePolicy(t, `
version: 1
policy:
  default: challenge
  rules:
    - name: bad-expr
      match: { expr: "score >= && true" }
      action: allow
`)
	_, err := policy.Load(p)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "bad-expr") || strings.Contains(err.Error(), "CEL"))
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := policy.Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot read")
}
