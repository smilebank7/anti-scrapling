package types

import "github.com/golang-jwt/jwt/v5"

// TokenClaims are the JWT claims embedded in every pass-token issued after a successful challenge.
type TokenClaims struct {
	Sub   string `json:"sub"`           // sha256(fingerprint)
	IP    string `json:"ip,omitempty"`  // bound client IP
	UA    string `json:"ua,omitempty"`  // bound User-Agent
	JA3   string `json:"ja3,omitempty"` // bound JA3 fingerprint
	JA4   string `json:"ja4,omitempty"` // bound JA4 fingerprint
	Score int    `json:"score"`         // risk score at time of issuance
	Ver   int    `json:"ver"`           // schema version
	jwt.RegisteredClaims
}
