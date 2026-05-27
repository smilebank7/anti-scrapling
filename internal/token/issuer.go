package token

import (
	"fmt"
	"time"

	"github.com/anti-scrapling/anti-scrapling/internal/types"
	"github.com/golang-jwt/jwt/v5"
)

type Issuer struct {
	key    []byte
	ttl    time.Duration
	bindTo []string
}

func NewIssuer(key []byte, ttl time.Duration, bindTo []string) *Issuer {
	return &Issuer{key: key, ttl: ttl, bindTo: bindTo}
}

type IssueContext struct {
	FingerprintHash  string
	IP, UA, JA3, JA4 string
	Score            int
}

func (i *Issuer) Issue(ctx IssueContext) (string, error) {
	now := time.Now()
	claims := &types.TokenClaims{
		Sub:   ctx.FingerprintHash,
		Score: ctx.Score,
		Ver:   1,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
		},
	}

	for _, field := range i.bindTo {
		switch field {
		case "ip":
			claims.IP = ctx.IP
		case "ua":
			claims.UA = ctx.UA
		case "ja3":
			claims.JA3 = ctx.JA3
		case "ja4":
			claims.JA4 = ctx.JA4
		}
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(i.key)
	if err != nil {
		return "", fmt.Errorf("token: sign: %w", err)
	}
	return signed, nil
}
