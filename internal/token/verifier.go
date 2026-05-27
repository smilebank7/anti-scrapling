package token

import (
	"errors"
	"fmt"

	"github.com/smilebank7/anti-scrapling/internal/types"
	"github.com/golang-jwt/jwt/v5"
)

type Verifier struct {
	key    []byte
	bindTo []string
}

func NewVerifier(key []byte, bindTo []string) *Verifier {
	return &Verifier{key: key, bindTo: bindTo}
}

type VerifyContext struct {
	IP, UA, JA3, JA4 string
}

func (v *Verifier) Verify(tokenStr string, current VerifyContext) (*types.TokenClaims, error) {
	var claims types.TokenClaims

	tok, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("token: unexpected signing method: %v", t.Header["alg"])
		}
		return v.key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token: parse: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("token: invalid")
	}

	if err := BoundFields(&claims, current, v.bindTo); err != nil {
		return nil, err
	}

	return &claims, nil
}
