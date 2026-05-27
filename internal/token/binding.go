package token

import (
	"fmt"
	"strings"

	"github.com/anti-scrapling/anti-scrapling/internal/types"
)

// BoundFields checks each field listed in bindTo against the current request context.
// UA comparison is case-insensitive; all other fields are exact.
// Returns an error that lists every mismatch, or nil on full match.
func BoundFields(claims *types.TokenClaims, current VerifyContext, bindTo []string) error {
	var mismatches []string

	for _, field := range bindTo {
		switch field {
		case "ip":
			if claims.IP != current.IP {
				mismatches = append(mismatches, fmt.Sprintf("ip: claim=%q current=%q", claims.IP, current.IP))
			}
		case "ua":
			if !strings.EqualFold(claims.UA, current.UA) {
				mismatches = append(mismatches, fmt.Sprintf("ua: claim=%q current=%q", claims.UA, current.UA))
			}
		case "ja3":
			if claims.JA3 != current.JA3 {
				mismatches = append(mismatches, fmt.Sprintf("ja3: claim=%q current=%q", claims.JA3, current.JA3))
			}
		case "ja4":
			if claims.JA4 != current.JA4 {
				mismatches = append(mismatches, fmt.Sprintf("ja4: claim=%q current=%q", claims.JA4, current.JA4))
			}
		}
	}

	if len(mismatches) > 0 {
		return fmt.Errorf("token: binding mismatch: %s", strings.Join(mismatches, "; "))
	}
	return nil
}
