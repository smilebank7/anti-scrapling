package token

import (
	"net/http"
	"time"
)

const DefaultCookieName = "__as_pass"

func SetCookie(w http.ResponseWriter, name, value string, ttl time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		Path:     "/",
	})
}

func GetCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
