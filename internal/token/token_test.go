package token_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anti-scrapling/anti-scrapling/internal/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

var (
	baseIssue = token.IssueContext{
		FingerprintHash: "deadbeefcafe0123456789abcdef0000",
		IP:              "1.2.3.4",
		UA:              "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		JA3:             "771,4865-4866-4867,23-65281,0-1-3-5-7-18-23-43-51,0",
		JA4:             "t13d1516h2_8daaf6152771_02713d6af862",
		Score:           15,
	}
	baseVerify = token.VerifyContext{
		IP:  "1.2.3.4",
		UA:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		JA3: "771,4865-4866-4867,23-65281,0-1-3-5-7-18-23-43-51,0",
		JA4: "t13d1516h2_8daaf6152771_02713d6af862",
	}
)

func TestRoundTrip_NoBind(t *testing.T) {
	key := testKey()
	issuer := token.NewIssuer(key, time.Hour, nil)
	verifier := token.NewVerifier(key, nil)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)
	require.NotEmpty(t, tok)

	claims, err := verifier.Verify(tok, baseVerify)
	require.NoError(t, err)
	assert.Equal(t, baseIssue.FingerprintHash, claims.Sub)
	assert.Equal(t, 15, claims.Score)
	assert.Equal(t, 1, claims.Ver)
	assert.Empty(t, claims.IP)
	assert.Empty(t, claims.UA)
	assert.Empty(t, claims.JA3)
	assert.Empty(t, claims.JA4)
}

func TestRoundTrip_AllBindings(t *testing.T) {
	key := testKey()
	bindTo := []string{"ip", "ua", "ja3", "ja4"}
	issuer := token.NewIssuer(key, time.Hour, bindTo)
	verifier := token.NewVerifier(key, bindTo)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	claims, err := verifier.Verify(tok, baseVerify)
	require.NoError(t, err)
	assert.Equal(t, baseIssue.IP, claims.IP)
	assert.Equal(t, baseIssue.UA, claims.UA)
	assert.Equal(t, baseIssue.JA3, claims.JA3)
	assert.Equal(t, baseIssue.JA4, claims.JA4)
}

func TestRoundTrip_IPOnly(t *testing.T) {
	key := testKey()
	bindTo := []string{"ip"}
	issuer := token.NewIssuer(key, time.Hour, bindTo)
	verifier := token.NewVerifier(key, bindTo)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	claims, err := verifier.Verify(tok, baseVerify)
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4", claims.IP)
	assert.Empty(t, claims.UA)
	assert.Empty(t, claims.JA3)
}

func TestRoundTrip_UAOnly(t *testing.T) {
	key := testKey()
	bindTo := []string{"ua"}
	issuer := token.NewIssuer(key, time.Hour, bindTo)
	verifier := token.NewVerifier(key, bindTo)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	claims, err := verifier.Verify(tok, baseVerify)
	require.NoError(t, err)
	assert.Equal(t, baseIssue.UA, claims.UA)
	assert.Empty(t, claims.IP)
}

func TestRoundTrip_JA3Only(t *testing.T) {
	key := testKey()
	bindTo := []string{"ja3"}
	issuer := token.NewIssuer(key, time.Hour, bindTo)
	verifier := token.NewVerifier(key, bindTo)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	claims, err := verifier.Verify(tok, baseVerify)
	require.NoError(t, err)
	assert.Equal(t, baseIssue.JA3, claims.JA3)
}

func TestRoundTrip_JA4Only(t *testing.T) {
	key := testKey()
	bindTo := []string{"ja4"}
	issuer := token.NewIssuer(key, time.Hour, bindTo)
	verifier := token.NewVerifier(key, bindTo)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	claims, err := verifier.Verify(tok, baseVerify)
	require.NoError(t, err)
	assert.Equal(t, baseIssue.JA4, claims.JA4)
}

func TestExpiredToken_Rejected(t *testing.T) {
	key := testKey()
	issuer := token.NewIssuer(key, -2*time.Second, nil)
	verifier := token.NewVerifier(key, nil)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	_, err = verifier.Verify(tok, baseVerify)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestTamperedSignature_Rejected(t *testing.T) {
	key := testKey()
	issuer := token.NewIssuer(key, time.Hour, nil)
	verifier := token.NewVerifier(key, nil)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	parts := strings.Split(tok, ".")
	require.Len(t, parts, 3)
	sig := []byte(parts[2])
	for i := range sig {
		sig[i] ^= 0x01
		if sig[i] != parts[2][i] {
			break
		}
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)

	_, err = verifier.Verify(tampered, baseVerify)
	require.Error(t, err)
}

func TestBindingMismatch_IP(t *testing.T) {
	key := testKey()
	bindTo := []string{"ip"}
	issuer := token.NewIssuer(key, time.Hour, bindTo)
	verifier := token.NewVerifier(key, bindTo)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	changed := baseVerify
	changed.IP = "9.9.9.9"

	_, err = verifier.Verify(tok, changed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ip")
}

func TestBindingMismatch_UA(t *testing.T) {
	key := testKey()
	bindTo := []string{"ua"}
	issuer := token.NewIssuer(key, time.Hour, bindTo)
	verifier := token.NewVerifier(key, bindTo)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	changed := baseVerify
	changed.UA = "curl/7.88.1"

	_, err = verifier.Verify(tok, changed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ua")
}

func TestBindingMismatch_JA3(t *testing.T) {
	key := testKey()
	bindTo := []string{"ja3"}
	issuer := token.NewIssuer(key, time.Hour, bindTo)
	verifier := token.NewVerifier(key, bindTo)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	changed := baseVerify
	changed.JA3 = "769,47-53,0,0"

	_, err = verifier.Verify(tok, changed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ja3")
}

func TestBindingMismatch_MultiField(t *testing.T) {
	key := testKey()
	bindTo := []string{"ip", "ja3"}
	issuer := token.NewIssuer(key, time.Hour, bindTo)
	verifier := token.NewVerifier(key, bindTo)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	changed := token.VerifyContext{
		IP:  "9.9.9.9",
		UA:  baseVerify.UA,
		JA3: "different",
		JA4: baseVerify.JA4,
	}

	_, err = verifier.Verify(tok, changed)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ip")
	assert.Contains(t, err.Error(), "ja3")
}

func TestUA_CaseInsensitive(t *testing.T) {
	key := testKey()
	bindTo := []string{"ua"}
	issuer := token.NewIssuer(key, time.Hour, bindTo)
	verifier := token.NewVerifier(key, bindTo)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	changed := baseVerify
	changed.UA = strings.ToUpper(baseVerify.UA)

	claims, err := verifier.Verify(tok, changed)
	require.NoError(t, err)
	assert.NotNil(t, claims)
}

func TestReplay_SameContext(t *testing.T) {
	key := testKey()
	bindTo := []string{"ip", "ua", "ja3"}
	issuer := token.NewIssuer(key, time.Hour, bindTo)
	verifier := token.NewVerifier(key, bindTo)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	for range 3 {
		claims, err := verifier.Verify(tok, baseVerify)
		require.NoError(t, err)
		assert.Equal(t, baseIssue.FingerprintHash, claims.Sub)
	}
}

func TestLoadKey_GeneratesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")

	key, err := token.LoadKey(path)
	require.NoError(t, err)
	assert.Len(t, key, 32)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, key, data)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestLoadKey_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")

	key1, err := token.LoadKey(path)
	require.NoError(t, err)

	key2, err := token.LoadKey(path)
	require.NoError(t, err)

	assert.Equal(t, key1, key2)
}

func TestLoadKey_RejectsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.key")
	require.NoError(t, os.WriteFile(path, []byte{}, 0600))

	_, err := token.LoadKey(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestCookie_SetGet(t *testing.T) {
	w := httptest.NewRecorder()
	token.SetCookie(w, token.DefaultCookieName, "jwt.payload.sig", time.Hour, false)

	resp := w.Result()
	cookies := resp.Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, token.DefaultCookieName, cookies[0].Name)
	assert.Equal(t, "jwt.payload.sig", cookies[0].Value)
	assert.True(t, cookies[0].HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookies[0])

	val := token.GetCookie(req, token.DefaultCookieName)
	assert.Equal(t, "jwt.payload.sig", val)
}

func TestCookie_MissingReturnsEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.Empty(t, token.GetCookie(req, token.DefaultCookieName))
}

func TestCookie_WrongNameReturnsEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "other", Value: "v"})
	assert.Empty(t, token.GetCookie(req, token.DefaultCookieName))
}

func TestWrongKey_Rejected(t *testing.T) {
	key1 := testKey()
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(255 - i)
	}

	issuer := token.NewIssuer(key1, time.Hour, nil)
	verifier := token.NewVerifier(key2, nil)

	tok, err := issuer.Issue(baseIssue)
	require.NoError(t, err)

	_, err = verifier.Verify(tok, baseVerify)
	require.Error(t, err)
}
