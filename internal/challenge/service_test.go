package challenge

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/smilebank7/anti-scrapling/internal/token"
	"github.com/smilebank7/anti-scrapling/internal/types"
)

func newTestService(t *testing.T, difficulty, threshold int) *Service {
	t.Helper()
	issuer, err := NewChallengeIssuer(difficulty)
	if err != nil {
		t.Fatalf("NewChallengeIssuer: %v", err)
	}
	tokIssuer := token.NewIssuer([]byte("test-secret-key-32byteslong12345"), time.Hour, nil)
	return NewService(issuer, tokIssuer, threshold, time.Hour, nil)
}

func solvePow(challengeID string, difficulty int) string {
	for i := 0; ; i++ {
		solution := fmt.Sprintf("%d", i)
		sum := sha256.Sum256([]byte(challengeID + solution))
		if leadingZeroBits(sum[:]) >= difficulty {
			return solution
		}
	}
}

func loadFingerprintJSON(t *testing.T, name string) json.RawMessage {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "fingerprint", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return normalizeFingerprintFixture(t, data)
}

func normalizeFingerprintFixture(t *testing.T, data []byte) json.RawMessage {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}
	if speech, ok := root["speech"].(map[string]any); ok {
		if rawVoices, ok := speech["voices"].([]any); ok {
			voices := make([]string, 0, len(rawVoices))
			for _, rv := range rawVoices {
				switch v := rv.(type) {
				case string:
					voices = append(voices, v)
				case map[string]any:
					if name, ok := v["name"].(string); ok {
						voices = append(voices, name)
					}
				}
			}
			speech["voices"] = voices
		}
	}
	if hairline, ok := root["hairline"].(map[string]any); ok {
		if legacyPass, ok := hairline["non_modernizr_result"].(bool); ok {
			if legacyPass {
				hairline["non_modernizr_result"] = 0
			} else {
				hairline["non_modernizr_result"] = 1
			}
		}
	}
	out, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("re-marshal fixture: %v", err)
	}
	return out
}

func TestHandleChallenge_ServesHTMLWithMetaTag(t *testing.T) {
	svc := newTestService(t, 4, 100)

	req := httptest.NewRequest(http.MethodGet, "/__as/challenge?origin=https://example.com/page", nil)
	rec := httptest.NewRecorder()

	svc.HandleChallenge(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, `data-difficulty="4"`) {
		t.Errorf("missing data-difficulty in HTML: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `data-origin="https://example.com/page"`) {
		t.Errorf("missing data-origin in HTML: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `data-id="`) {
		t.Errorf("missing data-id in HTML: %s", bodyStr)
	}
	if strings.Contains(bodyStr, metaPlaceholder) {
		t.Errorf("placeholder not replaced in HTML")
	}
}

func TestHandleBundle_ServesBundle(t *testing.T) {
	svc := newTestService(t, 4, 100)

	req := httptest.NewRequest(http.MethodGet, "/__as/challenge.bundle.js", nil)
	rec := httptest.NewRecorder()

	svc.HandleBundle(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("Content-Type = %q, want text/javascript", ct)
	}
	body, _ := io.ReadAll(res.Body)
	if len(body) == 0 {
		t.Error("bundle body is empty")
	}
}

func TestHandleVerify_ValidPow_LowScore_Redirects(t *testing.T) {
	svc := newTestService(t, 1, 100)

	id := svc.issuer.NewChallengeID()
	solution := solvePow(id, 1)

	fingerprintRaw := loadFingerprintJSON(t, "clean_chrome_131_linux.json")

	body := buildVerifyBody(t, id, solution, fingerprintRaw, "https://example.com/page")
	req := httptest.NewRequest(http.MethodPost, "/__as/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	svc.HandleVerify(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "https://example.com/page" {
		t.Errorf("Location = %q, want https://example.com/page", loc)
	}
	hasCookie := false
	for _, c := range res.Cookies() {
		if c.Name == token.DefaultCookieName {
			hasCookie = true
		}
	}
	if !hasCookie {
		t.Error("pass cookie not set")
	}
}

func TestHandleVerify_InvalidPow_Returns400(t *testing.T) {
	svc := newTestService(t, 20, 100)

	id := svc.issuer.NewChallengeID()

	fingerprintRaw := loadFingerprintJSON(t, "clean_chrome_131_linux.json")
	body := buildVerifyBody(t, id, "wrong-solution", fingerprintRaw, "/")
	req := httptest.NewRequest(http.MethodPost, "/__as/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	svc.HandleVerify(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHandleVerify_HighScoreFingerprint_Returns403(t *testing.T) {
	svc := newTestService(t, 1, 50)

	id := svc.issuer.NewChallengeID()
	solution := solvePow(id, 1)

	fingerprintRaw := loadFingerprintJSON(t, "scrapling_stealthy_fetcher.json")

	body := buildVerifyBody(t, id, solution, fingerprintRaw, "/")
	req := httptest.NewRequest(http.MethodPost, "/__as/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	svc.HandleVerify(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestHandleBeacon_Returns204(t *testing.T) {
	svc := newTestService(t, 4, 100)

	b := types.BehaviorBeacon{
		SessionID: "test-session",
		Timestamp: 1234567890,
	}
	data, _ := json.Marshal(b)
	req := httptest.NewRequest(http.MethodPost, "/__as/beacon", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	svc.HandleBeacon(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

func TestHandleSW_ReturnsServiceWorker(t *testing.T) {
	svc := newTestService(t, 4, 100)

	req := httptest.NewRequest(http.MethodGet, "/__as/sw.js", nil)
	rec := httptest.NewRecorder()

	svc.HandleSW(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "fetch") {
		t.Errorf("SW body missing fetch listener: %s", body)
	}
}

func buildVerifyBody(t *testing.T, id, solution string, fingerprintRaw json.RawMessage, originURL string) []byte {
	t.Helper()
	payload := map[string]json.RawMessage{
		"challenge_id":       mustJSON(t, id),
		"pow_solution":       mustJSON(t, solution),
		"fingerprint_report": fingerprintRaw,
		"origin_url":         mustJSON(t, originURL),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal verify body: %v", err)
	}
	return data
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return data
}
