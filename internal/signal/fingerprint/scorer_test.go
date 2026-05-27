package fingerprint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anti-scrapling/anti-scrapling/internal/types"
)

func TestScoreFixtures(t *testing.T) {
	testdataDir := filepath.Join("..", "..", "..", "testdata", "fingerprint")

	tests := []struct {
		file         string
		maxExclusive int
		minInclusive int
	}{
		{file: "clean_chrome_131_linux.json", maxExclusive: 20},
		{file: "clean_chrome_131_mac.json", maxExclusive: 20},
		{file: "clean_firefox_134_linux.json", maxExclusive: 20},
		{file: "clean_safari_18_mac.json", maxExclusive: 20},
		{file: "patchright_chromium_131.json", minInclusive: 80},
		{file: "camoufox_default.json", minInclusive: 80},
		{file: "playwright_stealth_chromium.json", minInclusive: 80},
		{file: "scrapling_stealthy_fetcher.json", minInclusive: 80},
	}

	for _, test := range tests {
		test := test
		t.Run(strings.TrimSuffix(test.file, ".json"), func(t *testing.T) {
			report := loadFingerprintFixture(t, filepath.Join(testdataDir, test.file))

			signals, err := Score(report)
			if err != nil {
				t.Fatalf("Score() error = %v", err)
			}

			score := totalScore(signals)
			t.Logf("profile=%s score=%d signals=%v", test.file, score, signalNames(signals))

			if test.maxExclusive > 0 && score >= test.maxExclusive {
				t.Fatalf("score = %d, want < %d", score, test.maxExclusive)
			}
			if test.minInclusive > 0 && score < test.minInclusive {
				t.Fatalf("score = %d, want >= %d", score, test.minInclusive)
			}
		})
	}
}

func loadFingerprintFixture(t *testing.T, path string) types.FingerprintReport {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var report types.FingerprintReport
	if err := json.Unmarshal(normalizeFixtureJSON(t, data), &report); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	return report
}

func normalizeFixtureJSON(t *testing.T, data []byte) []byte {
	t.Helper()

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("decode fixture JSON: %v", err)
	}

	normalizeSpeechVoices(root)
	normalizeHairlineResult(root)

	normalized, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("encode normalized fixture JSON: %v", err)
	}

	return normalized
}

func normalizeSpeechVoices(root map[string]any) {
	speech, ok := root["speech"].(map[string]any)
	if !ok {
		return
	}

	rawVoices, ok := speech["voices"].([]any)
	if !ok {
		return
	}

	voices := make([]string, 0, len(rawVoices))
	for _, rawVoice := range rawVoices {
		switch voice := rawVoice.(type) {
		case string:
			voices = append(voices, voice)
		case map[string]any:
			if name, ok := voice["name"].(string); ok {
				voices = append(voices, name)
			}
		}
	}

	speech["voices"] = voices
}

func normalizeHairlineResult(root map[string]any) {
	hairline, ok := root["hairline"].(map[string]any)
	if !ok {
		return
	}

	legacyPass, ok := hairline["non_modernizr_result"].(bool)
	if !ok {
		return
	}

	// Early fixtures stored this as pass/fail bool: true is normal, false is the
	// non-Modernizr anomaly. The frozen schema stores an anomaly count instead.
	if legacyPass {
		hairline["non_modernizr_result"] = 0
		return
	}
	hairline["non_modernizr_result"] = 1
}

func totalScore(signals []types.Signal) int {
	total := 0
	for _, signal := range signals {
		total += signal.Score
	}
	return total
}

func signalNames(signals []types.Signal) []string {
	names := make([]string, 0, len(signals))
	for _, signal := range signals {
		names = append(names, signal.Name)
	}
	return names
}
