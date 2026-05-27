package behavior_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/anti-scrapling/anti-scrapling/internal/signal/behavior"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixtureDir = "../../../testdata/behavior"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, name))
	require.NoError(t, err, "loading fixture %s", name)
	return data
}

type fixtureCase struct {
	file     string
	minScore int
	maxScore int
}

var cases = []fixtureCase{
	{"real_user_browsing.json", 0, 0},
	{"real_user_fast_reader.json", 0, 0},
	{"real_user_mobile.json", 0, 0},
	{"bot_scrapling_stealthy.json", 30, 9999},
	{"bot_scrapling_turnstile_click.json", 30, 9999},
	{"bot_synthetic_smooth.json", 30, 9999},
}

func TestFixtureScores(t *testing.T) {
	for _, tc := range cases {
		tc := tc
		t.Run(tc.file, func(t *testing.T) {
			data := loadFixture(t, tc.file)

			beacon, err := behavior.Ingest(data)
			require.NoError(t, err)

			signals := behavior.Score(beacon)

			score := 0
			for _, s := range signals {
				score += s.Score
				t.Logf("  signal=%s score=%d reason=%q", s.Name, s.Score, s.Reason)
			}
			t.Logf("total_score=%d", score)

			assert.GreaterOrEqual(t, score, tc.minScore, "score should be >= %d", tc.minScore)
			assert.LessOrEqual(t, score, tc.maxScore, "score should be <= %d", tc.maxScore)
		})
	}
}

func TestIngestEmptyPayload(t *testing.T) {
	_, err := behavior.Ingest(nil)
	assert.Error(t, err)
}

func TestIngestMissingSessionID(t *testing.T) {
	_, err := behavior.Ingest([]byte(`{"visit_duration_ms":1000}`))
	assert.Error(t, err)
}

func TestIngestInvalidJSON(t *testing.T) {
	_, err := behavior.Ingest([]byte(`{not json`))
	assert.Error(t, err)
}
