package observability_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/smilebank7/anti-scrapling/internal/observability"
	"github.com/smilebank7/anti-scrapling/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeAuditEntry(ts time.Time, verdict types.Verdict) observability.AuditEntry {
	return observability.AuditEntry{
		Timestamp: ts,
		RequestID: fmt.Sprintf("r-%d", ts.UnixNano()),
		IP:        "1.2.3.4",
		URL:       "https://example.com/",
		Verdict:   verdict,
		Score:     20,
	}
}

func TestAudit_RecordAndSince_Basic(t *testing.T) {
	a := observability.NewAudit(100)
	now := time.Now()

	a.Record(makeAuditEntry(now.Add(-10*time.Minute), types.VerdictAllow))
	a.Record(makeAuditEntry(now.Add(-5*time.Minute), types.VerdictDeny))
	a.Record(makeAuditEntry(now.Add(-1*time.Minute), types.VerdictChallenge))

	all := a.Since(now.Add(-20 * time.Minute))
	assert.Len(t, all, 3, "all three entries since 20 min ago")

	recent := a.Since(now.Add(-7 * time.Minute))
	require.Len(t, recent, 2, "two entries in last 7 minutes")
	assert.Equal(t, types.VerdictDeny, recent[0].Verdict)
	assert.Equal(t, types.VerdictChallenge, recent[1].Verdict)
}

func TestAudit_RingEviction(t *testing.T) {
	const size = 5
	a := observability.NewAudit(size)
	base := time.Now().Truncate(time.Second)

	for i := 0; i < 8; i++ {
		a.Record(makeAuditEntry(base.Add(time.Duration(i)*time.Second), types.VerdictAllow))
	}

	all := a.Since(base.Add(-time.Second))
	assert.Len(t, all, size, "ring buffer holds exactly %d entries", size)
	assert.Equal(t, base.Add(3*time.Second).Unix(), all[0].Timestamp.Unix(),
		"oldest surviving entry should be the 4th recorded (index 3)")
}

func TestAudit_EmptyBuffer(t *testing.T) {
	a := observability.NewAudit(10)
	assert.Empty(t, a.Since(time.Now()))
}

func TestAudit_DefaultSize(t *testing.T) {
	a := observability.NewAudit(0)
	base := time.Now()
	a.Record(makeAuditEntry(base, types.VerdictAllow))
	assert.Len(t, a.Since(base.Add(-time.Second)), 1)
}

func TestAudit_HTTPHandler_NoFilter(t *testing.T) {
	a := observability.NewAudit(100)
	now := time.Now()
	a.Record(makeAuditEntry(now.Add(-2*time.Minute), types.VerdictAllow))
	a.Record(makeAuditEntry(now.Add(-30*time.Second), types.VerdictDeny))

	rr := httptest.NewRecorder()
	a.HTTPHandler().ServeHTTP(rr, httptest.NewRequest("GET", "/admin/audit", nil))
	require.Equal(t, 200, rr.Code)

	var entries []observability.AuditEntry
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&entries))
	assert.Len(t, entries, 2)
}

func TestAudit_HTTPHandler_SinceFilter(t *testing.T) {
	a := observability.NewAudit(100)
	now := time.Now()
	a.Record(makeAuditEntry(now.Add(-2*time.Minute), types.VerdictAllow))
	a.Record(makeAuditEntry(now.Add(-30*time.Second), types.VerdictDeny))

	params := url.Values{"since": {now.Add(-1 * time.Minute).UTC().Format(time.RFC3339)}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/admin/audit?"+params.Encode(), nil)
	a.HTTPHandler().ServeHTTP(rr, req)
	require.Equal(t, 200, rr.Code)

	var entries []observability.AuditEntry
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&entries))
	require.Len(t, entries, 1)
	assert.Equal(t, types.VerdictDeny, entries[0].Verdict)
}
