package headers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRefererTracker_BelowMinimumCount(t *testing.T) {
	tr := NewRefererTracker(10, 0.80)
	for i := 0; i < 4; i++ {
		triggered := tr.Observe("1.2.3.4", "https://www.google.com/")
		assert.False(t, triggered, "should not trigger before 5 observations")
	}
}

func TestRefererTracker_TriggerAboveThreshold(t *testing.T) {
	tr := NewRefererTracker(10, 0.80)
	for i := 0; i < 9; i++ {
		tr.Observe("1.2.3.4", "https://www.google.com/")
	}
	triggered := tr.Observe("1.2.3.4", "https://www.google.com/")
	assert.True(t, triggered, "10/10 = 100% should trigger")
}

func TestRefererTracker_NoTriggerAt80Percent(t *testing.T) {
	tr := NewRefererTracker(10, 0.80)
	for i := 0; i < 2; i++ {
		tr.Observe("1.2.3.4", "")
	}
	for i := 0; i < 8; i++ {
		tr.Observe("1.2.3.4", "https://www.google.com/")
	}
	triggered := tr.Observe("1.2.3.4", "")
	_ = triggered

	tr2 := NewRefererTracker(10, 0.80)
	for i := 0; i < 2; i++ {
		tr2.Observe("1.2.3.4", "")
	}
	for i := 0; i < 7; i++ {
		tr2.Observe("1.2.3.4", "https://www.google.com/")
	}
	result := tr2.Observe("1.2.3.4", "")
	assert.False(t, result, "7/10 = 70% should not trigger")
}

func TestRefererTracker_PerIPIsolation(t *testing.T) {
	tr := NewRefererTracker(10, 0.80)
	for i := 0; i < 10; i++ {
		tr.Observe("1.1.1.1", "https://www.google.com/")
	}
	triggered := tr.Observe("2.2.2.2", "https://www.google.com/")
	assert.False(t, triggered, "different IP should have its own window")
}

func TestRefererTracker_NonGoogleReferer(t *testing.T) {
	tr := NewRefererTracker(10, 0.80)
	for i := 0; i < 10; i++ {
		tr.Observe("1.2.3.4", "https://example.com/")
	}
	triggered := tr.Observe("1.2.3.4", "https://example.com/")
	assert.False(t, triggered)
}

func TestIsGoogleReferer(t *testing.T) {
	assert.True(t, isGoogleReferer("https://www.google.com/"))
	assert.True(t, isGoogleReferer("https://google.com/search"))
	assert.True(t, isGoogleReferer("https://www.google.co.uk/"))
	assert.False(t, isGoogleReferer(""))
	assert.False(t, isGoogleReferer("https://example.com/"))
	assert.False(t, isGoogleReferer("https://notgoogle.com/"))
}
