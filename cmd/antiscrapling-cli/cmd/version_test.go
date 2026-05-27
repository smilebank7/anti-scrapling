package cmd_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/smilebank7/anti-scrapling/cmd/antiscrapling-cli/cmd"
)

func TestVersionCmd(t *testing.T) {
	var buf bytes.Buffer
	err := cmd.ExecuteWithArgs([]string{"version"}, &buf)
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "antiscrapling-cli") {
		t.Errorf("expected output to contain 'antiscrapling-cli', got: %q", got)
	}
	if !strings.Contains(got, cmd.Version) {
		t.Errorf("expected output to contain version %q, got: %q", cmd.Version, got)
	}
}
