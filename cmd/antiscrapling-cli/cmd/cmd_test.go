package cmd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/smilebank7/anti-scrapling/cmd/antiscrapling-cli/cmd"
)

func TestConfigValidate_Valid(t *testing.T) {
	var buf bytes.Buffer
	err := cmd.ExecuteWithArgs([]string{"config", "validate", policyPath(t, "default.yaml")}, &buf)
	if err != nil {
		t.Fatalf("config validate failed: %v", err)
	}
	if !strings.Contains(buf.String(), "OK") {
		t.Errorf("expected OK in output, got: %q", buf.String())
	}
}

func TestConfigValidate_Invalid(t *testing.T) {
	f := writeTempFile(t, "bad.yaml", []byte("version: 1\npolicy:\n  default: bad_action\n"))
	var buf bytes.Buffer
	err := cmd.ExecuteWithArgs([]string{"config", "validate", f}, &buf)
	if err == nil {
		t.Fatal("expected error for invalid policy, got nil")
	}
}

func TestConfigExplain(t *testing.T) {
	var buf bytes.Buffer
	err := cmd.ExecuteWithArgs([]string{"config", "explain", policyPath(t, "default.yaml")}, &buf)
	if err != nil {
		t.Fatalf("config explain failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Rules") {
		t.Errorf("expected 'Rules' in output, got: %q", out)
	}
	if !strings.Contains(out, "Weights") {
		t.Errorf("expected 'Weights' in output, got: %q", out)
	}
}

func TestPolicyLint(t *testing.T) {
	var buf bytes.Buffer
	err := cmd.ExecuteWithArgs([]string{"policy", "lint", policyPath(t, "default.yaml")}, &buf)
	if err != nil {
		t.Fatalf("policy lint failed: %v", err)
	}
	if !strings.Contains(buf.String(), "OK") {
		t.Errorf("expected OK in output, got: %q", buf.String())
	}
}

func TestFingerprintScore_Clean(t *testing.T) {
	var buf bytes.Buffer
	err := cmd.ExecuteWithArgs([]string{"fingerprint", "score", fingerprintPath(t, "clean_chrome_131_linux.json")}, &buf)
	if err != nil {
		t.Fatalf("fingerprint score failed: %v", err)
	}
	if !strings.Contains(buf.String(), "TOTAL") {
		t.Errorf("expected TOTAL in output, got: %q", buf.String())
	}
}

func TestFingerprintScoreDir(t *testing.T) {
	var buf bytes.Buffer
	dir := repoRoot(t) + "/testdata/fingerprint"
	err := cmd.ExecuteWithArgs([]string{"fingerprint", "score-dir", dir}, &buf)
	if err != nil {
		t.Fatalf("fingerprint score-dir failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "TOTAL") {
		t.Errorf("expected TOTAL in output, got: %q", out)
	}
}

func policyPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "policies", name)
}

func fingerprintPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "testdata", "fingerprint", name)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod)")
		}
		dir = parent
	}
}

func writeTempFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(f, content, 0600); err != nil {
		t.Fatal(err)
	}
	return f
}
