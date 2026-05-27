package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/smilebank7/anti-scrapling/internal/signal/fingerprint"
	"github.com/smilebank7/anti-scrapling/internal/types"
	"github.com/spf13/cobra"
)

func newFingerprintCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "fingerprint",
		Short: "Browser fingerprint scoring",
	}
	c.AddCommand(newFingerprintScoreCmd(), newFingerprintScoreDirCmd())
	return c
}

func newFingerprintScoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "score <report.json>",
		Short: "Score a single fingerprint report JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return scoreFile(cmd, args[0])
		},
	}
}

func newFingerprintScoreDirCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "score-dir <dir>",
		Short: "Score all *.json fingerprint reports in a directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			matches, err := filepath.Glob(filepath.Join(args[0], "*.json"))
			if err != nil {
				return fmt.Errorf("glob: %w", err)
			}
			if len(matches) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "No *.json files found in %s\n", args[0])
				return nil
			}
			for _, path := range matches {
				fmt.Fprintf(cmd.OutOrStdout(), "=== %s ===\n", filepath.Base(path))
				if err := scoreFile(cmd, path); err != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "  ERROR: %v\n", err)
				}
				fmt.Fprintln(cmd.OutOrStdout())
			}
			return nil
		},
	}
}

func normalizeFixtureJSON(data []byte) ([]byte, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	normalizeSpeechVoices(root)
	normalizeHairlineResult(root)
	return json.Marshal(root)
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
		switch v := rawVoice.(type) {
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

func normalizeHairlineResult(root map[string]any) {
	hairline, ok := root["hairline"].(map[string]any)
	if !ok {
		return
	}
	legacyPass, ok := hairline["non_modernizr_result"].(bool)
	if !ok {
		return
	}
	if legacyPass {
		hairline["non_modernizr_result"] = 0
	} else {
		hairline["non_modernizr_result"] = 1
	}
}

func scoreFile(cmd *cobra.Command, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	data, err = normalizeFixtureJSON(data)
	if err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	var report types.FingerprintReport
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	signals, err := fingerprint.Score(report)
	if err != nil {
		return fmt.Errorf("score: %w", err)
	}

	out := cmd.OutOrStdout()
	total := 0
	for _, s := range signals {
		total += s.Score
		fmt.Fprintf(out, "  %-45s  +%d  %s\n", s.Name, s.Score, s.Reason)
	}

	if len(signals) == 0 {
		fmt.Fprintf(out, "  (no signals triggered)\n")
	}

	fmt.Fprintf(out, "  %-45s  %d\n", "TOTAL", total)
	return nil
}
