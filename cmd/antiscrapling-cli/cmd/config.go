package cmd

import (
	"fmt"
	"sort"

	"github.com/smilebank7/anti-scrapling/internal/policy"
	"github.com/smilebank7/anti-scrapling/internal/types"
	"github.com/spf13/cobra"
)

func newConfigCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Policy config management",
	}
	c.AddCommand(newConfigValidateCmd(), newConfigExplainCmd())
	return c
}

func newConfigValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <file>",
		Short: "Validate a policy YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := policy.Load(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "OK: %s is valid\n", args[0])
			return nil
		},
	}
}

func newConfigExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <file>",
		Short: "Pretty-print parsed policy rules, weights, and CEL expressions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := policy.Load(args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Policy file: %s\n", args[0])
			fmt.Fprintf(out, "Version:     %d\n", cfg.Version)
			fmt.Fprintf(out, "Default:     %s\n\n", cfg.Policy.Default)

			fmt.Fprintf(out, "Rules (%d):\n", len(cfg.Policy.Rules))
			for i, r := range cfg.Policy.Rules {
				fmt.Fprintf(out, "  [%d] %s  →  %s\n", i, r.Name, r.Action)
				if r.Reason != "" {
					fmt.Fprintf(out, "       reason: %s\n", r.Reason)
				}
				printMatch(out, r)
			}

			fmt.Fprintf(out, "\nScoring thresholds:\n")
			fmt.Fprintf(out, "  challenge >= %d\n", cfg.Scoring.ChallengeThreshold)
			fmt.Fprintf(out, "  deny      >= %d\n", cfg.Scoring.DenyThreshold)

			if len(cfg.Scoring.Weights) > 0 {
				fmt.Fprintf(out, "\nWeights (%d signals):\n", len(cfg.Scoring.Weights))
				keys := sortedKeys(cfg.Scoring.Weights)
				for _, k := range keys {
					fmt.Fprintf(out, "  %-45s %d\n", k, cfg.Scoring.Weights[k])
				}
			}

			fmt.Fprintf(out, "\nToken TTL:    %s\n", cfg.Token.TTL)
			fmt.Fprintf(out, "Token bind:   %v\n", cfg.Token.BindTo)
			return nil
		},
	}
}

func printMatch(out interface{ Write([]byte) (int, error) }, r types.PolicyRule) {
	if len(r.Match) == 0 {
		fmt.Fprintf(out, "       match:  (always)\n")
		return
	}
	for k, v := range r.Match {
		fmt.Fprintf(out, "       match:  %s = %v\n", k, v)
	}
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
