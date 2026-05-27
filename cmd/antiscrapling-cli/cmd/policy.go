package cmd

import (
	"fmt"

	"github.com/anti-scrapling/anti-scrapling/internal/policy"
	"github.com/spf13/cobra"
)

func newPolicyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "policy",
		Short: "Policy analysis tools",
	}
	c.AddCommand(newPolicyLintCmd())
	return c
}

func newPolicyLintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lint <file>",
		Short: "Validate policy and check for shadowed rules",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := policy.Load(args[0])
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Lint: %s\n\n", args[0])

			evaluator, err := policy.NewEvaluator(cfg)
			if err != nil {
				return fmt.Errorf("compile error: %w", err)
			}
			_ = evaluator

			rules := cfg.Policy.Rules
			var warnings []string

			for i := 0; i < len(rules); i++ {
				for j := i + 1; j < len(rules); j++ {
					if rulesConflict(rules[i].Match, rules[j].Match) {
						warnings = append(warnings, fmt.Sprintf(
							"  WARNING: rule[%d] %q may shadow rule[%d] %q (identical match conditions)",
							i, rules[i].Name, j, rules[j].Name,
						))
					}
				}
			}

			if len(warnings) > 0 {
				fmt.Fprintf(out, "Reachability warnings:\n")
				for _, w := range warnings {
					fmt.Fprintln(out, w)
				}
				fmt.Fprintf(out, "\n%d warning(s) found\n", len(warnings))
			} else {
				fmt.Fprintf(out, "No shadowed rules detected.\n")
			}

			fmt.Fprintf(out, "Rules: %d  Default: %s\n", len(rules), cfg.Policy.Default)
			fmt.Fprintf(out, "OK\n")
			return nil
		},
	}
}

func rulesConflict(a, b map[string]any) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			return false
		}
		if fmt.Sprintf("%v", va) != fmt.Sprintf("%v", vb) {
			return false
		}
	}
	return true
}
