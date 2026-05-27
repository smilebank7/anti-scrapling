package cmd

import (
	"io"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "antiscrapling-cli",
	Short: "Admin CLI for the anti-scrapling proxy",
	Long: `antiscrapling-cli is the administrative command-line interface for the
anti-scrapling reverse proxy. It provides tools for policy management,
token issuance/verification, and fingerprint scoring.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func ExecuteWithArgs(args []string, out io.Writer) error {
	rootCmd.SetOut(out)
	rootCmd.SetErr(out)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
	rootCmd.SetArgs(nil)
	return err
}

func init() {
	rootCmd.AddCommand(
		newVersionCmd(),
		newConfigCmd(),
		newTokenCmd(),
		newPolicyCmd(),
		newFingerprintCmd(),
	)
}
