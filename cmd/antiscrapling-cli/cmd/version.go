package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const Version = "0.1.0"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print CLI version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "antiscrapling-cli %s\n", Version)
		},
	}
}
