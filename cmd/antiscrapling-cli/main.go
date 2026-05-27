package main

import (
	"os"

	"github.com/anti-scrapling/anti-scrapling/cmd/antiscrapling-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
