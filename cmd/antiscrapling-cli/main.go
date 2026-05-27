package main

import (
	"os"

	"github.com/smilebank7/anti-scrapling/cmd/antiscrapling-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
