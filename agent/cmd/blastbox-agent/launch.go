package main

import (
	"fmt"
	"os"

	"github.com/wmetcalf/blastbox/agent/internal/sandbox"
)

// runHelper handles the agent's re-exec helper subcommands. It returns false if args is not one.
func runHelper(args []string) bool {
	if len(args) < 2 {
		return false
	}
	switch args[1] {
	case "__launch":
		err := sandbox.RunLaunch(args[2:])
		fmt.Fprintln(os.Stderr, "blastbox-agent __launch:", err) // Exec only returns on error
		os.Exit(126)
	case "__probe":
		os.Exit(sandbox.RunProbe(args[2:], os.Stdout))
	}
	return false
}
