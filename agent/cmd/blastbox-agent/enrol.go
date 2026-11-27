package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/wmetcalf/blastbox/agent/internal/agent"
)

func cmdEnrol(args []string) int {
	fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	id := fs.String("node-id", "", "node id (CSR common name)")
	dir := fs.String("dir", "", "directory for node.key and node.csr (created 0700)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *id == "" || *dir == "" || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: blastbox-agent enrol --node-id ID --dir DIR")
		return 2
	}
	if err := agent.Enrol(*id, *dir, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "blastbox-agent enrol:", err)
		return 1
	}
	return 0
}
