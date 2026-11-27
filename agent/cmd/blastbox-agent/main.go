// Command blastbox-agent is a credential-less pull worker agent.
package main

import (
	"fmt"
	"os"
	"runtime"
)

// version is set by -ldflags "-X main.version=...".
var version = "dev"

func main() {
	runHelper(os.Args)
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		fmt.Printf("blastbox-agent %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: blastbox-agent version")
	os.Exit(2)
}
