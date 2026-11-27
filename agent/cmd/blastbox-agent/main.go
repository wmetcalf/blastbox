// Command blastbox-agent is a credential-less pull worker agent.
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/wmetcalf/blastbox/agent/internal/agent"
)

// version is set by -ldflags "-X main.version=...".
var version = "dev"

const usage = `usage: blastbox-agent <command>
  run    --config P                 run the agent
  probe  --config P                 probe and self-test every engine; exit 1 if any is red
  enrol  --node-id ID --dir DIR     create node.key + node.csr for the CA host to sign
  renew  --config P                 request a certificate renewal now
  version`

func main() {
	runHelper(os.Args)
	agent.Version = version
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "version":
		fmt.Printf("blastbox-agent %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	case "run":
		os.Exit(cmdRun(args))
	case "probe":
		os.Exit(cmdProbe(args))
	case "enrol":
		os.Exit(cmdEnrol(args))
	case "renew":
		os.Exit(cmdRenew(args))
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}
