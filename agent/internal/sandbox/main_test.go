package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// testAgentBin is the blastbox-agent binary hosting __launch/__probe: BLASTBOX_AGENT_BIN, or
// built here (with the host toolchain) when unset.
var testAgentBin string

func TestMain(m *testing.M) {
	code := 1
	func() {
		testAgentBin = os.Getenv("BLASTBOX_AGENT_BIN")
		if testAgentBin == "" {
			dir, err := os.MkdirTemp("", "bb-agent-bin-")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			defer os.RemoveAll(dir)
			if real, err := filepath.EvalSymlinks(dir); err == nil {
				dir = real
			}
			testAgentBin = filepath.Join(dir, "blastbox-agent")
			cmd := exec.Command("go", "build", "-buildvcs=false", "-o", testAgentBin, "../../cmd/blastbox-agent")
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "build agent: %v\n%s", err, out)
				return
			}
		}
		code = m.Run()
	}()
	os.Exit(code)
}
