//go:build darwin

package sandbox

import (
	"context"
	"testing"

	"github.com/wmetcalf/blastbox/agent/internal/config"
)

func TestProbeDeniesUnderSeatbelt(t *testing.T) { sandboxProofs(t, Host{}, "seatbelt") }

func TestSeatbeltChildEnvIsMinimal(t *testing.T) {
	t.Setenv("SECRET_TOKEN", "leak")
	eng := config.Engine{Name: "x", Sandbox: "seatbelt", SelftestArgv: []string{"/bin/sh", "-c",
		`test "$HOME" = "$TMPDIR" && test "$LANG" = C && test -z "$SECRET_TOKEN"`}}
	if r := (Host{AgentBin: testAgentBin}).SelfTest(context.Background(), eng); !r.OK {
		t.Fatalf("env check inside seatbelt: %s", r.Reason)
	}
}
