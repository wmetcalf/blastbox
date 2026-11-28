package main

import (
	"strings"
	"testing"

	"github.com/wmetcalf/blastbox/agent/internal/agent"
)

func TestProbeReportExitCode(t *testing.T) {
	var b strings.Builder
	if rc := probeReport(&b, []agent.EngineStatus{{Name: "a", OK: true, Reason: "ok"}}); rc != 0 {
		t.Fatal(rc)
	}
	b.Reset()
	rc := probeReport(&b, []agent.EngineStatus{{Name: "a", OK: true}, {Name: "b", OK: false, Reason: "probe: x"}})
	if rc != 1 || !strings.Contains(b.String(), "b: RED: probe: x") || !strings.Contains(b.String(), "a: OK") {
		t.Fatal(rc, b.String())
	}
}

func TestModemSoundFlagOnlyOnRun(t *testing.T) {
	if _, _, code := loadConfigFlags("run", []string{"--modem-sound", "--config", "/nonexistent"}, true); code != 1 {
		t.Fatalf("run must accept --modem-sound (then fail on the config), got %d", code)
	}
	if _, _, code := loadConfigFlags("probe", []string{"--modem-sound", "--config", "/nonexistent"}, false); code != 2 {
		t.Fatalf("probe must reject --modem-sound, got %d", code)
	}
}
