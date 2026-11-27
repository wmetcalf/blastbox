package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/wmetcalf/blastbox/agent/internal/agent"
	"github.com/wmetcalf/blastbox/agent/internal/config"
)

func loadConfig(name string, args []string) (*config.Config, int) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	path := fs.String("config", "", "path of the agent TOML config")
	if err := fs.Parse(args); err != nil {
		return nil, 2
	}
	if *path == "" || fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "usage: blastbox-agent %s --config PATH\n", name)
		return nil, 2
	}
	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "blastbox-agent:", err)
		return nil, 1
	}
	return cfg, 0
}

func cmdRun(args []string) int {
	cfg, code := loadConfig("run", args)
	if cfg == nil {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := agent.Run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "blastbox-agent:", err)
		return 1
	}
	return 0
}

func cmdProbe(args []string) int {
	cfg, code := loadConfig("probe", args)
	if cfg == nil {
		return code
	}
	return probeReport(os.Stdout, agent.New(cfg).CheckEngines(context.Background()))
}

func probeReport(w io.Writer, st []agent.EngineStatus) int {
	rc := 0
	for _, s := range st {
		v := "OK"
		if !s.OK {
			v, rc = "RED", 1
		}
		fmt.Fprintf(w, "%s: %s: %s\n", s.Name, v, s.Reason)
	}
	return rc
}
