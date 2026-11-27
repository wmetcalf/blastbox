package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/agent"
	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

func cmdRenew(args []string) int {
	cfg, code := loadConfig("renew", args)
	if cfg == nil {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := agent.RecoverPair(cfg, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "blastbox-agent renew:", err)
		return 1
	}
	cl, err := wire.New(cfg, "blastbox-agent/"+agent.Version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "blastbox-agent renew:", err)
		return 1
	}
	r := &agent.Renewer{Cfg: cfg, Client: cl}
	st, err := r.Step(ctx, true)
	if err == nil && st == agent.RenewSubmitted {
		fmt.Println("renewal requested; the CA host must sign the CSR")
		st, err = r.Step(ctx, false) // it may already be issued
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "blastbox-agent renew:", err)
		return 1
	}
	switch st {
	case agent.RenewInstalled:
		fmt.Println("new certificate installed; restart the agent to use it")
	default:
		fmt.Println("renewal pending; a running agent installs the certificate once issued, or re-run renew later")
	}
	return 0
}
