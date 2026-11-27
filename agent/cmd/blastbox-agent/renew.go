package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/agent"
)

func cmdRenew(args []string) int {
	cfg, code := loadConfig("renew", args)
	if cfg == nil {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := agent.RenewNow(ctx, cfg, time.Now, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "blastbox-agent renew:", err)
		return 1
	}
	return 0
}
