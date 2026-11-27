// Package agent is the pull worker's main loop: startup checks, engine probes and self-tests,
// heartbeat, per-slot claim loops with back-off, shadow mode, crash recovery, online
// certificate renewal and a draining shutdown.
//
// Nothing here logs tokens, receipts, keys or input bytes.
package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/config"
	"github.com/wmetcalf/blastbox/agent/internal/runner"
	"github.com/wmetcalf/blastbox/agent/internal/sandbox"
	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

// Version is the agent's own version (set from main's ldflags).
var Version = "dev"

const (
	defHeartbeat = 30
	minHeartbeat = 10
	maxHeartbeat = 300
	skewWarn     = 60 * time.Second
)

// JobRunner runs one claimed job; *runner.Runner is the production implementation.
type JobRunner interface {
	Run(ctx context.Context, cl *wire.Client, eng config.Engine, c *wire.Claim, stateDir string) runner.Result
}

// Agent is one node agent. The exported fields are injection points; New fills the defaults.
type Agent struct {
	Cfg     *config.Config
	Version string
	Host    sandbox.Host
	Runner  JobRunner
	Log     *slog.Logger

	ProbeFn    func(context.Context, config.Engine) sandbox.ProbeResult
	SelfTestFn func(context.Context, config.Engine) sandbox.ProbeResult
	InsecureFn func() []string

	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) bool // false once ctx is done
	Rand  func() float64

	DrainGrace   time.Duration // added to the longest in-flight deadline (30 s)
	ReprobeEvery time.Duration // 10 min
	CertEvery    time.Duration // 5 min

	startedAt time.Time
	binSHA    string

	mu        sync.Mutex
	cl        *wire.Client
	notAfter  time.Time
	inflight  map[string]wire.HeartbeatJob
	recSet    map[string]bool // job ids left on disk by a previous run (and runner-refused ids)
	idLocks   map[string]*idLock
	maxDeadln time.Time

	engines []*engState
	tooOld  atomic.Bool
	hbReady chan struct{}
	hbOnce  sync.Once
	renewer *Renewer
	lock    *os.File // flock on <state_dir>/agent.lock, held for the life of Run
}

type engState struct {
	eng     config.Engine
	probeMu sync.Mutex // serialises probe runs
	mu      sync.Mutex
	ok      bool
	at      time.Time
	reason  string
	busy    int
	gen     int // bumped by markRed; a probe that started before a bump cannot make the engine claimable
}

// markRed makes the engine unclaimable at once (before any re-probe) and invalidates any probe
// already running.
func (e *engState) markRed(reason string) {
	e.mu.Lock()
	e.ok, e.reason = false, reason
	e.gen++
	e.mu.Unlock()
}

func (e *engState) claimable() bool { e.mu.Lock(); defer e.mu.Unlock(); return e.ok }

// New builds an Agent with production defaults. It touches neither the network nor the disk.
func New(cfg *config.Config) *Agent {
	a := &Agent{Cfg: cfg, Version: Version, Host: sandbox.HostFromConfig(cfg), hbReady: make(chan struct{}),
		inflight: map[string]wire.HeartbeatJob{}, recSet: map[string]bool{}, idLocks: map[string]*idLock{}}
	a.Log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	a.ProbeFn = func(ctx context.Context, e config.Engine) sandbox.ProbeResult { return a.Host.Probe(ctx, e) }
	a.SelfTestFn = func(ctx context.Context, e config.Engine) sandbox.ProbeResult { return a.Host.SelfTest(ctx, e) }
	a.InsecureFn = a.Host.InsecurityReasons
	a.Now = time.Now
	a.Sleep = realSleep
	a.Rand = rand.Float64
	a.DrainGrace, a.ReprobeEvery, a.CertEvery = 30*time.Second, 10*time.Minute, 5*time.Minute
	for _, e := range cfg.Engines {
		a.engines = append(a.engines, &engState{eng: e, reason: "not probed yet"})
	}
	return a
}

func realSleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (a *Agent) client() *wire.Client { a.mu.Lock(); defer a.mu.Unlock(); return a.cl }

// Run is the one-call entry point with production defaults.
func Run(ctx context.Context, cfg *config.Config) error { return New(cfg).Run(ctx) }

// EngineStatus is one engine's verdict.
type EngineStatus struct {
	Name   string
	OK     bool
	Reason string
}

// CheckEngines probes and self-tests every engine (updating claimability) and reports.
func (a *Agent) CheckEngines(ctx context.Context) []EngineStatus {
	out := make([]EngineStatus, 0, len(a.engines))
	for _, es := range a.engines {
		a.probeEngine(ctx, es, true)
		es.mu.Lock()
		out = append(out, EngineStatus{es.eng.Name, es.ok, es.reason})
		es.mu.Unlock()
	}
	return out
}

// probeEngine runs probe + selftest + host-insecurity checks. With wait=false it skips if a
// probe of this engine is already running.
func (a *Agent) probeEngine(ctx context.Context, es *engState, wait bool) {
	if wait {
		es.probeMu.Lock()
	} else if !es.probeMu.TryLock() {
		return
	}
	defer es.probeMu.Unlock()
	es.mu.Lock()
	g := es.gen
	es.mu.Unlock()
	ok, reason := a.evaluate(ctx, es.eng)
	es.mu.Lock()
	if es.gen != g && ok {
		ok, reason = false, "a sandbox failure happened during this probe; re-probing"
	}
	prev := es.ok
	es.ok, es.reason, es.at = ok, reason, a.Now()
	es.mu.Unlock()
	if ok != prev || !ok {
		lvl := slog.LevelInfo
		if !ok {
			lvl = slog.LevelWarn
		}
		a.Log.Log(ctx, lvl, "engine check", "engine", es.eng.Name, "ok", ok, "reason", reason)
	}
}

func (a *Agent) evaluate(ctx context.Context, eng config.Engine) (bool, string) {
	if eng.Sandbox == "nsjail" {
		if err := a.checkNsjailPin(); err != nil {
			return false, err.Error()
		}
		if r := a.InsecureFn(); len(r) > 0 {
			return false, "insecure nsjail host: " + strings.Join(r, ", ")
		}
	}
	pr := a.ProbeFn(ctx, eng)
	if !pr.OK {
		return false, "probe: " + pr.Reason
	}
	if len(eng.SelftestArgv) > 0 {
		sr := a.SelfTestFn(ctx, eng)
		if !sr.OK {
			return false, "selftest: " + sr.Reason
		}
	}
	return true, "probe and selftest ok"
}

// checkNsjailPin refuses an nsjail binary that is not the pinned one.
func (a *Agent) checkNsjailPin() error {
	n := a.Cfg.Nsjail
	if n == nil {
		return nil
	}
	sum, err := fileSHA256(n.Path)
	if err != nil {
		return fmt.Errorf("nsjail: %w", err)
	}
	if sum != n.SHA256 {
		return errors.New("nsjail binary does not match the pinned sha256")
	}
	return nil
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// startup runs the pre-flight: key/cert pair recovery, cert verification, nsjail pin, client.
func (a *Agent) startup(ctx context.Context) error {
	if a.Runner == nil {
		a.Runner = &runner.Runner{Host: a.Host, Logf: func(f string, args ...any) {
			a.Log.Info("runner", "msg", fmt.Sprintf(f, args...))
		}, SandboxFault: func(engine, reason string) {
			// Stop claiming on the engine NOW, before the failed job is reported.
			for _, es := range a.engines {
				if es.eng.Name == engine {
					es.markRed("sandbox failure: " + reason)
				}
			}
		}}
	}
	a.startedAt = a.Now()
	if p, err := os.Executable(); err == nil {
		if s, err := fileSHA256(p); err == nil {
			a.binSHA = s
		}
	}
	if promoted, err := RecoverPair(a.Cfg, a.Now()); err != nil {
		return fmt.Errorf("finishing an interrupted certificate swap: %w", err)
	} else if promoted {
		a.Log.Warn("completed an interrupted key+cert swap at startup")
	}
	caPEM, err := os.ReadFile(a.Cfg.CAFile)
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(a.Cfg.CertFile)
	if err != nil {
		return err
	}
	_, na, err := config.CheckNodeCert(certPEM, caPEM, a.Now())
	if err != nil {
		return fmt.Errorf("node certificate unusable: %w (run `blastbox-agent enrol` to get a new identity, or `blastbox-agent renew` while the old one is still valid)", err)
	}
	a.notAfter = na
	if err := a.checkNsjailPin(); err != nil {
		return err
	}
	cl, err := wire.New(a.Cfg, "blastbox-agent/"+a.Version)
	if err != nil {
		return err
	}
	a.cl = cl
	a.renewer = &Renewer{Cfg: a.Cfg, Now: a.Now}
	return nil
}

// resession replaces the client (dropping its token) and handshakes anew.
func (a *Agent) resession(ctx context.Context) error {
	cl, err := wire.New(a.Cfg, "blastbox-agent/"+a.Version)
	if err != nil {
		return err
	}
	if err := cl.Session(ctx); err != nil {
		return err
	}
	a.mu.Lock()
	a.cl = cl
	a.mu.Unlock()
	return nil
}

// Run runs the agent until ctx is cancelled (SIGTERM/SIGINT), then drains and returns nil.
func (a *Agent) Run(ctx context.Context) error {
	lk, err := lockStateDir(a.Cfg.StateDir)
	if err != nil {
		return err
	}
	a.lock = lk
	defer lk.Close()
	if err := a.startup(ctx); err != nil {
		return err
	}
	if err := a.client().Session(ctx); err != nil {
		a.Log.Warn("initial session failed; will retry", "err", err.Error())
	}
	a.snapshotRecovery()
	a.recoverJobs(ctx)
	for _, es := range a.engines {
		a.probeEngine(ctx, es, true)
	}

	bg, stopBG := context.WithCancel(context.Background()) // heartbeat, reprobe, cert, recovery
	jobsCtx, killJobs := context.WithCancel(context.Background())
	defer killJobs()
	var bgWG, slotWG sync.WaitGroup
	spawn := func(wg *sync.WaitGroup, f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
	spawn(&bgWG, func() { a.heartbeatLoop(bg) })
	spawn(&bgWG, func() { a.reprobeLoop(bg) })
	spawn(&bgWG, func() { a.certLoop(bg) })
	spawn(&bgWG, func() { a.recoverLoop(bg) })
	if a.Cfg.Claim {
		for _, es := range a.engines {
			for s := 0; s < es.eng.SlotCount(); s++ {
				es := es
				spawn(&slotWG, func() { a.slotLoop(ctx, jobsCtx, es) })
			}
		}
	} else {
		a.Log.Info("shadow mode: heartbeat and probes only, never claiming")
	}

	<-ctx.Done()
	a.Log.Info("shutting down: no new claims; draining in-flight jobs")
	a.drain(&slotWG, killJobs)
	stopBG()
	bgWG.Wait()
	return nil
}

// drain waits for the slot loops (each runs its job inline) up to the longest job deadline
// plus the grace; past that the jobs' context is cancelled so the runner tears them down.
func (a *Agent) drain(wg *sync.WaitGroup, kill context.CancelFunc) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	start := time.Now()
	for {
		a.mu.Lock()
		limit := a.maxDeadln
		a.mu.Unlock()
		if limit.Before(start) {
			limit = start
		}
		limit = limit.Add(a.DrainGrace)
		select {
		case <-done:
			return
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(limit) {
			a.Log.Error("drain timeout; cancelling in-flight jobs")
			kill()
			select {
			case <-done:
			case <-time.After(a.DrainGrace):
			}
			return
		}
	}
}

// ---- heartbeat ----

func clampHeartbeat(s int) time.Duration {
	if s <= 0 {
		s = defHeartbeat
	}
	if s < minHeartbeat {
		s = minHeartbeat
	}
	if s > maxHeartbeat {
		s = maxHeartbeat
	}
	return time.Duration(s) * time.Second
}

func (a *Agent) buildHeartbeat() wire.Heartbeat {
	hb := wire.Heartbeat{
		AgentVersion: a.Version, BinarySHA256: a.binSHA, GOOS: goos, GOARCH: goarch,
		StartedAt: rfc3339(a.startedAt),
	}
	a.mu.Lock()
	hb.CertNotAfter = rfc3339(a.notAfter)
	for _, j := range a.inflight {
		hb.InFlight = append(hb.InFlight, j)
	}
	a.mu.Unlock()
	for _, es := range a.engines {
		es.mu.Lock()
		// selftest_ok/selftest_at mean "probe AND selftest (if configured) passed, and when";
		// an engine without selftest_argv reports its probe result and probe time.
		hb.Engines = append(hb.Engines, wire.HeartbeatEngine{
			Name: es.eng.Name, Sandbox: es.eng.Sandbox, Floor: es.eng.FloorName(), Slots: es.eng.SlotCount(),
			Busy: es.busy, SelftestOK: es.ok, SelftestAt: rfc3339(es.at)})
		es.mu.Unlock()
	}
	return hb
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	interval := time.Duration(defHeartbeat) * time.Second
	attempt := 0
	for ctx.Err() == nil {
		sent := a.Now()
		resp, err := a.client().Heartbeat(ctx, a.buildHeartbeat())
		wait := interval
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			wait = a.errDelay(ctx, err, &attempt, "heartbeat")
			if wait > interval {
				wait = interval
			}
		} else {
			attempt = 0
			interval = clampHeartbeat(resp.HeartbeatS)
			wait = interval
			if resp.ServerTime > 0 {
				skew := time.Duration(resp.ServerTime*1e9)*time.Nanosecond - time.Duration(sent.UnixNano())
				if time.Duration(math.Abs(float64(skew))) > skewWarn {
					a.Log.Warn("server clock differs from ours", "skew_s", skew.Seconds())
				}
			}
			old := a.tooOld.Load()
			now := resp.MinAgentVersion != "" && semverLess(a.Version, resp.MinAgentVersion)
			a.tooOld.Store(now)
			if now && !old {
				a.Log.Error("agent is older than the control plane's minimum; claiming stopped",
					"version", a.Version, "min_agent_version", resp.MinAgentVersion)
			} else if !now && old {
				a.Log.Info("agent meets the minimum version again; claiming resumes")
			}
			a.hbOnce.Do(func() { close(a.hbReady) })
		}
		if !a.Sleep(ctx, wait) {
			return
		}
	}
}

// errDelay turns a wire error into the next delay (and logs it).
func (a *Agent) errDelay(ctx context.Context, err error, attempt *int, what string) time.Duration {
	if d, lvl, ok := classify(err); ok {
		a.Log.Log(ctx, lvl, what+" failed", "err", err.Error(), "retry_in_s", d.Seconds())
		return d
	}
	if errors.Is(err, wire.ErrUnauthorized) {
		if rerr := a.resession(ctx); rerr == nil {
			if *attempt == 0 {
				*attempt = 1
				a.Log.Info(what + ": session rejected; re-established")
				return 0
			}
		} else {
			a.Log.Warn(what+": session rejected and re-session failed", "err", rerr.Error())
		}
	}
	d := serverBackoff(*attempt, a.Rand())
	*attempt++
	a.Log.Warn(what+" failed", "err", err.Error(), "retry_in_s", d.Seconds())
	return d
}

// ---- probes ----

func (a *Agent) reprobeLoop(ctx context.Context) {
	for a.Sleep(ctx, a.ReprobeEvery) {
		for _, es := range a.engines {
			a.probeEngine(ctx, es, true)
		}
	}
}

// ---- crash recovery retry ----

func (a *Agent) recoverLoop(ctx context.Context) {
	for a.Sleep(ctx, 30*time.Second) {
		a.recoverJobs(ctx)
	}
}

// ---- certificate ----

func (a *Agent) certLoop(ctx context.Context) {
	for ctx.Err() == nil {
		a.renewer.Client = a.client()
		st, err := a.renewer.Step(ctx, false)
		switch {
		case err != nil && ctx.Err() == nil:
			a.Log.Warn("certificate renewal step failed", "err", err.Error())
		case st == RenewInstalled:
			a.Log.Info("renewed certificate installed; re-handshaking")
			a.afterInstall(ctx)
		case st == RenewSubmitted:
			a.Log.Info("certificate renewal requested; waiting for the CA to sign it")
		}
		if !a.Sleep(ctx, a.CertEvery) {
			return
		}
	}
}

func (a *Agent) afterInstall(ctx context.Context) {
	if err := a.resession(ctx); err != nil {
		a.Log.Error("re-handshake with the new certificate failed", "err", err.Error())
	}
	if raw, err := os.ReadFile(a.Cfg.CertFile); err == nil {
		if _, c, err := certPub(raw); err == nil {
			a.mu.Lock()
			a.notAfter = c.NotAfter
			a.mu.Unlock()
		}
	}
}

// ---- per-job-id exclusion between recovery and a live run ----

type idLock struct {
	mu   sync.Mutex
	refs int
}

// lockID takes the job id's lock and returns its unlock.
func (a *Agent) lockID(id string) func() {
	a.mu.Lock()
	l := a.idLocks[id]
	if l == nil {
		l = &idLock{}
		a.idLocks[id] = l
	}
	l.refs++
	a.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		a.mu.Lock()
		if l.refs--; l.refs == 0 {
			delete(a.idLocks, id)
		}
		a.mu.Unlock()
	}
}

// ---- claim loops ----

func (a *Agent) slotLoop(ctx, jobsCtx context.Context, es *engState) {
	select {
	case <-a.hbReady: // never claim before the control plane has acknowledged us (and its min version)
	case <-ctx.Done():
		return
	}
	attempt := 0
	for ctx.Err() == nil {
		if a.tooOld.Load() || !es.claimable() {
			if !a.Sleep(ctx, idleDelay) {
				return
			}
			continue
		}
		claim, err := a.client().Claim(ctx, es.eng.Name, nil)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if !a.Sleep(ctx, a.errDelay(ctx, err, &attempt, "claim")) {
				return
			}
			continue
		}
		attempt = 0
		if claim == nil {
			if !a.Sleep(ctx, idleDelay) {
				return
			}
			continue
		}
		a.runClaim(ctx, jobsCtx, es, claim)
	}
}

// runClaim runs one claimed job. The job id is registered in-flight before the runner creates
// its dir, so recovery never touches it.
//
// Known gap: a Claim request in flight when SIGTERM arrives is cancelled client-side; if the
// server had already assigned the job, it stays claimed until the server's reclaim sweep.
func (a *Agent) runClaim(ctx, jobsCtx context.Context, es *engState, c *wire.Claim) {
	if ctx.Err() != nil { // claimed as we were told to stop: hand it straight back
		rctx, cancel := context.WithTimeout(jobsCtx, 30*time.Second)
		defer cancel()
		if err := a.client().Release(rctx, c); err != nil {
			a.Log.Warn("could not release a claim taken during shutdown", "job", c.JobID, "err", err.Error())
		}
		return
	}
	start := a.Now()
	dl := start.Add(time.Duration(c.Run.DeadlineS) * time.Second)
	a.mu.Lock()
	if live, dup := a.inflight[c.JobID]; dup {
		a.mu.Unlock()
		if live.ClaimID == c.ClaimID {
			// The same claim handed over again: it is the live run's own; nothing to do.
			a.Log.Warn("claim re-delivered for a job running here; ignored", "job", c.JobID)
			return
		}
		// The control plane re-issued a job this node is still running (its earlier claim was
		// reclaimed). The live run is left alone; the job reached a sandbox here, so the new
		// claim is failed, never run and never released.
		rctx, cancel := context.WithTimeout(jobsCtx, 2*time.Minute)
		defer cancel()
		err := a.client().Fail(rctx, c, "this node is still running the job under an earlier claim", a.Now())
		a.Log.Warn("claimed a job that is still running here; failed the new claim", "job", c.JobID, "err", fmt.Sprint(err))
		return
	}
	a.inflight[c.JobID] = wire.HeartbeatJob{JobID: c.JobID, ClaimID: c.ClaimID, StartedAt: rfc3339(start), DeadlineAt: rfc3339(dl)}
	if t := time.Now().Add(time.Duration(c.Run.DeadlineS) * time.Second); t.After(a.maxDeadln) {
		a.maxDeadln = t
	}
	a.mu.Unlock()
	es.mu.Lock()
	es.busy++
	es.mu.Unlock()
	// A recovery pass already settling this job id (and about to wipe its dir) finishes first.
	a.lockID(c.JobID)()

	res := a.Runner.Run(jobsCtx, a.client(), es.eng, c, a.Cfg.StateDir)

	es.mu.Lock()
	es.busy--
	es.mu.Unlock()
	a.mu.Lock()
	delete(a.inflight, c.JobID)
	a.mu.Unlock()
	a.Log.Info("job finished", "job", c.JobID, "engine", es.eng.Name, "outcome", res.Outcome)
	switch {
	case res.Keep:
		// The terminal report went unanswered: recovery retries it from the kept dir.
		a.Log.Warn("job report not delivered; left to recovery", "job", c.JobID)
		a.addRecovery(c.JobID)
	case res.Outcome == "refused":
		// A job dir already held a started marker: it now belongs to crash recovery.
		a.Log.Warn("runner refused a claim whose job dir holds a started marker; left to recovery", "job", c.JobID)
		a.addRecovery(c.JobID)
	}
	if res.SandboxFailure {
		// Stop claiming NOW, then re-probe (queued behind any probe already running) -- whether
		// or not the report was delivered. A sandbox that could not even be built is released,
		// not failed, but is the same host fault.
		es.markRed("sandbox failure: " + res.Reason)
		a.probeEngine(jobsCtx, es, true)
	}
}
