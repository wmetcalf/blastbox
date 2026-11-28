// Package runner runs ONE claimed job: fetch its input, run the engine under its sandbox with a
// hard deadline and a memory watchdog, tar the output deterministically, upload it, and always
// wipe the job directory. A job is released only while no sandbox has seen its input; after the
// `started` marker it is failed, never released.
package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/canon"
	"github.com/wmetcalf/blastbox/agent/internal/config"
	"github.com/wmetcalf/blastbox/agent/internal/sandbox"
	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

// Result is what happened to the claim, for logging and heartbeat use.
type Result struct {
	Outcome string // "done" | "failed" | "released" | "lost" | "refused" (a started job dir exists; nothing was sent or wiped)
	Reason  string
	// SandboxFailure: the sandbox could not be built, started or shown to have confined (and
	// cleaned up) the run. The engine must stop claiming until a probe passes again.
	SandboxFailure bool
	// Keep: the terminal report (fail, release or the result upload) was never answered, so
	// the job dir is kept, intact, for crash recovery to retry; it is not wiped.
	Keep bool
	// Unswept: processes of this (seatbelt) run could not be shown gone; recovery keeps trying
	// to stop them, and the engine must not claim until it has.
	Unswept bool
	// Unrecorded (with Keep): the undelivered report was for a claim whose claim.json never
	// reached disk, so crash recovery has nothing to retry it from. The host must retry it:
	// a release, or a fail with PendingFail as its reason.
	Unrecorded  bool
	PendingFail string
}

// Files a job dir may hold besides in/ out/ scratch/ (crash recovery reads them).
const (
	ResultTarName  = "result.tar"
	ResultMetaName = "result.json"  // the upload's headers, so recovery can replay it
	ReportedName   = "reported"     // the control plane answered the upload (200): nothing left to send
	UploadedName   = "uploaded"     // the upload was accepted (202): only replay the PUT or poll, never fail/release
	RunRecordName  = "sandbox.json" // the running sandbox's identity (sandbox.RunRecord)
)

// ResultRecord is result.json.
type ResultRecord struct {
	WorkerRuntime string `json:"worker_runtime"`
	StartedAtMs   int64  `json:"started_at_ms"`
	FinishedAtMs  int64  `json:"finished_at_ms"`
}

// Blastbox's default output caps, used when a claim carries none.
const (
	defMaxMetadata       = 4 << 20
	defMaxArtifact       = 50 << 20
	defMaxTotalArtifacts = 500 << 20
	defMaxArtifacts      = 1000
	tarMemberSlack       = 64 // node_claim.put_result: max_members = max_artifacts + 64
	maxDirs              = 4096
	maxParamValue        = 4096 // characters, as dispatch._MAX_ENV_VALUE_LEN
	metadataName         = "metadata.json"
)

var (
	badNameRE = regexp.MustCompile(`[^A-Za-z0-9._-]`)
)

// Runner holds the host-level settings shared by every job. The zero value works with
// sandbox.DefaultHost.
type Runner struct {
	Host sandbox.Host
	// Logf receives one line per decision; nil = the standard logger.
	Logf func(format string, args ...any)
	// SandboxFault, if set, is called as soon as a run's sandbox fails (before the job is
	// reported), so the host can stop claiming on that engine at once.
	// unswept: processes of the run could not be shown gone.
	SandboxFault func(engine, jobID, reason string, unswept bool)

	// Tunables (zero = production defaults); tests shorten them.
	MemPoll     time.Duration                 // memory watchdog period (500 ms)
	DispWait    time.Duration                 // how long to poll Disposition after an "accepted" (60 s)
	DispPoll    time.Duration                 // Disposition poll period (2 s)
	RetryBase   time.Duration                 // first retry delay for Fail/PutResult on a retryable error (2 s)
	RetryTries  int                           // attempts for Fail/PutResult (3)
	ReportWait  time.Duration                 // bound on one fail/release report, retries included (2 min)
	UploadWait  time.Duration                 // bound on one result upload, retries included (DefaultUploadWait)
	rss         func(pgid int) (int64, error) // test seam; nil = groupRSSKiB (plus the run's escapees)
	build       func(context.Context, sandbox.Kind, sandbox.Request, []string, sandbox.Limits) (*exec.Cmd, error)
	hostPins    *sandbox.HostPins
	sweep       func(sandbox.RunIdentity) (int, error) // test seam; nil = sandbox.SweepRun
	skipAAProbe bool
}

// Run runs one claim with the default Runner built from sandbox.DefaultHost.
func Run(ctx context.Context, cl *wire.Client, eng config.Engine, c *wire.Claim, stateDir string) Result {
	return (&Runner{Host: sandbox.DefaultHost}).Run(ctx, cl, eng, c, stateDir)
}

func (r *Runner) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func def(d, v time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return v
}

// job carries the per-run state.
type job struct {
	r      *Runner
	cl     *wire.Client
	c      *wire.Claim
	eng    config.Engine
	dir    string
	in     string
	out    string
	scr    string
	start  time.Time
	inPath string
	ident  sandbox.RunIdentity // seatbelt: names the run's processes for the sweep and the watchdog
	// recorded: claim.json is on disk, so crash recovery can retry an undelivered report.
	recorded bool
}

// Run is the state machine of the design (§6.4, §6.5):
//
//	network != none                -> release
//	input fetch / sandbox setup    -> release (nothing has seen the input in a sandbox)
//	started marker (fsync) ...     -> from here: never released
//	deadline / memory / bad exit   -> fail
//	limits / non-regular output    -> fail
//	tar + PUT result               -> done | failed | lost
func (r *Runner) Run(ctx context.Context, cl *wire.Client, eng config.Engine, c *wire.Claim, stateDir string) (res Result) {
	j := &job{r: r, cl: cl, c: c, eng: eng}
	defer func() { r.logf("job %s: %s %s", c.JobID, res.Outcome, res.Reason) }()

	if c.Run.DeadlineS <= 0 {
		return j.release(ctx, fmt.Sprintf("run.deadline_s is %d, not positive", c.Run.DeadlineS))
	}
	if c.Run.Network != "none" {
		return j.release(ctx, fmt.Sprintf("run.network is %q, not none", c.Run.Network))
	}
	env, err := r.paramEnv(c.JobID, eng, c.Run.Params)
	if err != nil {
		return j.fail(ctx, "invalid run params: "+err.Error())
	}
	kind, err := kindOf(eng)
	if err != nil {
		return j.release(ctx, err.Error())
	}
	base, err := filepath.EvalSymlinks(stateDir)
	if err != nil {
		return j.release(ctx, "state dir: "+err.Error())
	}
	jobs := filepath.Join(base, "jobs")
	if err := os.MkdirAll(jobs, 0o700); err != nil {
		return j.release(ctx, "state dir: "+err.Error())
	}
	j.dir = filepath.Join(jobs, c.JobID)
	if _, err := os.Lstat(filepath.Join(j.dir, "started")); err == nil {
		// A started job's dir belongs to crash recovery: never wipe or reuse it here. The job
		// reached a sandbox on this node (under an earlier claim), so this new claim is failed
		// -- never released, never run -- or it would stay RUNNING until the reclaim sweep.
		why := "job dir already holds a started marker; left for crash recovery"
		fr := j.fail(ctx, "this node already started the job under an earlier claim")
		return Result{Outcome: "refused", Reason: why + " (new claim: " + fr.Outcome + ")",
			Unrecorded: fr.Unrecorded, PendingFail: fr.PendingFail}
	}
	if _, err := os.Lstat(j.dir); err == nil { // leftover of an earlier, unstarted attempt
		wipe(j.dir)
	}
	if err := os.Mkdir(j.dir, 0o700); err != nil {
		return j.release(ctx, "job dir: "+err.Error())
	}
	defer func() {
		if !res.Keep {
			wipe(j.dir)
		}
	}()
	j.in, j.out, j.scr = filepath.Join(j.dir, "in"), filepath.Join(j.dir, "out"), filepath.Join(j.dir, "scratch")
	for _, d := range []string{j.in, j.out, j.scr} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return j.release(ctx, "job dir: "+err.Error())
		}
	}
	claimJSON, _ := json.Marshal(map[string]any{
		"job_id": c.JobID, "claim_id": c.ClaimID, "receipt": c.Receipt, "engine": eng.Name, "started": false,
		"claimed_at_ms": claimedMs(c)})
	// Durable before the started marker: recovery needs the claim to settle a started job.
	if err := atomicWrite(filepath.Join(j.dir, "claim.json"), claimJSON); err != nil {
		return j.release(ctx, "claim.json: "+err.Error())
	}
	j.recorded = true

	j.inPath = filepath.Join(j.in, sanitiseName(c.Run.Input.Filename))
	argv, err := template(eng.Argv, map[string]string{"input": j.inPath, "out": j.out, "scratch": j.scr})
	if err != nil {
		return j.release(ctx, "argv template: "+err.Error())
	}
	if _, err := cl.FetchInput(ctx, c, j.inPath); err != nil {
		return j.releaseOrLost(ctx, "input: "+err.Error(), err)
	}

	// Build the sandboxed command BEFORE the started marker: a sandbox that cannot be built
	// (insecure nsjail host, missing binary) has not seen the input.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd, nonce, err := j.command(runCtx, kind, argv, env)
	if err != nil {
		why := "sandbox: " + err.Error()
		return j.sandboxFault(why, func() Result { return j.release(ctx, why) })
	}
	var capw *capWriter
	if eng.Output == "stdout-envelope" {
		capw = newCapWriter(orDef(c.Run.Limits.MaxMetadata, defMaxMetadata))
		cmd.Stdout = capw
	}
	tail := &tailWriter{max: 4096}
	cmd.Stderr = tail

	if err := writeStarted(j.dir); err != nil {
		return j.release(ctx, "started marker: "+err.Error())
	}
	// From here the job is never released.
	claimJSON, _ = json.Marshal(map[string]any{
		"job_id": c.JobID, "claim_id": c.ClaimID, "receipt": c.Receipt, "engine": eng.Name, "started": true,
		"claimed_at_ms": claimedMs(c)})
	if err := atomicWrite(filepath.Join(j.dir, "claim.json"), claimJSON); err != nil {
		r.logf("job %s: claim.json rewrite: %v (the started marker is authoritative)", c.JobID, err)
	}
	j.start = time.Now()
	killed, runErr := j.exec(runCtx, cmd, capw)
	if errors.Is(runErr, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success() {
		// The engine exited 0, but something it left held its stdout/stderr open past WaitDelay
		// (Wait reports that only for a successful exit). The leftover is killed with the group
		// and swept below; the run is judged by the engine's own status.
		runErr = nil
	}
	// A seatbelt child that setsid()s leaves the process group, so the group kill above cannot
	// reach it: find the run's processes by their sandbox and kill them BEFORE anything reads
	// the output (a survivor could still be rewriting it) and whatever the run's outcome.
	if j.ident.Canary != "" {
		sweep := r.sweep
		if sweep == nil {
			sweep = sandbox.SweepRun
		}
		n, err := sweep(j.ident)
		if err != nil {
			why := "sandbox: escaped processes not shown gone: " + err.Error()
			res := j.sandboxFaultU(why, true, func() Result { return j.fail(ctx, why) })
			// Keep the dir and its run record: recovery retries the kill until the run is gone.
			res.Keep, res.Unswept = true, true
			return res
		}
		if n > 0 {
			r.logf("job %s: killed %d process(es) that escaped the run's process group", c.JobID, n)
		}
	}
	if killed != "" {
		return j.fail(ctx, killed)
	}
	if capw != nil && capw.overflowed() {
		return j.fail(ctx, "envelope over max_metadata")
	}
	var ee *exec.ExitError
	if runErr != nil && killed == "" && !errors.As(runErr, &ee) {
		// Nothing ran (the sandbox binary could not be started, the run record could not be
		// written): say so, rather than "not confined".
		why := "engine did not run: " + runErr.Error()
		return j.sandboxFault(why, func() Result { return j.fail(ctx, why) })
	}
	if !handshakeOK(j.scr, nonce) {
		r.logf("job %s: sandbox stderr tail: %q", c.JobID, tail.String())
		why := "sandbox handshake missing: the run was not confined"
		return j.sandboxFault(why, func() Result { return j.fail(ctx, why) })
	}
	if runErr != nil {
		r.logf("job %s: engine stderr tail: %q", c.JobID, tail.String())
		if errors.As(runErr, &ee) {
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				return j.fail(ctx, "engine killed by signal "+ws.Signal().String())
			}
			return j.fail(ctx, fmt.Sprintf("engine exited with status %d", ee.ExitCode()))
		}
		why := "engine did not run: " + runErr.Error()
		return j.sandboxFault(why, func() Result { return j.fail(ctx, why) })
	}

	if capw != nil {
		b := capw.bytes()
		if len(b) == 0 {
			return j.fail(ctx, "engine produced no envelope")
		}
		if err := os.WriteFile(filepath.Join(j.out, metadataName), b, 0o600); err != nil {
			return j.fail(ctx, "envelope: "+err.Error())
		}
	}
	files, err := j.checkOutput()
	if err != nil {
		return j.fail(ctx, err.Error())
	}
	if err := j.fillArtifacts(files); err != nil {
		return j.fail(ctx, err.Error())
	}
	fi, err := os.Lstat(filepath.Join(j.out, metadataName))
	if err != nil || fi.Size() > orDef(c.Run.Limits.MaxMetadata, defMaxMetadata) {
		return j.fail(ctx, "metadata.json over max_metadata")
	}
	// metadata.json has its own cap above and does not count toward max_total_artifacts: the
	// control plane's vet_tar, its extractor and the cold trust gate all exclude it.
	var total int64
	for rel, n := range files {
		if rel != metadataName {
			total += n
		}
	}
	if maxTotal := orDef(c.Run.Limits.MaxTotalArtifacts, defMaxTotalArtifacts); total > maxTotal {
		return j.fail(ctx, fmt.Sprintf("artifacts total %d is over max_total_artifacts (%d)", total, maxTotal))
	}
	tarPath := filepath.Join(j.dir, ResultTarName)
	if err := Write(j.out, tarPath); err != nil {
		return j.fail(ctx, "output tree refused: "+err.Error())
	}
	return j.upload(ctx, tarPath, kind)
}

// sandboxFault tells the host at once (so the engine stops claiming before the report, which may
// take minutes against a struggling control plane), then reports and flags the result.
func (j *job) sandboxFault(why string, report func() Result) Result {
	return j.sandboxFaultU(why, false, report)
}

func (j *job) sandboxFaultU(why string, unswept bool, report func() Result) Result {
	if f := j.r.SandboxFault; f != nil {
		f(j.eng.Name, j.c.JobID, why, unswept)
	}
	res := report()
	res.SandboxFailure = true
	return res
}

func orDef(v, d int64) int64 {
	if v > 0 {
		return v
	}
	return d
}

func kindOf(eng config.Engine) (sandbox.Kind, error) {
	switch eng.Sandbox {
	case "seatbelt":
		return sandbox.Seatbelt, nil
	case "nsjail":
		return sandbox.Nsjail, nil
	}
	return "", fmt.Errorf("engine %q has sandbox %q: the agent will not run an unsandboxed engine", eng.Name, eng.Sandbox)
}

func sanitiseName(n string) string {
	n = badNameRE.ReplaceAllString(filepath.Base(strings.ReplaceAll(n, "\\", "/")), "_")
	n = strings.TrimLeft(n, ".")
	if len(n) > 100 {
		n = n[:100]
	}
	if n == "" {
		return "input"
	}
	return n
}

// template expands {input} {out} {scratch}; any other {...}, or a stray brace, is an error.
func template(argv []string, vars map[string]string) ([]string, error) {
	out := make([]string, len(argv))
	for i, a := range argv {
		var b strings.Builder
		for k := 0; k < len(a); {
			switch a[k] {
			case '{':
				e := strings.IndexByte(a[k:], '}')
				if e < 0 {
					return nil, fmt.Errorf("unterminated { in %q", a)
				}
				name := a[k+1 : k+e]
				v, ok := vars[name]
				if !ok {
					return nil, fmt.Errorf("unknown placeholder {%s}", name)
				}
				b.WriteString(v)
				k += e + 1
			case '}':
				return nil, fmt.Errorf("stray } in %q", a)
			default:
				b.WriteByte(a[k])
				k++
			}
		}
		out[i] = b.String()
	}
	return out, nil
}

// Keys a job may never set, whatever the engine's allowlist says: the dispatcher's
// engine-agnostic floor (dispatch._RESERVED_ENV_PREFIXES/_KEYS: framework, loader, interpreter,
// executable and shell resolution) plus DYLD_, the macOS loader's LD_.
var (
	reservedParamPrefixes = []string{"BLASTBOX_", "LD_", "DYLD_", "PYTHON"}
	reservedParamKeys     = map[string]bool{"PATH": true, "IFS": true}
)

func reservedParam(eng config.Engine, k string) bool {
	if reservedParamKeys[k] {
		return true
	}
	for _, p := range reservedParamPrefixes {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	for _, r := range eng.ReservedParamKeys {
		if k == r {
			return true
		}
	}
	return false
}

// paramEnv turns run.params into extra child env, filtered as the dispatcher's
// _sanitize_params filters them: a key must match ^[A-Z][A-Z0-9_]{0,63}$, must not be reserved
// (the floor above, or the engine's reserved_param_keys) and, when the engine sets param_keys,
// must be in it; a value is cut to 4096 characters and one holding NUL is dropped. Anything
// else is dropped (and logged), not fatal:
// the push path runs such a job without the key, and so does this one. Nothing is forwarded
// unless the engine opts in (default true).
func (r *Runner) paramEnv(jobID string, eng config.Engine, params map[string]any) (map[string]string, error) {
	env := map[string]string{}
	if len(params) == 0 || !eng.ForwardParams() {
		return env, nil
	}
	var allow map[string]bool
	if eng.ParamKeys != nil {
		allow = map[string]bool{}
		for _, k := range *eng.ParamKeys {
			allow[k] = true
		}
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch {
		case !config.ParamKeyRE.MatchString(k):
			r.logf("job %s: dropping param %+q: not ^[A-Z][A-Z0-9_]{0,63}$", jobID, k)
			continue
		case reservedParam(eng, k):
			r.logf("job %s: dropping reserved param %+q", jobID, k)
			continue
		case allow != nil && !allow[k]:
			r.logf("job %s: dropping param %+q: not in the engine's param_keys", jobID, k)
			continue
		}
		var v string
		switch t := params[k].(type) {
		case string:
			v = t
		case nil:
			v = ""
		case bool:
			v = strconv.FormatBool(t)
		case float64:
			v = strconv.FormatFloat(t, 'f', -1, 64)
		case json.Number:
			v = t.String()
		default:
			b, err := json.Marshal(t)
			if err != nil {
				return nil, fmt.Errorf("param %q: %v", k, err)
			}
			v = string(b)
		}
		if strings.ContainsRune(v, 0) {
			r.logf("job %s: dropping param %+q: value holds NUL", jobID, k)
			continue
		}
		if rs := []rune(v); len(rs) > maxParamValue {
			r.logf("job %s: truncating param %+q to %d characters", jobID, k, maxParamValue)
			v = string(rs[:maxParamValue])
		}
		env[k] = v
	}
	return env, nil
}

func (j *job) command(ctx context.Context, kind sandbox.Kind, argv []string, env map[string]string) (*exec.Cmd, string, error) {
	h := j.r.Host
	agent := h.AgentBin
	exe := argv[0]
	if !filepath.IsAbs(exe) {
		lp, err := exec.LookPath(exe)
		if err != nil {
			return nil, "", err
		}
		exe = lp
	}
	exe, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return nil, "", err
	}
	var ro []string
	for _, p := range j.eng.ROPaths {
		rp, err := filepath.EvalSymlinks(p)
		if err != nil {
			return nil, "", err
		}
		ro = append(ro, rp)
	}
	ro = append(ro, j.in) // the input is read-only to the engine
	rw := []string{}
	if j.eng.Output == "dir" {
		rw = append(rw, j.out)
	}
	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		return nil, "", err
	}
	nonce := hex.EncodeToString(nb)
	var canary string
	if kind == sandbox.Seatbelt {
		if canary, err = sandbox.NewCanary(); err != nil {
			return nil, "", err
		}
		j.ident = sandbox.RunIdentity{Scratch: j.scr, Canary: canary, StartedAfter: time.Now().Add(-time.Second)}
	}
	req := sandbox.Request{
		ExecPaths: []string{exe}, ROPaths: ro, RWPaths: rw, Accelerators: j.eng.Accelerators,
		Scratch: j.scr, Canary: canary, Nonce: nonce, Env: env, AgentBin: agent,
		NsjailPath: h.NsjailPath, SeccompPolicy: h.SeccompPolicy,
		AppArmorProfile: h.AppArmorProfile, AllowMissingAppArmor: h.AllowMissingAppArmor,
		Pins: j.r.hostPins,
	}
	if kind == sandbox.Nsjail && !j.r.skipAAProbe {
		req.AttachAppArmor = h.AttachAppArmor()
	}
	lim := sandbox.Limits{
		TimeoutS:   int64(j.c.Run.DeadlineS),
		FSizeBytes: uint64(max(orDef(j.c.Run.Limits.MaxArtifact, defMaxArtifact), orDef(j.c.Run.Limits.MaxMetadata, defMaxMetadata))),
	}
	build := j.r.build
	if build == nil {
		build = sandbox.Command
	}
	cmd, err := build(ctx, kind, req, argv, lim)
	return cmd, nonce, err
}

// exec starts cmd and supervises it. killed is a non-empty failure reason when the agent had to
// stop the run (deadline, memory, envelope cap, shutdown).
func (j *job) exec(ctx context.Context, cmd *exec.Cmd, capw *capWriter) (killed string, runErr error) {
	// The run is recorded so that, if this agent dies or gives up draining, the next one can stop
	// it before settling its job (it would otherwise outlive the agent unsupervised). A seatbelt
	// run's sweep identity is known before it starts, so it is recorded first: a crash between
	// Start and the pid's record still leaves a way to find the run. A run that cannot be
	// recorded is not started (or is killed at once).
	rec := sandbox.RunRecord{Scratch: j.ident.Scratch, Canary: j.ident.Canary,
		NotAfter: time.Now().Add(time.Duration(j.c.Run.DeadlineS)*time.Second + time.Minute).Unix()}
	if j.ident.Canary != "" {
		rec.StartedAfter = j.ident.StartedAfter.UnixMicro()
	}
	writeRec := func() error {
		b, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return atomicWrite(filepath.Join(j.dir, RunRecordName), b)
	}
	if err := writeRec(); err != nil {
		return "", fmt.Errorf("start: run record: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start: %w", err)
	}
	pid := cmd.Process.Pid
	rec.PID = pid
	rec.Identity, _ = sandbox.ProcIdentity(pid)
	if err := writeRec(); err != nil {
		syscall.Kill(-pid, syscall.SIGKILL)
		err2 := cmd.Wait()
		_ = err2
		return "run record could not be written: " + err.Error(), nil
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Duration(j.c.Run.DeadlineS) * time.Second
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	tick := time.NewTicker(def(j.r.MemPoll, 500*time.Millisecond))
	defer tick.Stop()
	limit := int64(j.eng.RSSLimitMiB()) << 10 // KiB
	var overflow <-chan struct{}
	if capw != nil {
		overflow = capw.over
	}
	kill := func(reason string) {
		killed = reason
		syscall.Kill(-pid, syscall.SIGKILL)
	}
	rssFails := 0
	rssFn := j.r.rss
	if rssFn == nil {
		rssFn = func(pgid int) (int64, error) { return groupRSSKiB(pgid, j.ident.Match) }
	}
	for {
		select {
		case err := <-done:
			syscall.Kill(-pid, syscall.SIGKILL) // reap strays left in the group
			if killed == "" && ctx.Err() != nil {
				// exec.CommandContext's Cancel killed the group before our select saw Done.
				killed = "run interrupted: agent shutting down"
			}
			return killed, err
		case <-timer.C:
			kill(fmt.Sprintf("deadline exceeded after %ds", j.c.Run.DeadlineS))
			err := <-done
			return killed, err
		case <-overflow:
			kill("envelope over max_metadata")
			err := <-done
			return killed, err
		case <-ctx.Done():
			kill("run interrupted: agent shutting down")
			err := <-done
			return killed, err
		case <-tick.C:
			rss, err := rssFn(pid)
			if err != nil {
				// Fail closed: with no other memory enforcement (darwin), a blind watchdog is
				// no watchdog.
				rssFails++
				j.r.logf("job %s: memory watchdog read failed (%d/3): %v", j.c.JobID, rssFails, err)
				if rssFails >= 3 {
					kill("memory watchdog unavailable")
					err := <-done
					return killed, err
				}
				continue
			}
			rssFails = 0
			if rss > limit {
				kill("memory cap exceeded")
				err := <-done
				return killed, err
			}
		}
	}
}

func handshakeOK(scratch, nonce string) bool {
	m := filepath.Join(scratch, sandbox.HandshakeName)
	fi, err := os.Lstat(m)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	b, err := os.ReadFile(m)
	os.Remove(m)
	return err == nil && string(b) == nonce
}

// atomicWrite replaces p with b durably: the data is synced before the rename and the
// directory after it.
func atomicWrite(p string, b []byte) error {
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	return syncDir(filepath.Dir(p))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// claimedMs is the claim's node-clock receipt time in ms (0 when unknown), kept in claim.json so
// a recovery Fail can clamp finished_at to it.
func claimedMs(c *wire.Claim) int64 {
	if c.ClaimedAt.IsZero() {
		return 0
	}
	return c.ClaimedAt.UnixMilli()
}

// MarkReported durably records that the control plane answered dir's result upload.
func MarkReported(dir string) error { return atomicWrite(filepath.Join(dir, ReportedName), nil) }

// MarkUploaded durably (fsync'd, with its directory) records that the control plane accepted
// dir's result upload with a 202. The server refuses release and fail from then on.
func MarkUploaded(dir string) error { return atomicWrite(filepath.Join(dir, UploadedName), nil) }

// writeStarted records, durably, that the sandbox is about to see the input.
func writeStarted(dir string) error {
	p := filepath.Join(dir, "started")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(strconv.FormatInt(time.Now().Unix(), 10) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

type outFile struct {
	rel  string
	size int64
}

// checkOutput walks out/ and enforces run.limits locally. Anything that is not a plain regular
// file with a single link is refused. The walk stops at the first violation, so a tree of
// millions of files is never fully scanned.
func (j *job) checkOutput() (map[string]int64, error) {
	lim := j.c.Run.Limits
	maxArt, maxTotal, maxN := orDef(lim.MaxArtifact, defMaxArtifact), orDef(lim.MaxTotalArtifacts, defMaxTotalArtifacts), orDef(lim.MaxArtifacts, defMaxArtifacts)
	maxMeta := orDef(lim.MaxMetadata, defMaxMetadata)
	files := map[string]int64{}
	var total, n, dirs int64
	err := filepath.WalkDir(j.out, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(j.out, p)
		if rel == "." {
			return nil
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if fi.IsDir() {
			if dirs++; dirs > maxDirs {
				return errors.New("too many directories in output")
			}
			return nil
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("non-regular file in output: %+q (%s)", rel, fi.Mode().Type())
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && uint64(st.Nlink) > 1 {
			return fmt.Errorf("hardlinked file in output: %+q", rel)
		}
		rel = filepath.ToSlash(rel)
		files[rel] = fi.Size()
		if rel == metadataName {
			if fi.Size() > maxMeta {
				return errors.New("metadata.json over max_metadata")
			}
			return nil
		}
		// The control plane's tar check allows max_artifacts + 64 members, metadata.json
		// included; max_artifacts itself bounds the DECLARED artifacts (in its trust gate).
		if n++; n+1 > maxN+tarMemberSlack {
			return fmt.Errorf("more than max_artifacts (%d) + %d tar members in output", maxN, tarMemberSlack)
		}
		if fi.Size() > maxArt {
			return fmt.Errorf("artifact %+q is over max_artifact (%d)", rel, maxArt)
		}
		if total += fi.Size(); total > maxTotal {
			return fmt.Errorf("output total is over max_total_artifacts (%d)", maxTotal)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, ok := files[metadataName]; !ok {
		return nil, errors.New("output has no metadata.json")
	}
	return files, nil
}

// fillArtifacts rewrites sha256 and bytes of the declared artifacts that exist in the output,
// nothing else, and only then. An envelope that declares no artifacts, or any envelope the
// agent cannot canonically re-serialise, is left byte-for-byte as the engine wrote it (the
// control plane re-seals anyway).
func (j *job) fillArtifacts(files map[string]int64) error {
	p := filepath.Join(j.out, metadataName)
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if !canon.Lossless(raw) {
		return nil // decoding would replace bytes with U+FFFD: leave the engine's bytes alone
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var env map[string]any
	if dec.Decode(&env) != nil || env == nil {
		return nil
	}
	arts, _ := env["artifacts"].([]any)
	changed := false
	for _, a := range arts {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		path, _ := m["path"].(string)
		clean := filepath.ToSlash(filepath.Clean(path))
		if path == "" || filepath.IsAbs(path) || clean == metadataName {
			continue
		}
		size, ok := files[clean]
		if !ok {
			continue
		}
		sum, err := fileSHA(filepath.Join(j.out, filepath.FromSlash(clean)))
		if err != nil {
			return fmt.Errorf("artifact %+q: %v", clean, err)
		}
		m["sha256"], m["bytes"] = sum, json.Number(strconv.FormatInt(size, 10))
		changed = true
	}
	if !changed {
		return nil
	}
	out, err := canon.Marshal(env)
	if err != nil {
		return nil // e.g. a float: leave the engine's bytes alone
	}
	return os.WriteFile(p, out, 0o600)
}

func fileSHA(p string) (string, error) {
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

// ---- reporting ----

func retryable(err error) bool {
	return errors.Is(err, wire.ErrServer) || errors.Is(err, wire.ErrTLS)
}

// Permanent reports whether the control plane refused a report for good (a 4xx other than
// 403/409/408/429, or a 404: no such job). Retrying it from a kept dir could never succeed.
func Permanent(err error) bool {
	return errors.Is(err, wire.ErrRejected) || errors.Is(err, wire.ErrNotFound)
}

func (r *Runner) retry(ctx context.Context, f func() error) error {
	tries := r.RetryTries
	if tries <= 0 {
		tries = 3
	}
	delay := def(r.RetryBase, 2*time.Second)
	var err error
	for i := 0; i < tries; i++ {
		if err = f(); err == nil || !retryable(err) {
			return err
		}
		if i < tries-1 {
			wait := delay
			var ra *wire.RetryAfterError
			if errors.As(err, &ra) && ra.After > wait {
				wait = ra.After // the control plane said how long it needs
			}
			select {
			case <-time.After(wait):
				delay *= 2
			case <-ctx.Done():
				return err
			}
		}
	}
	return err
}

// reportCtx outlives a cancelled run context: a job interrupted by shutdown must still be told
// to the control plane.
func (r *Runner) reportCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), def(r.ReportWait, 2*time.Minute))
}

// DefaultUploadWait bounds a result upload: the wire client's 30 min stream timeout for the
// body plus its 5 min wait for the control plane's answer (it extracts and fsyncs the tree
// before answering). The 2 min report bound would cut off any large tar on a slow uplink.
const DefaultUploadWait = 35 * time.Minute

// UploadContext is reportCtx for a result upload (and its disposition poll).
func (r *Runner) UploadContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), def(r.UploadWait, DefaultUploadWait))
}

func (j *job) release(ctx context.Context, why string) Result {
	rc, cancel := j.r.reportCtx(ctx)
	defer cancel()
	return j.releaseOrLost2(rc, why, j.cl.Release(rc, j.c))
}

// releaseOrLost handles a step error that is itself the reason to release: a lost claim wins.
func (j *job) releaseOrLost(ctx context.Context, why string, cause error) Result {
	if errors.Is(cause, wire.ErrClaimLost) {
		return Result{Outcome: "lost", Reason: why}
	}
	return j.release(ctx, why)
}

func (j *job) releaseOrLost2(_ context.Context, why string, err error) Result {
	switch {
	case err == nil:
		return Result{Outcome: "released", Reason: why}
	case errors.Is(err, wire.ErrClaimLost):
		return Result{Outcome: "lost", Reason: why + "; release: " + err.Error()}
	case errors.Is(err, wire.ErrRefused), Permanent(err):
		return Result{Outcome: "failed", Reason: why + "; release refused: " + err.Error()}
	}
	return Result{Outcome: "failed", Reason: why + "; release not delivered: " + err.Error(), Keep: true,
		Unrecorded: !j.recorded}
}

// serverReason makes a reason safe to send: printable ASCII only, at most 200 chars.
func serverReason(s string) string {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b = append(b, byte(r))
		} else {
			b = append(b, '?')
		}
	}
	if len(b) > 200 {
		b = b[:200]
	}
	return string(b)
}

func (j *job) fail(ctx context.Context, why string) Result {
	why = serverReason(why)
	rc, cancel := j.r.reportCtx(ctx)
	defer cancel()
	err := j.r.retry(rc, func() error { return j.cl.Fail(rc, j.c, why, time.Now()) })
	switch {
	case err == nil:
		return Result{Outcome: "failed", Reason: why}
	case errors.Is(err, wire.ErrClaimLost):
		return Result{Outcome: "lost", Reason: why + "; fail: " + err.Error()}
	case errors.Is(err, wire.ErrRefused), Permanent(err):
		return Result{Outcome: "failed", Reason: why + "; fail refused: " + err.Error()}
	}
	return Result{Outcome: "failed", Reason: why + "; fail not delivered: " + err.Error(), Keep: true,
		Unrecorded: !j.recorded, PendingFail: pendingFail(j.recorded, why)}
}

func pendingFail(recorded bool, why string) string {
	if recorded {
		return ""
	}
	return why
}

func (j *job) upload(ctx context.Context, tarPath string, kind sandbox.Kind) Result {
	rc, cancel := j.r.UploadContext(ctx)
	defer cancel()
	meta := wire.ResultMeta{WorkerRuntime: string(kind), StartedAt: j.start, FinishedAt: time.Now()}
	// Recorded first: if the upload goes unanswered (or the agent dies), recovery replays the
	// same idempotent PUT rather than failing a job whose result exists.
	rec, _ := json.Marshal(ResultRecord{meta.WorkerRuntime, meta.StartedAt.UnixMilli(), meta.FinishedAt.UnixMilli()})
	if err := atomicWrite(filepath.Join(j.dir, ResultMetaName), rec); err != nil {
		return j.fail(ctx, "result record: "+err.Error())
	}
	var out wire.Outcome
	err := j.r.retry(rc, func() (e error) { out, e = j.cl.PutResult(rc, j.c, tarPath, meta); return })
	if errors.Is(err, wire.ErrClaimLost) {
		return Result{Outcome: "lost", Reason: "result upload: " + err.Error()}
	}
	if err != nil && !Permanent(err) && !errors.Is(err, wire.ErrRefused) {
		return Result{Outcome: "failed", Reason: "result upload not delivered: " + err.Error(), Keep: true}
	}
	if err != nil {
		return j.fail(ctx, "result upload failed: "+err.Error())
	}
	if out.Status == "done" || out.Status == "accepted" {
		// From here a crash must not fail the job: the control plane holds the result. After a
		// 202 recovery replays the PUT or polls the disposition; it never sends fail or release.
		mark, name := MarkReported, ReportedName
		if out.Status == "accepted" {
			mark, name = MarkUploaded, UploadedName
		}
		if err := mark(j.dir); err != nil {
			j.r.logf("job %s: %s marker: %v", j.c.JobID, name, err)
		}
	}
	switch out.Status {
	case "done":
		return Result{Outcome: "done", Reason: ""}
	case "failed":
		// A first-time extraction refusal stores no outcome, so nothing else settles the job.
		return j.fail(ctx, "control plane rejected the result: "+out.Reason)
	}
	// accepted: the finalizer is still working. Poll for a log line.
	wait := time.Now().Add(def(j.r.DispWait, 60*time.Second))
	for {
		st, err := j.cl.Disposition(rc, j.c.JobID)
		if err == nil && (st == "done" || st == "failed") {
			j.r.logf("job %s: disposition %s", j.c.JobID, st)
			if st == "failed" {
				return Result{Outcome: "failed", Reason: "control plane failed the job after acceptance"}
			}
			return Result{Outcome: "done", Reason: "disposition " + st}
		} else if err == nil {
			j.r.logf("job %s: disposition pending:%s", j.c.JobID, st)
		}
		if time.Now().After(wait) {
			return Result{Outcome: "done", Reason: "accepted; disposition still pending"}
		}
		select {
		case <-time.After(def(j.r.DispPoll, 2*time.Second)):
		case <-rc.Done():
			return Result{Outcome: "done", Reason: "accepted; disposition not observed"}
		}
	}
}

// ---- wiping ----

// wipe removes the job dir whatever the engine did to its modes.
func wipe(dir string) {
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if d != nil && d.IsDir() {
			os.Chmod(p, 0o700)
		}
		return nil
	})
	os.RemoveAll(dir)
}

// ---- writers ----

type capWriter struct {
	mu   sync.Mutex
	max  int64
	buf  bytes.Buffer
	over chan struct{}
	hit  bool
}

func newCapWriter(max int64) *capWriter { return &capWriter{max: max, over: make(chan struct{})} }

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.hit || int64(w.buf.Len()+len(p)) > w.max {
		if !w.hit {
			w.hit = true
			close(w.over)
		}
		return len(p), nil // discard; the supervisor kills the group
	}
	return w.buf.Write(p)
}

func (w *capWriter) overflowed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hit
}

func (w *capWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

// tailWriter keeps the last max bytes (engine stderr, for the local log only).
type tailWriter struct {
	mu  sync.Mutex
	max int
	b   []byte
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.b = append(w.b, p...)
	if len(w.b) > w.max {
		w.b = w.b[len(w.b)-w.max:]
	}
	return len(p), nil
}

func (w *tailWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.b)
}
