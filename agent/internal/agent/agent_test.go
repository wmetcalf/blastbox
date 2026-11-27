package agent

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/config"
	"github.com/wmetcalf/blastbox/agent/internal/runner"
	"github.com/wmetcalf/blastbox/agent/internal/sandbox"
	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

func TestBackoffTable(t *testing.T) {
	// rnd 0.5 = no jitter: 1,2,4,8,16 then capped at 30.
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30, 30}
	for i, w := range want {
		if got := serverBackoff(i, 0.5); got != w*time.Second {
			t.Errorf("attempt %d: %v, want %v", i, got, w*time.Second)
		}
	}
	// +-20% jitter at the extremes, also at the cap.
	if got := serverBackoff(2, 0); got != 3200*time.Millisecond {
		t.Errorf("low jitter %v", got)
	}
	if got := serverBackoff(2, 1); got != 4800*time.Millisecond {
		t.Errorf("high jitter %v", got)
	}
	if got := serverBackoff(50, 0); got != 24*time.Second {
		t.Errorf("capped low jitter %v", got)
	}
	cases := []struct {
		err error
		d   time.Duration
		ok  bool
	}{
		{wire.ErrRefused, 60 * time.Second, true},
		{wire.ErrTLS, 5 * time.Minute, true},
		{wire.ErrRedirect, 5 * time.Minute, true},
		{wire.ErrServer, 0, false},
		{wire.ErrUnauthorized, 0, false},
	}
	for _, c := range cases {
		d, _, ok := classify(c.err)
		if d != c.d || ok != c.ok {
			t.Errorf("%v: %v %v", c.err, d, ok)
		}
	}
	if idleDelay != 2*time.Second {
		t.Error("idle delay")
	}
}

func TestSemver(t *testing.T) {
	for _, c := range []struct {
		a, b string
		less bool
	}{{"dev", "0.0.1", true}, {"1.0.0", "9.0.0", true}, {"1.2.3", "1.2.3", false}, {"v1.10.0", "1.9.9", false},
		{"2.0.0-rc1", "2.0.0", false}, {"dev", "dev", false}, {"1.0.0", "", false}} {
		if got := semverLess(c.a, c.b); got != c.less {
			t.Errorf("%q < %q = %v", c.a, c.b, got)
		}
	}
}

func TestShadowNeverClaims(t *testing.T) {
	e := fresh(t)
	e.cfg.Claim = false
	e.in.onClaim = func(int) (int, string) { t.Error("shadow mode called /claim"); return 204, "" }
	h := newHarness(e)
	stop := h.start(t)
	eventually(t, "heartbeats", func() bool { return e.in.hbCount() >= 3 })
	time.Sleep(30 * time.Millisecond)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if e.in.claimCount() != 0 {
		t.Fatal("claimed in shadow mode")
	}
	hb := e.in.hbs[0]
	if len(hb.Engines) != 1 || !hb.Engines[0].SelftestOK || hb.Engines[0].SelftestAt == "" || hb.CertNotAfter == "" ||
		hb.StartedAt == "" || hb.AgentVersion != "1.0.0" || len(hb.BinarySHA256) != 64 {
		t.Fatalf("%+v", hb)
	}
	if _, err := time.Parse(time.RFC3339, hb.StartedAt); err != nil {
		t.Fatal(err)
	}
}

func TestSkewStillWorks(t *testing.T) {
	for _, off := range []time.Duration{10 * time.Minute, -10 * time.Minute} {
		e := fresh(t)
		e.in.dateOffset = off
		e.in.onClaim = func(n int) (int, string) {
			if n == 1 {
				return 200, claimBody("j1")
			}
			return 204, ""
		}
		h := newHarness(e)
		ran := make(chan string, 4)
		h.a.Runner = fakeRunner{fn: func(_ context.Context, c *wire.Claim) runner.Result {
			ran <- c.JobID
			return runner.Result{Outcome: "done"}
		}}
		stop := h.start(t)
		select {
		case id := <-ran:
			if id != "j1" {
				t.Fatal(id)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("no job ran with skew %v", off)
		}
		eventually(t, "skew warning", func() bool { return strings.Contains(h.logs.String(), "server clock differs") })
		stop()
	}
}

func TestRestartWithStartedMarkerFailsNotReleases(t *testing.T) {
	e := fresh(t)
	e.cfg.Claim = false
	d := jobDir(e, "j1", true, true)
	os.WriteFile(filepath.Join(d, "scratch.bin"), []byte("x"), 0o600)
	h := newHarness(e)
	h.start(t)
	eventually(t, "recovery", func() bool { return e.in.update("j1") != nil })
	u := e.in.update("j1")
	f := u["fields"].(map[string]any)
	if f["status"] != "failed" || f["error"] != "agent restarted mid-run" || u["claim_id"] != "cid-j1" || u["receipt"] != "rcpt-j1" {
		t.Fatalf("%v", u)
	}
	eventually(t, "wipe", func() bool { _, err := os.Stat(d); return os.IsNotExist(err) })
}

// An upload the control plane never answered is replayed (the PUT is idempotent per claim),
// not failed: the result exists.
func TestRecoveryReplaysAnUnansweredUpload(t *testing.T) {
	e := fresh(t)
	e.cfg.Claim = false
	d := jobDir(e, "ju", true, true)
	os.WriteFile(filepath.Join(d, runner.ResultTarName), make([]byte, 1024), 0o600)
	os.WriteFile(filepath.Join(d, runner.ResultMetaName), []byte(`{"worker_runtime":"seatbelt","started_at_ms":1,"finished_at_ms":2}`), 0o600)
	h := newHarness(e)
	h.start(t)
	eventually(t, "replayed upload and wipe", func() bool {
		_, err := os.Stat(d)
		return e.in.putCount("ju") == 1 && os.IsNotExist(err)
	})
	if u := e.in.update("ju"); u != nil {
		t.Fatalf("a job whose result was delivered on replay was also failed: %v", u)
	}
}

func TestRecoveryFailsAReplayTheExtractorRefuses(t *testing.T) {
	e := fresh(t)
	e.cfg.Claim = false
	d := jobDir(e, "jx", true, true)
	os.WriteFile(filepath.Join(d, runner.ResultTarName), make([]byte, 1024), 0o600)
	os.WriteFile(filepath.Join(d, runner.ResultMetaName), []byte(`{"worker_runtime":"seatbelt"}`), 0o600)
	e.in.putStatus["jx"] = 422
	h := newHarness(e)
	h.start(t)
	eventually(t, "failed after the refused replay", func() bool { return e.in.update("jx") != nil })
	if f := e.in.update("jx")["fields"].(map[string]any); f["status"] != "failed" {
		t.Fatalf("%v", f)
	}
}

// After the control plane answered the upload (done or accepted), a crash must not fail the
// job: the finalizer may still be turning it DONE.
func TestRecoveryAfterAReportedUploadSendsNothing(t *testing.T) {
	e := fresh(t)
	e.cfg.Claim = false
	d := jobDir(e, "jd", true, true)
	os.WriteFile(filepath.Join(d, runner.ResultTarName), make([]byte, 1024), 0o600)
	os.WriteFile(filepath.Join(d, runner.ReportedName), nil, 0o600)
	h := newHarness(e)
	h.start(t)
	eventually(t, "wipe", func() bool { _, err := os.Stat(d); return os.IsNotExist(err) })
	if u, n := e.in.update("jd"), e.in.putCount("jd"); u != nil || n != 0 {
		t.Fatalf("recovery re-reported a reported job: update=%v puts=%d", u, n)
	}
}

func TestKeptJobGoesToRecovery(t *testing.T) {
	e := fresh(t)
	e.in.onClaim = func(n int) (int, string) {
		if n == 1 {
			return 200, claimBody("jk")
		}
		return 204, ""
	}
	h := newHarness(e)
	h.a.Runner = fakeRunner{fn: func(context.Context, *wire.Claim) runner.Result {
		jobDir(e, "jk", true, true)
		return runner.Result{Outcome: "failed", Reason: "fail not delivered", Keep: true}
	}}
	h.start(t)
	eventually(t, "recovery of the kept job", func() bool { return e.in.update("jk") != nil })
	if f := e.in.update("jk")["fields"].(map[string]any); f["status"] != "failed" {
		t.Fatalf("%v", f)
	}
}

// Recovery settles a job the control plane will never accept a report for (deleted: 404;
// refused outright: 4xx) instead of re-sending it every pass, and fails a job whose replayed
// upload is refused outright.
func TestRecoveryGivesUpOnPermanentRefusals(t *testing.T) {
	e := fresh(t)
	e.cfg.Claim = false
	gone := jobDir(e, "jg", true, true)
	bad := jobDir(e, "jb", true, true)
	big := jobDir(e, "jt", true, true)
	os.WriteFile(filepath.Join(big, runner.ResultTarName), make([]byte, 1024), 0o600)
	os.WriteFile(filepath.Join(big, runner.ResultMetaName), []byte(`{"worker_runtime":"seatbelt"}`), 0o600)
	e.in.jobStatus["jg"], e.in.jobStatus["jb"] = 404, 400
	e.in.putStatus["jt"] = 413
	h := newHarness(e)
	h.start(t)
	eventually(t, "all three settled and wiped", func() bool {
		for _, d := range []string{gone, bad, big} {
			if _, err := os.Stat(d); !os.IsNotExist(err) {
				return false
			}
		}
		return true
	})
	if u := e.in.update("jt"); u == nil || u["fields"].(map[string]any)["status"] != "failed" {
		t.Fatalf("a refused replay was not failed: %v", u)
	}
	if n := e.in.putCount("jt"); n != 1 {
		t.Fatalf("replayed %d times", n)
	}
}

// The agent died (or gave up draining) while an engine ran: the engine is still alive when the
// next agent starts. Recovery stops the recorded run before failing the job and wiping its dir.
func TestRecoveryKillsAnOrphanedRun(t *testing.T) {
	e := fresh(t)
	e.cfg.Claim = false
	d := jobDir(e, "jo", true, true)
	cmd := exec.Command("/bin/sh", "-c", "sleep 60 & sleep 60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reaped := make(chan struct{})
	go func() { cmd.Wait(); close(reaped) }()
	t.Cleanup(func() { syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	id, ok := sandbox.ProcIdentity(cmd.Process.Pid)
	if !ok {
		t.Fatal("no identity")
	}
	rec, _ := json.Marshal(sandbox.RunRecord{PID: cmd.Process.Pid, Identity: id})
	os.WriteFile(filepath.Join(d, runner.RunRecordName), rec, 0o600)
	h := newHarness(e)
	h.start(t)
	eventually(t, "recovery", func() bool { return e.in.update("jo") != nil })
	select {
	case <-reaped:
	case <-time.After(5 * time.Second):
		t.Fatal("the orphaned run survived recovery")
	}
}

// A started dir whose claim record is unusable is still a run that may be alive: it is stopped
// before the dir is wiped.
func TestRecoveryKillsAnOrphanEvenWithoutAClaim(t *testing.T) {
	e := fresh(t)
	e.cfg.Claim = false
	d := jobDir(e, "jn", true, false)
	cmd := exec.Command("/bin/sh", "-c", "sleep 60 & sleep 60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reaped := make(chan struct{})
	go func() { cmd.Wait(); close(reaped) }()
	t.Cleanup(func() { syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	id, _ := sandbox.ProcIdentity(cmd.Process.Pid)
	rec, _ := json.Marshal(sandbox.RunRecord{PID: cmd.Process.Pid, Identity: id})
	os.WriteFile(filepath.Join(d, runner.RunRecordName), rec, 0o600)
	h := newHarness(e)
	h.start(t)
	select {
	case <-reaped:
	case <-time.After(5 * time.Second):
		t.Fatal("the orphaned run survived recovery of a dir without a claim record")
	}
}

func TestRestartWithOnlyClaimJSONReleases(t *testing.T) {
	e := fresh(t)
	e.cfg.Claim = false
	d := jobDir(e, "j2", false, true)
	empty := jobDir(e, "j3", false, false)
	h := newHarness(e)
	h.start(t)
	eventually(t, "recovery", func() bool { return e.in.update("j2") != nil })
	f := e.in.update("j2")["fields"].(map[string]any)
	if f["status"] != "queued" || f["claim_id"] != nil {
		t.Fatalf("%v", f)
	}
	eventually(t, "wipe", func() bool {
		_, e1 := os.Stat(d)
		_, e2 := os.Stat(empty)
		return os.IsNotExist(e1) && os.IsNotExist(e2)
	})
	if e.in.update("j3") != nil {
		t.Fatal("a dir with no claim record must just be wiped")
	}
}

func TestRestartServerErrorKeepsDirAndLostWipes(t *testing.T) {
	e := fresh(t)
	e.cfg.Claim = false
	kept := jobDir(e, "jk", true, true)
	lost := jobDir(e, "jl", true, true)
	e.in.jobStatus["jk"] = 503
	e.in.jobStatus["jl"] = 409
	h := newHarness(e)
	h.start(t)
	eventually(t, "both attempted", func() bool { return e.in.update("jk") != nil && e.in.update("jl") != nil })
	eventually(t, "lost wiped", func() bool { _, err := os.Stat(lost); return os.IsNotExist(err) })
	if _, err := os.Stat(kept); err != nil {
		t.Fatal("a job dir must survive a server error so recovery can retry")
	}
}

func TestRedProbeStopsClaims(t *testing.T) {
	e := fresh(t)
	e.in.onClaim = func(int) (int, string) { t.Error("claimed on a red engine"); return 204, "" }
	h := newHarness(e)
	h.a.ProbeFn = func(context.Context, config.Engine) sandbox.ProbeResult {
		return sandbox.ProbeResult{OK: false, Reason: "canary readable"}
	}
	h.start(t)
	eventually(t, "red heartbeat", func() bool {
		e.in.mu.Lock()
		defer e.in.mu.Unlock()
		return len(e.in.hbs) >= 2 && !e.in.hbs[len(e.in.hbs)-1].Engines[0].SelftestOK
	})
	time.Sleep(30 * time.Millisecond)
	if e.in.claimCount() != 0 {
		t.Fatal("claimed on a red engine")
	}
}

func TestSelftestRedAndSandboxFailureReprobe(t *testing.T) {
	// The runner reports a sandbox that could not be built as a release (no sandbox saw the
	// input) and one that failed mid-run as a failure; either must stop claims at once.
	// Either way the report may go undelivered (Keep): that must not hide the sandbox fault.
	for _, outcome := range []string{"released", "failed"} {
		for _, keep := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/keep=%v", outcome, keep), func(t *testing.T) { sandboxFailureStopsClaims(t, outcome, keep) })
		}
	}
}

func sandboxFailureStopsClaims(t *testing.T, outcome string, keep bool) {
	e := fresh(t)
	e.cfg.Engines[0].SelftestArgv = []string{"/bin/true"}
	var probes int
	good := true
	e.in.onClaim = func(n int) (int, string) { return 200, claimBody("j" + string(rune('0'+n))) }
	h := newHarness(e)
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}
	h.a.SelfTestFn = func(context.Context, config.Engine) sandbox.ProbeResult {
		<-mu
		defer func() { mu <- struct{}{} }()
		probes++
		return sandbox.ProbeResult{OK: good, Reason: "selftest says"}
	}
	h.a.Runner = fakeRunner{fn: func(context.Context, *wire.Claim) runner.Result {
		<-mu
		good = false // the host went bad underneath the job
		mu <- struct{}{}
		return runner.Result{Outcome: outcome, Reason: "could not build: insecure host", SandboxFailure: true, Keep: keep}
	}}
	h.start(t)
	eventually(t, "the sandbox failure and a re-probe after it", func() bool {
		<-mu
		defer func() { mu <- struct{}{} }()
		return !good && probes >= 2
	})
	n := e.in.claimCount()
	time.Sleep(60 * time.Millisecond)
	if got := e.in.claimCount(); got != n || got != 1 {
		t.Fatalf("claims continued on a red engine: %d -> %d", n, got)
	}
	if !strings.Contains(h.logs.String(), "selftest: selftest says") {
		t.Fatal("red reason not logged")
	}
}

func TestMinAgentVersionStopsClaims(t *testing.T) {
	e := fresh(t)
	e.in.hbResp["min_agent_version"] = "9.0.0"
	e.in.onClaim = func(int) (int, string) { t.Error("claimed with an outdated agent"); return 204, "" }
	h := newHarness(e)
	h.start(t)
	eventually(t, "heartbeats keep going", func() bool { return e.in.hbCount() >= 4 })
	eventually(t, "ERROR logged", func() bool {
		return strings.Contains(h.logs.String(), `"level":"ERROR"`) && strings.Contains(h.logs.String(), "min_agent_version")
	})
}

func TestBackoffsOnTheClaimLoop(t *testing.T) {
	e := fresh(t)
	e.in.onClaim = func(n int) (int, string) {
		switch {
		case n == 1:
			return 500, `{}`
		case n == 2:
			return 403, `{}`
		}
		return 204, ""
	}
	h := newHarness(e)
	h.start(t)
	eventually(t, "idle, server and refused delays", func() bool {
		return h.slept(idleDelay) && h.slept(60*time.Second) && h.slept(1*time.Second)
	})
}

func TestSigtermDrains(t *testing.T) {
	e := fresh(t)
	e.in.onClaim = func(n int) (int, string) {
		if n == 1 {
			return 200, claimBody("jd")
		}
		return 204, ""
	}
	h := newHarness(e)
	entered, release := make(chan struct{}), make(chan struct{})
	finished := make(chan struct{})
	h.a.Runner = fakeRunner{fn: func(ctx context.Context, c *wire.Claim) runner.Result {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			t.Error("the job was cancelled instead of being drained")
		}
		close(finished)
		return runner.Result{Outcome: "done"}
	}}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- h.a.Run(ctx) }()
	<-entered
	eventually(t, "in-flight reported", func() bool {
		e.in.mu.Lock()
		defer e.in.mu.Unlock()
		for _, hb := range e.in.hbs {
			if len(hb.InFlight) == 1 && hb.InFlight[0].JobID == "jd" && hb.Engines[0].Busy == 1 {
				return true
			}
		}
		return false
	})
	cancel()
	time.Sleep(150 * time.Millisecond)
	n := e.in.claimCount()
	select {
	case err := <-errc:
		t.Fatalf("returned before the job finished: %v", err)
	default:
	}
	time.Sleep(100 * time.Millisecond)
	if e.in.claimCount() != n {
		t.Fatal("claiming continued while draining")
	}
	close(release)
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not exit after the drain")
	}
	select {
	case <-finished:
	default:
		t.Fatal("exited without the job finishing")
	}
}

func TestExpiredCertExitsNamingEnrolRenew(t *testing.T) {
	e := newEnv(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	err := New(e.cfg).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "enrol") || !strings.Contains(err.Error(), "renew") {
		t.Fatalf("%v", err)
	}
}

func TestRenewalSwapsKeyAndCertAndRehandshakes(t *testing.T) {
	// 30-day cert with 1 day left: past the 1/3-remaining mark.
	e := newEnv(t, time.Now().Add(-29*24*time.Hour), time.Now().Add(24*time.Hour))
	oldCert := string(e.cert)
	h := newHarness(e)
	h.start(t)
	eventually(t, "swap", func() bool {
		b, _ := os.ReadFile(e.cfg.CertFile)
		return string(b) != oldCert
	})
	_, err1 := os.Stat(e.cfg.KeyFile + ".next")
	_, err2 := os.Stat(e.cfg.CertFile + ".next")
	if !os.IsNotExist(err1) || !os.IsNotExist(err2) {
		t.Fatal(".next files left behind")
	}
	raw, _ := os.ReadFile(e.cfg.CertFile)
	pub, c, err := certPub(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !keyMatches(e.cfg.KeyFile, pub) {
		t.Fatal("key and cert do not match after the swap")
	}
	if st, _ := os.Stat(e.cfg.KeyFile); st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode())
	}
	if c.Subject.CommonName != "node-a" {
		t.Fatal(c.Subject)
	}
	e.in.mu.Lock()
	csr := e.in.csrs[0]
	e.in.mu.Unlock()
	blk, _ := pem.Decode(csr)
	req, _ := x509.ParseCertificateRequest(blk.Bytes)
	if req.Subject.CommonName != "node-a" {
		t.Fatal("CSR CN", req.Subject)
	}
	eventually(t, "re-handshake with the new cert", func() bool {
		e.in.mu.Lock()
		defer e.in.mu.Unlock()
		return len(e.in.sessions) >= 2 && e.in.sessions[len(e.in.sessions)-1] == string(raw)
	})
	eventually(t, "heartbeat reports the new expiry", func() bool {
		e.in.mu.Lock()
		defer e.in.mu.Unlock()
		last := e.in.hbs[len(e.in.hbs)-1].CertNotAfter
		return last == c.NotAfter.UTC().Format(time.RFC3339)
	})
}

func TestRenewKeyNextReusedAndExclusive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.next")
	k1, err := ensureNextKey(p)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ensureNextKey(p)
	if err != nil || !k1.PublicKey.Equal(&k2.PublicKey) {
		t.Fatal("an existing .next must be reused")
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatal(st.Mode())
	}
	if err := writeKeyExcl(p, k1); err == nil {
		t.Fatal("writeKeyExcl must not overwrite")
	}
}

func TestRecoverPairPromotesVerifyingNextPair(t *testing.T) {
	e := fresh(t)
	nk := mustKey(t)
	newCert := e.ca.issueNode(t, "node-a", &nk.PublicKey, time.Now().Add(-time.Minute), time.Now().Add(7*24*time.Hour))
	// crash after key.next -> key but before cert.next -> cert
	os.Remove(e.cfg.KeyFile)
	writeKey(t, e.cfg.KeyFile, nk)
	os.WriteFile(e.cfg.CertFile+".next", newCert, 0o644)
	ok, err := RecoverPair(e.cfg, time.Now())
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if b, _ := os.ReadFile(e.cfg.CertFile); string(b) != string(newCert) {
		t.Fatal("cert not promoted")
	}
	// crash before either rename
	e2 := fresh(t)
	nk2 := mustKey(t)
	c2 := e2.ca.issueNode(t, "node-a", &nk2.PublicKey, time.Now().Add(-time.Minute), time.Now().Add(7*24*time.Hour))
	writeKey(t, e2.cfg.KeyFile+".next", nk2)
	os.WriteFile(e2.cfg.CertFile+".next", c2, 0o644)
	if ok, err := RecoverPair(e2.cfg, time.Now()); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if k, err := wire.LoadKey(e2.cfg.KeyFile); err != nil || !k.PublicKey.Equal(&nk2.PublicKey) {
		t.Fatal("key not promoted")
	}
	// a .next cert that does not verify is left alone
	e3 := fresh(t)
	os.WriteFile(e3.cfg.CertFile+".next", []byte("junk"), 0o644)
	if ok, _ := RecoverPair(e3.cfg, time.Now()); ok {
		t.Fatal("promoted junk")
	}
}

func TestEnrol(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "id")
	var out strings.Builder
	if err := Enrol("node-b", dir, &out); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatal(st.Mode())
	}
	if st, _ := os.Stat(filepath.Join(dir, "node.key")); st.Mode().Perm() != 0o600 {
		t.Fatal(st.Mode())
	}
	if _, err := wire.LoadKey(filepath.Join(dir, "node.key")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "node.csr"))
	blk, _ := pem.Decode(raw)
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.Subject.CommonName != "node-b" || csr.CheckSignature() != nil {
		t.Fatal(err, csr)
	}
	want := "blastbox pki sign-node-csr --csr " + filepath.Join(dir, "node.csr") + " --node-id node-b --engine <E> --tier none --days 7"
	if !strings.Contains(out.String(), want) || strings.Contains(out.String(), "PRIVATE") {
		t.Fatalf("%s", out.String())
	}
	if err := Enrol("node-b", dir, &out); err == nil {
		t.Fatal("must not overwrite an existing identity")
	}
	if err := Enrol("Bad ID", t.TempDir(), &out); err == nil {
		t.Fatal("bad id accepted")
	}
}

func TestRecoveryNeverTouchesLiveJobs(t *testing.T) {
	e := fresh(t)
	e.in.onClaim = func(n int) (int, string) {
		if n == 1 {
			return 200, claimBody("live")
		}
		return 204, ""
	}
	h := newHarness(e)
	entered, release := make(chan struct{}), make(chan struct{})
	h.a.Runner = fakeRunner{fn: func(ctx context.Context, c *wire.Claim) runner.Result {
		jobDir(e, "live", true, true) // claim.json + started, as the real runner leaves them
		close(entered)
		<-release
		return runner.Result{Outcome: "done"}
	}}
	h.start(t)
	<-entered
	// the recover loop ticks every ~1 ms under the harness; let it tick many times
	time.Sleep(300 * time.Millisecond)
	if u := e.in.update("live"); u != nil {
		t.Fatalf("recovery posted an update for a live job: %v", u)
	}
	if _, err := os.Stat(filepath.Join(e.cfg.StateDir, "jobs", "live")); err != nil {
		t.Fatal("a live job's dir was wiped")
	}
	close(release)
}

// Recovery releases job J (a retry pass, after a 503); while that request is in flight the
// control plane re-queues J and this node claims it again. The live run's dir must survive the
// recovery pass finishing: recovery and a live run of the same job never overlap.
func TestRecoveryAndALiveReclaimNeverOverlap(t *testing.T) {
	e := fresh(t)
	jobDir(e, "jr2", false, true)
	inRelease, unblock := make(chan struct{}), make(chan struct{})
	e.in.onUpdate = func(id string, n int) int {
		if id != "jr2" || n != 2 {
			return 503 // the first (startup) pass fails; later live updates don't matter
		}
		close(inRelease)
		<-unblock
		return 200
	}
	var claimed bool
	e.in.onClaim = func(int) (int, string) {
		select {
		case <-inRelease:
			if !claimed {
				claimed = true
				go func() { time.Sleep(50 * time.Millisecond); close(unblock) }()
				return 200, claimBody("jr2")
			}
		default:
		}
		return 204, ""
	}
	h := newHarness(e)
	survived := make(chan bool, 1)
	h.a.Runner = fakeRunner{fn: func(context.Context, *wire.Claim) runner.Result {
		d := jobDir(e, "jr2", true, true)  // the live run's dir
		time.Sleep(300 * time.Millisecond) // the recovery pass completes meanwhile
		_, err := os.Stat(d)
		survived <- err == nil
		os.RemoveAll(d)
		return runner.Result{Outcome: "done"}
	}}
	h.start(t)
	select {
	case ok := <-survived:
		if !ok {
			t.Fatal("recovery wiped a live run's job dir")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the job was never re-claimed")
	}
}

// Two agents on one state dir would each treat the other's live job dirs as crash leftovers.
func TestOneAgentPerStateDir(t *testing.T) {
	e := fresh(t)
	e.cfg.Claim = false
	first := newHarness(e)
	first.start(t)
	eventually(t, "first agent up", func() bool { return e.in.hbCount() >= 1 })
	second := newHarness(e)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := second.a.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "state dir") {
		t.Fatalf("second agent on the same state dir: %v", err)
	}
}

// The control plane hands this node a job it is still running (its claim was reclaimed and the
// job re-queued). The second claim must not touch the live run: no second run, no recovery of
// the live dir; the new claim is failed (the job already reached a sandbox here).
func TestDuplicateClaimOfALiveJob(t *testing.T) {
	e := fresh(t)
	two := 2
	e.cfg.Engines[0].Slots = &two
	body := func(cid string) string {
		return strings.Replace(claimBody("jd"), `"claim_id":"cid-jd"`, `"claim_id":"`+cid+`"`, 1)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	e.in.onClaim = func(n int) (int, string) {
		switch n {
		case 1:
			return 200, body("cid-1")
		}
		select {
		case <-entered:
			if n < 50 {
				return 200, body(fmt.Sprintf("cid-%d", n))
			}
		default:
		}
		return 204, ""
	}
	h := newHarness(e)
	var mu sync.Mutex
	runs := 0
	h.a.Runner = fakeRunner{fn: func(ctx context.Context, c *wire.Claim) runner.Result {
		mu.Lock()
		runs++
		first := runs == 1
		mu.Unlock()
		if !first {
			return runner.Result{Outcome: "done"}
		}
		jobDir(e, "jd", true, true)
		close(entered)
		<-release
		return runner.Result{Outcome: "done"}
	}}
	h.start(t)
	<-entered
	eventually(t, "the duplicate claim answered", func() bool { return e.in.update("jd") != nil })
	time.Sleep(200 * time.Millisecond) // recovery loop ticks
	if _, err := os.Stat(filepath.Join(e.cfg.StateDir, "jobs", "jd")); err != nil {
		t.Fatal("the live run's dir was wiped")
	}
	mu.Lock()
	n := runs
	mu.Unlock()
	if n != 1 {
		t.Fatalf("the job ran %d times concurrently", n)
	}
	u := e.in.update("jd")
	if f := u["fields"].(map[string]any); f["status"] != "failed" || u["claim_id"] == "cid-1" {
		t.Fatalf("duplicate claim not failed (or the live claim was): %v", u)
	}
	close(release)
}

// The production runner's sandbox-fault hook marks the engine red at once, before the job's
// report (which may take minutes) and before Run returns.
func TestSandboxFaultHookMarksEngineRed(t *testing.T) {
	e := fresh(t)
	a := New(e.cfg)
	a.Log = slog.New(slog.NewJSONHandler(io.Discard, nil))
	if err := a.startup(context.Background()); err != nil {
		t.Fatal(err)
	}
	es := a.engines[0]
	es.mu.Lock()
	es.ok = true
	es.mu.Unlock()
	r, ok := a.Runner.(*runner.Runner)
	if !ok || r.SandboxFault == nil {
		t.Fatal("the production runner has no sandbox-fault hook")
	}
	r.SandboxFault(es.eng.Name, "handshake missing")
	if es.claimable() {
		t.Fatal("engine still claimable after a sandbox fault")
	}
}

// While processes of an earlier run are not shown gone, the engine stays unclaimable even if a
// fresh probe passes; once recovery stops them, claiming resumes.
func TestUnsweptRunKeepsEngineRed(t *testing.T) {
	e := fresh(t)
	e.in.onClaim = func(n int) (int, string) {
		if n == 1 {
			return 200, claimBody("ju2")
		}
		return 204, ""
	}
	h := newHarness(e)
	var mu sync.Mutex
	stuck := true
	h.a.KillRunFn = func(sandbox.RunRecord) error {
		mu.Lock()
		defer mu.Unlock()
		if stuck {
			return fmt.Errorf("still alive")
		}
		return nil
	}
	h.a.Runner = fakeRunner{fn: func(context.Context, *wire.Claim) runner.Result {
		d := jobDir(e, "ju2", true, true)
		os.WriteFile(filepath.Join(d, runner.RunRecordName), []byte(`{"pid":0}`), 0o600)
		return runner.Result{Outcome: "failed", SandboxFailure: true, Keep: true, Unswept: true}
	}}
	h.start(t)
	eventually(t, "first claim", func() bool { return e.in.claimCount() >= 1 })
	time.Sleep(200 * time.Millisecond) // probes pass, recovery retries
	if n := e.in.claimCount(); n != 1 {
		t.Fatalf("claimed %d times while an earlier run's processes were not shown gone", n)
	}
	mu.Lock()
	stuck = false
	mu.Unlock()
	eventually(t, "claims resume after recovery stops the run", func() bool { return e.in.claimCount() > 1 })
}

func TestRefusedJobGoesToRecovery(t *testing.T) {
	e := fresh(t)
	e.in.onClaim = func(n int) (int, string) {
		if n == 1 {
			return 200, claimBody("jr")
		}
		return 204, ""
	}
	h := newHarness(e)
	h.a.Runner = fakeRunner{fn: func(context.Context, *wire.Claim) runner.Result {
		jobDir(e, "jr", true, true)
		return runner.Result{Outcome: "refused", Reason: "started marker"}
	}}
	h.start(t)
	eventually(t, "recovery of the refused job", func() bool { return e.in.update("jr") != nil })
	if f := e.in.update("jr")["fields"].(map[string]any); f["status"] != "failed" {
		t.Fatalf("%v", f)
	}
	if !strings.Contains(h.logs.String(), "left to recovery") {
		t.Fatal("not logged")
	}
}

func TestRenewNowAgainstControlPlane(t *testing.T) {
	e := newEnv(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)) // not due: force still renews
	var out strings.Builder
	if err := RenewNow(context.Background(), e.cfg, time.Now, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "installed") {
		t.Fatalf("%q", out.String())
	}
	e.in.mu.Lock()
	n := len(e.in.csrs)
	e.in.mu.Unlock()
	if n != 1 {
		t.Fatalf("csrs %d", n)
	}
	raw, _ := os.ReadFile(e.cfg.CertFile)
	pub, _, _ := certPub(raw)
	if !keyMatches(e.cfg.KeyFile, pub) || string(raw) == string(e.cert) {
		t.Fatal("pair not swapped")
	}
}

// A truncated or garbage key.next (a disk fault, a manual edit) must not wedge renewal until the
// certificate expires: it is replaced and a fresh CSR is sent.
func TestCorruptKeyNextIsReplaced(t *testing.T) {
	e := newEnv(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := os.WriteFile(e.cfg.KeyFile+".next", []byte("-----BEGIN PRIV"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := RenewNow(context.Background(), e.cfg, time.Now, &out); err != nil {
		t.Fatalf("renewal with a corrupt key.next: %v", err)
	}
	if !strings.Contains(out.String(), "installed") {
		t.Fatalf("%q", out.String())
	}
}

func TestEnrolRefusesExistingKeyAndFixesDirMode(t *testing.T) {
	d := t.TempDir()
	os.Chmod(d, 0o755)
	os.WriteFile(filepath.Join(d, "node.key"), []byte("x"), 0o600)
	if err := Enrol("node-b", d, &strings.Builder{}); err == nil {
		t.Fatal("overwrote an existing node.key")
	}
	if _, err := os.Stat(filepath.Join(d, "node.csr")); err == nil {
		t.Fatal("generated a csr before refusing")
	}
	d2 := t.TempDir()
	os.Chmod(d2, 0o755)
	if err := Enrol("node-b", d2, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(d2); st.Mode().Perm() != 0o700 {
		t.Fatal(st.Mode())
	}
}

// The renew proof is verified by the fake control plane against the CURRENT cert's key; a
// second renewal after the swap must verify against the NEW current key and cert.
func TestRenewProofSignedByCurrentKeyAcrossSwaps(t *testing.T) {
	e := newEnv(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	for round := 0; round < 2; round++ {
		curCert, _ := os.ReadFile(e.cfg.CertFile)
		curPub, _, err := certPub(curCert)
		if err != nil {
			t.Fatal(err)
		}
		var out safeBuf
		if err := RenewNow(context.Background(), e.cfg, time.Now, &out); err != nil {
			t.Fatalf("round %d: %v\n%s", round, err, out.String())
		}
		e.in.mu.Lock()
		got := e.in.renewBodies
		e.in.mu.Unlock()
		if len(got) != round+1 {
			t.Fatalf("round %d: %d renew bodies", round, len(got))
		}
		b := got[round]
		if b["cert_pem"] != string(curCert) {
			t.Fatalf("round %d: cert_pem is not the current cert", round)
		}
		if at := int64(b["issued_at"].(float64)); at < time.Now().Unix()-30 || at > time.Now().Unix()+30 {
			t.Fatalf("round %d: issued_at %d", round, at)
		}
		newCert, _ := os.ReadFile(e.cfg.CertFile)
		if string(newCert) == string(curCert) {
			t.Fatalf("round %d: cert not swapped", round)
		}
		if np, _, _ := certPub(newCert); np.Equal(curPub) {
			t.Fatalf("round %d: key not rotated", round)
		}
	}
}
