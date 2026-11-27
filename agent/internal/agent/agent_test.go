package agent

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
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
		return runner.Result{Outcome: "failed", Reason: "sandbox: cannot build"}
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
