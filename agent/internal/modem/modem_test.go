package modem

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestWAVHeaderAndDuration(t *testing.T) {
	w, segs := Synth()
	if len(w) < 44 || string(w[0:4]) != "RIFF" || string(w[8:12]) != "WAVE" || string(w[12:16]) != "fmt " || string(w[36:40]) != "data" {
		t.Fatal("bad chunk ids")
	}
	le := binary.LittleEndian
	if le.Uint32(w[4:]) != uint32(len(w)-8) || le.Uint32(w[16:]) != 16 || le.Uint16(w[20:]) != 1 ||
		le.Uint16(w[22:]) != 1 || le.Uint16(w[34:]) != 16 {
		t.Fatal("bad fmt chunk")
	}
	rate := int(le.Uint32(w[24:]))
	if rate != 8000 && rate != 16000 {
		t.Fatalf("rate %d", rate)
	}
	if le.Uint32(w[28:]) != uint32(rate*2) || le.Uint16(w[32:]) != 2 {
		t.Fatal("byte rate / block align")
	}
	n := int(le.Uint32(w[40:]))
	if n != len(w)-44 || n%2 != 0 {
		t.Fatalf("data length %d vs %d", n, len(w)-44)
	}
	d := time.Duration(n/2) * time.Second / time.Duration(rate)
	if d < 3*time.Second || d > 5*time.Second {
		t.Fatalf("duration %v", d)
	}
	if len(segs) != 4 || segs[len(segs)-1].End != n/2 {
		t.Fatalf("segments %+v", segs)
	}
}

func TestSynthDeterministic(t *testing.T) {
	a, _ := Synth()
	b, _ := Synth()
	if sha256.Sum256(a) != sha256.Sum256(b) || !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
}

func TestEverySegmentAudibleAndFaded(t *testing.T) {
	w, segs := Synth()
	pcm := func(i int) float64 { return float64(int16(binary.LittleEndian.Uint16(w[44+2*i:]))) / 32768 }
	names := []string{}
	for _, s := range segs {
		names = append(names, s.Name)
		var sum float64
		for i := s.Start; i < s.End; i++ {
			sum += pcm(i) * pcm(i)
		}
		if rms := math.Sqrt(sum / float64(s.End-s.Start)); rms < 0.05 {
			t.Errorf("%s RMS %.4f too quiet", s.Name, rms)
		}
		if math.Abs(pcm(s.Start)) > 0.01 || math.Abs(pcm(s.End-1)) > 0.01 {
			t.Errorf("%s not faded at its edges (click)", s.Name)
		}
		for i := s.Start; i < s.End; i++ {
			if math.Abs(pcm(i)) > 0.95 {
				t.Fatalf("%s clips", s.Name)
			}
		}
	}
	if !reflect.DeepEqual(names, []string{"dtmf", "ringback", "ansam", "training"}) {
		t.Fatalf("names %v", names)
	}
}

func TestDTMFUsesRowColumnPairs(t *testing.T) {
	// Goertzel on the first digit's tone window must find its own pair, not a neighbour's.
	w, _ := Synth()
	rate := 8000
	pcm := func(i int) float64 { return float64(int16(binary.LittleEndian.Uint16(w[44+2*i:]))) / 32768 }
	g := func(f float64, from, n int) float64 {
		var s1, s2 float64
		c := 2 * math.Cos(2*math.Pi*f/float64(rate))
		for i := from; i < from+n; i++ {
			s0 := pcm(i) + c*s1 - s2
			s2, s1 = s1, s0
		}
		return s1*s1 + s2*s2 - c*s1*s2
	}
	d0 := DialDigits[0]
	row, col := dtmf(d0)
	from, n := 10*rate/1000, 80*rate/1000
	if g(row, from, n) < 20*g(row+200, from, n) || g(col, from, n) < 20*g(col+200, from, n) {
		t.Fatalf("digit %c pair %v/%v not dominant", d0, row, col)
	}
}

func TestEnsureWritesOnceAtomically0600AndRegenerates(t *testing.T) {
	dir := t.TempDir()
	p, err := Ensure(dir)
	if err != nil || p != filepath.Join(dir, "modem.wav") {
		t.Fatal(p, err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	os.Chtimes(p, time.Unix(1, 1), time.Unix(1, 1))
	if _, err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(p)
	if !st2.ModTime().Equal(st.ModTime().Add(0)) && st2.ModTime().Unix() != 1 {
		t.Fatal("rewritten although present")
	}
	os.Remove(p)
	if _, err := Ensure(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("not regenerated")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("leftover temp files: %v", ents)
	}
}

type recRunner struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *recRunner) run(argv, env []string, to time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, argv)
	return nil
}

func newNotifier(t *testing.T, enabled bool, goos string, have map[string]bool) (*Notifier, *recRunner) {
	rr := &recRunner{}
	n := &Notifier{Enabled: enabled, StateDir: t.TempDir(), GOOS: goos, Run: rr.run,
		LookPath: func(s string) (string, bool) { return "/usr/bin/" + s, have[s] },
		Async:    func(f func()) { f() }}
	return n, rr
}

func TestPlaysOnlyOnTheFirstSessionPerProcess(t *testing.T) {
	n, rr := newNotifier(t, true, "darwin", nil)
	n.OnSession(nil)
	n.OnSession(nil)
	n.OnSession(os.ErrDeadlineExceeded) // a drop
	n.OnSession(nil)                    // reconnect: silent
	n.OnSession(nil)
	if len(rr.calls) != 1 {
		t.Fatalf("want exactly 1 play, got %v", rr.calls)
	}
	want := []string{"/usr/bin/afplay", filepath.Join(n.StateDir, "modem.wav")}
	if !reflect.DeepEqual(rr.calls[0], want) {
		t.Fatalf("argv %v", rr.calls[0])
	}
}

func TestFailedSessionDoesNotConsumeTheOnePlay(t *testing.T) {
	n, rr := newNotifier(t, true, "darwin", nil)
	n.OnSession(os.ErrDeadlineExceeded)
	if len(rr.calls) != 0 {
		t.Fatal("played on failure")
	}
	n.OnSession(nil)
	if len(rr.calls) != 1 {
		t.Fatal("first successful session must play")
	}
}

func TestDisabledGeneratesAndPlaysNothing(t *testing.T) {
	n, rr := newNotifier(t, false, "darwin", nil)
	n.OnSession(nil)
	if len(rr.calls) != 0 {
		t.Fatal("played while disabled")
	}
	if ents, _ := os.ReadDir(n.StateDir); len(ents) != 0 {
		t.Fatalf("generated while disabled: %v", ents)
	}
	var nilN *Notifier
	nilN.OnSession(nil) // nil receiver is a no-op
}

func TestLinuxPlayerChoice(t *testing.T) {
	for _, tc := range []struct {
		have map[string]bool
		want []string
	}{
		{map[string]bool{"paplay": true, "aplay": true}, []string{"/usr/bin/paplay"}},
		{map[string]bool{"aplay": true}, []string{"/usr/bin/aplay", "-q"}},
		{nil, nil},
	} {
		n, rr := newNotifier(t, true, "linux", tc.have)
		n.OnSession(nil)
		if tc.want == nil {
			if len(rr.calls) != 0 {
				t.Fatalf("played without a player: %v", rr.calls)
			}
			continue
		}
		got := rr.calls[0]
		if !reflect.DeepEqual(got[:len(got)-1], tc.want) || filepath.Base(got[len(got)-1]) != "modem.wav" {
			t.Fatalf("argv %v", got)
		}
	}
}

func TestPlaybackNeverBlocksTheCaller(t *testing.T) {
	rr := &recRunner{}
	block := make(chan struct{})
	n := &Notifier{Enabled: true, StateDir: t.TempDir(), GOOS: "darwin",
		Run:      func(a, e []string, d time.Duration) error { <-block; return rr.run(a, e, d) },
		LookPath: func(s string) (string, bool) { return "/usr/bin/" + s, true }}
	done := make(chan struct{})
	go func() { n.OnSession(nil); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("OnSession blocked on playback")
	}
	close(block)
}

func TestExecRunnerKillsAfterTimeoutAndUsesMinimalEnv(t *testing.T) {
	start := time.Now()
	err := execRun([]string{"/bin/sleep", "30"}, minimalEnv(), 200*time.Millisecond)
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("not killed: %v after %v", err, time.Since(start))
	}
	t.Setenv("BLASTBOX_SECRET", "x")
	for _, e := range minimalEnv() {
		if len(e) >= 9 && e[:9] == "BLASTBOX_" {
			t.Fatalf("env leaks %s", e)
		}
	}
}
