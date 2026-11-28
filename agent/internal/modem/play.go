package modem

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"
)

const playTimeout = 10 * time.Second

// Ensure writes <stateDir>/modem.wav (tmp + rename, 0600) if it is missing and returns its path.
func Ensure(stateDir string) (string, error) {
	p := filepath.Join(stateDir, "modem.wav")
	if st, err := os.Lstat(p); err == nil && st.Mode().IsRegular() {
		return p, nil
	}
	w, _ := Synth()
	tmp, err := os.CreateTemp(stateDir, ".modem-*.tmp") // 0600
	if err != nil {
		return "", err
	}
	_, err = tmp.Write(w)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o600)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), p)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return p, nil
}

func minimalEnv() []string {
	env := []string{"PATH=/usr/bin:/bin:/usr/local/bin"}
	for _, k := range []string{"HOME", "XDG_RUNTIME_DIR", "PULSE_SERVER", "PULSE_RUNTIME_PATH"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// execRun runs argv directly (no shell) with env, killing it at the timeout.
func execRun(argv, env []string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	cmd.WaitDelay = time.Second
	return cmd.Run()
}

// Notifier plays the modem sound once per process, on the first successful session.
type Notifier struct {
	Enabled  bool
	StateDir string
	Debug    func(msg string, err error)

	// Injection points (defaults used when nil).
	GOOS     string
	Run      func(argv, env []string, timeout time.Duration) error
	LookPath func(name string) (string, bool)
	Async    func(func())

	played atomic.Bool
}

// OnSession is the wire.Client.OnSession hook. It never blocks and never fails the caller.
func (n *Notifier) OnSession(err error) {
	if n == nil || !n.Enabled || err != nil {
		return
	}
	if !n.played.CompareAndSwap(false, true) {
		return
	}
	async := n.Async
	if async == nil {
		async = func(f func()) { go f() }
	}
	async(n.play)
}

func (n *Notifier) play() {
	defer func() { recover() }() // best effort, whatever happens
	p, err := Ensure(n.StateDir)
	if err != nil {
		n.debug("modem: write wav", err)
		return
	}
	goos := n.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	look := n.LookPath
	if look == nil {
		look = func(s string) (string, bool) { r, e := exec.LookPath(s); return r, e == nil }
	}
	var argv []string
	switch goos {
	case "darwin":
		argv = []string{"/usr/bin/afplay", p}
		if n.LookPath != nil {
			bin, _ := look("afplay")
			argv[0] = bin
		}
	case "linux":
		if bin, ok := look("paplay"); ok {
			argv = []string{bin, p}
		} else if bin, ok := look("aplay"); ok {
			argv = []string{bin, "-q", p}
		}
	}
	if argv == nil {
		return
	}
	run := n.Run
	if run == nil {
		run = execRun
	}
	if err := run(argv, minimalEnv(), playTimeout); err != nil {
		n.debug("modem: playback", err)
	}
}

func (n *Notifier) debug(msg string, err error) {
	if n.Debug != nil {
		n.Debug(msg, err)
	}
}
