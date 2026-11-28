package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/wmetcalf/blastbox/agent/internal/config"
	"github.com/wmetcalf/blastbox/agent/internal/wire"
)

var nodeIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

const resubmitAfter = time.Hour

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

func certPub(certPEM []byte) (*ecdsa.PublicKey, *x509.Certificate, error) {
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, nil, errors.New("no CERTIFICATE PEM block")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("certificate key is not ECDSA")
	}
	return pub, c, nil
}

// unreadable reports whether a key load failed in the file system (open or read: permissions,
// EIO, fd exhaustion), as opposed to on its content. Only bad content proves a corrupt file.
func unreadable(err error) bool {
	var pe *fs.PathError
	return errors.As(err, &pe)
}

func keyMatches(keyPath string, pub *ecdsa.PublicKey) bool {
	k, err := wire.LoadKey(keyPath)
	return err == nil && k.PublicKey.Equal(pub)
}

// RecoverPair finishes an interrupted key+cert swap. The swap renames key.next -> key and then
// cert.next -> cert, so a crash between them leaves a mismatched pair; a `.next` cert that
// verifies against the CA and whose key is the current key or key.next wins and is promoted.
// It reports whether anything was promoted.
func RecoverPair(cfg *config.Config, now time.Time) (bool, error) {
	nextCert := cfg.CertFile + ".next"
	raw, err := os.ReadFile(nextCert)
	if err != nil {
		return false, nil
	}
	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return false, err
	}
	if _, _, err := config.CheckNodeCert(raw, caPEM, now); err != nil {
		return false, nil // not a usable certificate: leave it for the renewal loop to replace
	}
	pub, _, err := certPub(raw)
	if err != nil {
		return false, nil
	}
	nextKey := cfg.KeyFile + ".next"
	switch {
	case keyMatches(nextKey, pub):
		if err := os.Rename(nextKey, cfg.KeyFile); err != nil {
			return false, err
		}
		os.Remove(nextKey + ".csr")
	case keyMatches(cfg.KeyFile, pub):
	default:
		return false, nil
	}
	if err := os.Rename(nextCert, cfg.CertFile); err != nil {
		return false, err
	}
	os.Remove(nextKey + ".csr")
	syncDir(filepath.Dir(cfg.CertFile))
	return true, nil
}

// recoverPairLocked is RecoverPair under the certificate lock (a renewal step of another
// process may be mid-swap).
func recoverPairLocked(cfg *config.Config, now time.Time) (bool, error) {
	unlock, err := lockCert(cfg)
	if err != nil {
		return false, err
	}
	defer unlock()
	return RecoverPair(cfg, now)
}

// RenewState is what one renewal step did.
type RenewState int

const (
	RenewNotDue RenewState = iota
	RenewSubmitted
	RenewPending
	RenewInstalled
)

func (s RenewState) String() string {
	return [...]string{"not-due", "submitted", "pending", "installed"}[s]
}

// Renewer drives the online certificate renewal.
type Renewer struct {
	Cfg    *config.Config
	Client *wire.Client
	Now    func() time.Time

	submitted time.Time
}

func (r *Renewer) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Due reports whether a third of the certificate's lifetime or less remains.
func (r *Renewer) Due() (bool, time.Time, error) {
	raw, err := os.ReadFile(r.Cfg.CertFile)
	if err != nil {
		return false, time.Time{}, err
	}
	_, c, err := certPub(raw)
	if err != nil {
		return false, time.Time{}, err
	}
	life := c.NotAfter.Sub(c.NotBefore)
	return c.NotAfter.Sub(r.now()) < life/3, c.NotAfter, nil
}

// Step does one renewal action. A pending key.next means a CSR is outstanding (or was, in an
// earlier run): FetchCert is tried first, and the same persisted CSR (key.next.csr) is re-sent
// only if the certificate is still due and none was sent in the last hour (or force). The old
// key and cert stay current until /cert serves a cert for key.next.
func (r *Renewer) Step(ctx context.Context, force bool) (RenewState, error) {
	unlock, err := lockCert(r.Cfg)
	if err != nil {
		return RenewPending, err
	}
	defer unlock()
	return r.step(ctx, force)
}

func (r *Renewer) step(ctx context.Context, force bool) (RenewState, error) {
	// A swap interrupted between its two renames (a failed rename, or a crash) is finished
	// here too, not only at the next start: until then the key and cert do not match.
	if promoted, err := RecoverPair(r.Cfg, r.now()); err != nil {
		return RenewPending, err
	} else if promoted {
		r.submitted = time.Time{}
		return RenewInstalled, nil
	}
	due, _, err := r.Due()
	if err != nil {
		return RenewNotDue, err
	}
	nextKey := r.Cfg.KeyFile + ".next"
	_, statErr := os.Lstat(nextKey)
	pendingKey := statErr == nil
	if pendingKey {
		if _, err := wire.LoadKey(nextKey); err != nil {
			if unreadable(err) {
				// Not known to be corrupt: it may be the key a signed CSR names. Keep it.
				return RenewPending, fmt.Errorf("pending key %s: %w", nextKey, err)
			}
			// A corrupt leftover can never match an issued certificate: drop it, so a fresh key
			// and CSR replace it instead of every pass failing until the certificate expires.
			if rerr := os.Remove(nextKey); rerr != nil {
				return RenewPending, fmt.Errorf("unreadable %s (%v) and cannot be removed: %w", nextKey, err, rerr)
			}
			os.Remove(nextKey + ".csr")
			pendingKey, r.submitted = false, time.Time{}
		}
	}
	if !due && !force && !pendingKey {
		return RenewNotDue, nil
	}
	if pendingKey {
		ok, err := r.tryInstall(ctx)
		if err != nil {
			return RenewPending, err
		}
		if ok {
			return RenewInstalled, nil
		}
	}
	if !due && !force {
		return RenewPending, nil
	}
	if !force && !r.submitted.IsZero() && r.now().Sub(r.submitted) < resubmitAfter {
		return RenewPending, nil
	}
	key, err := ensureNextKey(nextKey)
	if err != nil {
		return RenewNotDue, err
	}
	csrPath := nextKey + ".csr"
	_, cerr := os.Lstat(csrPath)
	queued := !r.submitted.IsZero() || cerr == nil // an earlier attempt (maybe an earlier run) POSTed it
	csrPEM, err := ensureNextCSR(csrPath, key, r.Client.NodeID())
	if err != nil {
		return RenewNotDue, err
	}
	if err := r.Client.Renew(ctx, csrPEM); err != nil {
		if queued && errors.Is(err, wire.ErrRefused) {
			// A 403 after a renewal was queued: the CA timer may have published the new cert, so
			// the current key (the old one) is no longer current. Adopt the cert if it is ours.
			ok, ierr := r.tryInstall(ctx)
			if ierr != nil {
				return RenewPending, ierr
			}
			if ok {
				return RenewInstalled, nil
			}
			r.submitted = r.now()
			return RenewPending, nil
		}
		return RenewNotDue, err
	}
	r.submitted = r.now()
	return RenewSubmitted, nil
}

// ensureNextCSR returns the CSR for key persisted at path (0600, atomically, before it is ever
// sent), so a retry resends the SAME CSR. A leftover that is unreadable, or is not for key and
// this node, is replaced.
func ensureNextCSR(path string, key *ecdsa.PrivateKey, nodeID string) ([]byte, error) {
	if raw, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(raw); blk != nil && blk.Type == "CERTIFICATE REQUEST" {
			if req, err := x509.ParseCertificateRequest(blk.Bytes); err == nil && req.CheckSignature() == nil &&
				req.Subject.CommonName == nodeID {
				if pub, ok := req.PublicKey.(*ecdsa.PublicKey); ok && pub.Equal(&key.PublicKey) {
					return raw, nil
				}
			}
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: nodeID},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, err
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if err := writeFileAtomic(path, blob, 0o600); err != nil {
		return nil, err
	}
	return blob, nil
}

// writeFileAtomic replaces path with blob durably (temp file, fsync, rename, dir fsync).
func writeFileAtomic(path string, blob []byte, mode os.FileMode) error {
	tmp := fmt.Sprintf("%s.tmp-%d", path, time.Now().UnixNano())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// ensureNextKey returns the P-256 key at path, creating it (0600, exclusively) if absent.
// An existing readable key is reused; an unreadable leftover is replaced.
func ensureNextKey(path string) (*ecdsa.PrivateKey, error) {
	if k, err := wire.LoadKey(path); err == nil {
		return k, nil
	} else if _, serr := os.Lstat(path); serr == nil {
		if unreadable(err) {
			return nil, fmt.Errorf("pending key %s: %w", path, err)
		}
		if rerr := os.Remove(path); rerr != nil { // corrupt leftover of a crash
			return nil, fmt.Errorf("unreadable %s (%v) and cannot be removed: %w", path, err, rerr)
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeKeyExcl(path, k); err != nil {
		if errors.Is(err, os.ErrExist) { // lost a race with another renewer: use theirs
			return wire.LoadKey(path)
		}
		return nil, err
	}
	return k, nil
}

// writeKeyExcl writes a PKCS#8 key to path with O_EXCL and mode 0600, durably, via a temp
// file linked into place so a crash never leaves a truncated key at path.
func writeKeyExcl(path string, k *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	tmp := fmt.Sprintf("%s.tmp-%d", path, time.Now().UnixNano())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := f.Write(blob); err != nil {
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
	if err := os.Link(tmp, path); err != nil {
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

// tryInstall fetches the issued cert; if it carries key.next's public key and verifies, the
// pair is swapped into place (key first, then cert).
func (r *Renewer) tryInstall(ctx context.Context) (bool, error) {
	nextKey := r.Cfg.KeyFile + ".next"
	k, err := wire.LoadKey(nextKey)
	if err != nil {
		return false, err
	}
	raw, err := r.Client.FetchCert(ctx)
	if err != nil {
		if errors.Is(err, wire.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	pub, _, err := certPub(raw)
	if err != nil || !pub.Equal(&k.PublicKey) {
		return false, nil // still the old certificate
	}
	caPEM, err := os.ReadFile(r.Cfg.CAFile)
	if err != nil {
		return false, err
	}
	id, _, err := config.CheckNodeCert(raw, caPEM, r.now())
	if err != nil {
		return false, fmt.Errorf("issued certificate refused: %w", err)
	}
	if id != r.Client.NodeID() {
		return false, fmt.Errorf("issued certificate is for node %q, not %q", id, r.Client.NodeID())
	}
	nextCert := r.Cfg.CertFile + ".next"
	f, err := os.OpenFile(nextCert, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return false, err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return false, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	// cert.next's directory entry must be durable before key.next replaces the only key the
	// current cert matches: a power loss must never leave the new key without its cert.
	syncDir(filepath.Dir(nextCert))
	if err := os.Rename(nextKey, r.Cfg.KeyFile); err != nil {
		return false, err
	}
	if err := os.Rename(nextCert, r.Cfg.CertFile); err != nil {
		return false, err // RecoverPair finishes this at the next start
	}
	os.Remove(nextKey + ".csr")
	syncDir(filepath.Dir(r.Cfg.CertFile))
	r.submitted = time.Time{}
	return true, nil
}

// Enrol creates DIR (0700) with node.key (0600, PKCS#8 P-256, exclusive) and node.csr
// (CN=nodeID), and prints the command to run on the CA host. The key is never printed.
func Enrol(nodeID, dir string, w io.Writer) error {
	if !nodeIDRE.MatchString(nodeID) {
		return fmt.Errorf("node id %q must match %s", nodeID, nodeIDRE)
	}
	keyPath := filepath.Join(dir, "node.key")
	csrPath := filepath.Join(dir, "node.csr")
	for _, p := range []string{keyPath, csrPath} {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite an identity", p)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	if err := writeKeyExcl(keyPath, k); err != nil {
		return fmt.Errorf("node.key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: nodeID},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, k)
	if err != nil {
		return err
	}
	if err := os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(w, "wrote %s (private, mode 0600) and %s\n", keyPath, csrPath)
	fmt.Fprintf(w, "copy %s to the CA host and run (replace <E> with an engine this node serves):\n", csrPath)
	fmt.Fprintf(w, "  blastbox pki sign-node-csr --csr %s --node-id %s --engine <E> --tier none --days 7\n", csrPath, nodeID)
	return nil
}

// RenewNow is `blastbox-agent renew`: force one renewal attempt (the wire client handshakes
// lazily on its first authenticated call), then check once whether the cert is already issued.
func RenewNow(ctx context.Context, cfg *config.Config, now func() time.Time, w io.Writer) error {
	if _, err := recoverPairLocked(cfg, now()); err != nil {
		return err
	}
	cl, err := wire.New(cfg, "blastbox-agent/"+Version)
	if err != nil {
		return err
	}
	if err := cl.Session(ctx); err != nil {
		return err
	}
	r := &Renewer{Cfg: cfg, Client: cl, Now: now}
	st, err := r.Step(ctx, true)
	if err == nil && st == RenewSubmitted {
		fmt.Fprintln(w, "renewal requested; the CA host must sign the CSR")
		st, err = r.Step(ctx, false) // it may already be issued
	}
	if err != nil {
		return err
	}
	if st == RenewInstalled {
		fmt.Fprintln(w, "new certificate installed; restart the agent to use it")
	} else {
		fmt.Fprintln(w, "renewal pending; a running agent installs the certificate once issued, or re-run renew later")
	}
	return nil
}
