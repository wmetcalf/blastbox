#!/bin/sh
# Pinned installer for blastbox-agent. Never pipe this to a shell; download it,
# read it, then run it with an explicit --version and --sha256.
#
#   install.sh --version X.Y.Z --sha256 <sha256 of this platform's binary>
#              [--from DIR] [--prefix DIR] [--no-cosign]
#   install.sh --rollback [--prefix DIR]
#
# Order: pinned sha256 -> cosign verify-blob of SHA256SUMS -> binary's line in
# SHA256SUMS -> install -> atomic flip of <prefix>/current.
set -eu
# Installed dirs and files must be readable by a non-root service user even when the
# caller runs with a restrictive umask (077 is common for root).
umask 022
unset CDPATH

REPO="wmetcalf/blastbox"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
say() { printf 'install.sh: %s\n' "$*"; }

usage() {
  cat >&2 <<USAGE
usage: install.sh --version X.Y.Z --sha256 HEX [--from DIR] [--prefix DIR] [--no-cosign]
       install.sh --rollback [--prefix DIR]
USAGE
  exit 2
}

version=""; sha=""; from=""; prefix=""; nocosign=0; rollback=0
while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || usage; version=$2; shift 2 ;;
    --sha256) [ $# -ge 2 ] || usage; sha=$2; shift 2 ;;
    --from) [ $# -ge 2 ] || usage; from=$2; shift 2 ;;
    --prefix) [ $# -ge 2 ] || usage; prefix=$2; shift 2 ;;
    --no-cosign) nocosign=1; shift ;;
    --rollback) rollback=1; shift ;;
    *) usage ;;
  esac
done

if [ -z "$prefix" ]; then
  if [ "$(id -u)" = 0 ]; then
    prefix=/opt/blastbox-agent
  else
    [ -n "${HOME:-}" ] || die "HOME is unset; pass --prefix"
    prefix=$HOME/.local/blastbox-agent
  fi
fi

# One spelling of the prefix: no trailing slashes (readlink output is compared to it).
while [ "$prefix" != / ] && [ "${prefix%/}" != "$prefix" ]; do prefix=${prefix%/}; done

# Temp names in <prefix>; the EXIT trap removes them (and the stage dir) on any exit.
tmp=$prefix/.current.tmp.$$
ptmp=$prefix/.previous.tmp.$$
stage=""
newbin=""
locked=0
flipping=0   # 1 from recording .previous until current has been flipped to $flip_to
flip_to=""
on_exit() {
  # A die or a signal between record_previous and the flip puts the old .previous
  # back, so current and .previous never disagree. If current already points at
  # $flip_to (a signal right after the rename), the new .previous is the right one.
  if [ "$flipping" = 1 ] && [ "$(current_target 2>/dev/null || :)" != "$flip_to" ]; then
    (restore_previous) 2>/dev/null || :
  fi
  rm -f "$tmp" "$ptmp"
  if [ -n "$newbin" ]; then rm -f "$newbin"; fi
  if [ -n "$stage" ]; then rm -rf "$stage"; fi
  if [ "$locked" = 1 ]; then
    rmdir "$prefix/.lock" 2>/dev/null \
      || printf 'install.sh: could not remove %s/.lock; remove it by hand\n' "$prefix" >&2
  fi
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 131' QUIT
trap 'exit 143' TERM

os_name=$(uname -s)
case "$os_name" in
  Linux) goos=linux ;;
  Darwin) goos=darwin ;;
  *) die "unsupported OS: $os_name" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) goarch=amd64 ;;
  aarch64|arm64) goarch=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

# Atomically repoint <prefix>/current at the relative target $1. The link is
# created under a temporary name, then renamed over `current`. Plain `mv -f`
# would move INTO the directory current points at, so use the no-dereference
# flag: -T on GNU/Linux, -h on BSD/macOS.
flip_current() {
  if [ -e "$prefix/current" ] && [ ! -L "$prefix/current" ]; then
    die "$prefix/current exists and is not a symlink; move it aside"
  fi
  # Callers run this as `if ! flip_current`, where set -e is off, so every step
  # returns its failure explicitly.
  rm -f "$tmp" || return 1
  ln -s "$1" "$tmp" || return 1
  case "$os_name" in
    Darwin) mv -fh "$tmp" "$prefix/current" || return 1 ;;
    *)
      # GNU mv -T; busybox lacks it, so fall back to ln -sfn (replaces the
      # link in place without dereferencing; not a rename, but never nests).
      if mv -fT "$tmp" "$prefix/current" 2>/dev/null; then :; else
        ln -sfn "$1" "$prefix/current" || return 1
        rm -f "$tmp"
      fi ;;
  esac
}

# One installer at a time per prefix: reading current, recording .previous and flipping
# current are one transaction. mkdir is atomic; a lock left by a killed run must be
# removed by hand.
acquire_lock() {
  mkdir -p "$prefix"
  if ! mkdir "$prefix/.lock" 2>/dev/null; then
    [ -d "$prefix/.lock" ] \
      && die "another install.sh holds $prefix/.lock (remove it if none is running)"
    die "cannot create $prefix/.lock (is $prefix writable?)"
  fi
  locked=1
}

current_target() {
  if [ -L "$prefix/current" ]; then readlink "$prefix/current"; fi
}

valid_version() {
  case "$1" in
    ''|*[!0-9.]*|.*|*.|*..*) return 1 ;;
  esac
  [ "$(printf '%s' "$1" | tr -cd '.' | wc -c | tr -d ' ')" = 2 ]
}

# Record what current points at now ($1) as <prefix>/.previous, unless it is the version
# $2 we are about to point it at. This runs BEFORE the flip, so a failed write never
# leaves current moved with a stale .previous; it writes a temp file and renames it. If
# the flip then fails or is interrupted, on_exit's restore_previous puts the old
# .previous back.
# An absolute link into <prefix> is reduced to its version. Any other target (a link
# outside <prefix>, a non-version name, a version that is not installed) cannot be
# rolled back to, so .previous is removed rather than left naming an older version that
# was not the one active.
saved_prev=""   # "" = nothing to restore, "none" = there was no .previous, "v:X.Y.Z"
record_previous() {
  rp=$1
  pl=$(cd "$prefix" 2>/dev/null && pwd -L) || pl=$prefix
  pp=$(cd "$prefix" 2>/dev/null && pwd -P) || pp=$prefix
  for b in "$prefix" "$pl" "$pp"; do
    b=${b%/}   # "/" -> "", so the pattern below is "/*"
    case "$rp" in "$b"/*) rp=${rp#"$b"/}; break ;; esac
  done
  rp=${rp%/}
  [ "$rp" != "$2" ] || return 0
  if [ -e "$prefix/.previous" ] || [ -L "$prefix/.previous" ]; then
    if [ ! -f "$prefix/.previous" ] || [ -L "$prefix/.previous" ]; then
      die "$prefix/.previous is not a regular file"
    fi
    saved_prev="v:$(cat "$prefix/.previous")"
  else
    saved_prev=none
  fi
  if ! valid_version "$rp" || [ ! -x "$prefix/$rp/blastbox-agent" ]; then
    rm -f "$prefix/.previous"
    return 0
  fi
  write_previous "$rp"
}

write_previous() {
  rm -f "$ptmp"
  printf '%s\n' "$1" > "$ptmp"
  mv -f "$ptmp" "$prefix/.previous"
}

restore_previous() {
  case "$saved_prev" in
    none) rm -f "$prefix/.previous" ;;
    v:*) write_previous "${saved_prev#v:}" ;;
  esac
}

if [ "$rollback" = 1 ]; then
  [ -f "$prefix/.previous" ] || die "no previous version recorded in $prefix/.previous"
  acquire_lock
  prev=$(cat "$prefix/.previous")
  valid_version "$prev" || die "corrupt $prefix/.previous"
  [ -x "$prefix/$prev/blastbox-agent" ] || die "previous version $prev is not installed"
  cur=$(current_target || true)
  flip_to=$prev; flipping=1
  if [ -n "$cur" ]; then record_previous "$cur" "$prev"; fi
  flip_current "$prev" || die "could not repoint $prefix/current"
  flipping=0
  say "rolled back to $prev (was ${cur:-none})"
  exit 0
fi

[ -n "$version" ] || die "--version X.Y.Z is required"
[ -n "$sha" ] || die "--sha256 is required"
valid_version "$version" || die "--version must look like X.Y.Z"
case "$sha" in
  *[!0-9a-fA-F]*|'') die "--sha256 must be hex" ;;
esac
[ "${#sha}" = 64 ] || die "--sha256 must be 64 hex characters"
sha=$(printf '%s' "$sha" | tr 'A-F' 'a-f')

if [ "$nocosign" = 1 ]; then
  printf '%s\n' "WARNING: --no-cosign set. Only the pinned sha256 is checked; the Sigstore" \
    "WARNING: signature and signer identity are NOT verified. This is weaker." >&2
elif ! command -v cosign >/dev/null 2>&1; then
  die "cosign not found; install it, or pass --no-cosign together with --sha256 (weaker)"
fi

if [ "$os_name" = Darwin ]; then
  sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
fi

bin="blastbox-agent-$goos-$goarch"
tag="agent-v$version"
base="https://github.com/$REPO/releases/download/$tag"

acquire_lock
if [ -e "$prefix/current" ] && [ ! -L "$prefix/current" ]; then
  die "$prefix/current exists and is not a symlink; move it aside"
fi
# <prefix>/<version> must be a real directory: through a symlink the binary would be
# written outside the prefix.
if [ -L "$prefix/$version" ] || { [ -e "$prefix/$version" ] && [ ! -d "$prefix/$version" ]; }; then
  die "$prefix/$version is not a directory (a symlink or a file); move it aside"
fi
stage=$(mktemp -d "$prefix/.stage.XXXXXX")

fetch() {
  if [ -n "$from" ]; then
    [ -f "$from/$1" ] || die "missing $from/$1"
    cp "$from/$1" "$stage/$1"
  else
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL -o "$stage/$1" "$base/$1" || die "download failed: $base/$1"
  fi
}
fetch "$bin"
fetch SHA256SUMS
if [ "$nocosign" = 0 ]; then fetch SHA256SUMS.sigstore.json; fi

# 1. pinned sha256 of the binary, before anything else is trusted or run
got=$(sha256_of "$stage/$bin")
[ "$got" = "$sha" ] || die "sha256 mismatch for $bin: expected $sha, got $got"
say "pinned sha256 matches"

# 2. cosign keyless verification of SHA256SUMS against the pinned workflow identity
if [ "$nocosign" = 0 ]; then
  ( cd "$stage" && cosign verify-blob \
      --bundle SHA256SUMS.sigstore.json \
      --certificate-identity "https://github.com/$REPO/.github/workflows/agent-release.yml@refs/tags/$tag" \
      --certificate-oidc-issuer "$OIDC_ISSUER" \
      SHA256SUMS ) || die "cosign verification failed"
  say "cosign signature verified"
fi

# 3. the binary's line in the signed SHA256SUMS
grep -Fx -e "$sha  $bin" "$stage/SHA256SUMS" >/dev/null || die "SHA256SUMS has no matching line for $bin"

# 4. install
dest=$prefix/$version
if [ -e "$dest/blastbox-agent" ]; then
  # A version's binary is never replaced in place: current may already run it, and
  # no rollback target would remain. The same bytes again is a no-op.
  [ "$(sha256_of "$dest/blastbox-agent")" = "$sha" ] \
    || die "$version is already installed with different contents; remove $dest to replace it"
  say "$version already installed with this sha256"
else
  mkdir -p "$dest"
  newbin=$dest/blastbox-agent.new
  cp "$stage/$bin" "$newbin"
  chmod 0755 "$newbin"
  mv -f "$newbin" "$dest/blastbox-agent"
  newbin=""
fi

# 5. flip current atomically; remember what it pointed at
cur=$(current_target || true)
flip_to=$version; flipping=1
if [ -n "$cur" ]; then record_previous "$cur" "$version"; fi
flip_current "$version" || die "could not repoint $prefix/current"
flipping=0
say "installed $version to $dest (current -> $version)"
