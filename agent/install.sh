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
  tmp=$prefix/.current.tmp.$$
  rm -f "$tmp"
  ln -s "$1" "$tmp"
  case "$os_name" in
    Darwin) mv -fh "$tmp" "$prefix/current" ;;
    *)
      # GNU mv -T; busybox lacks it, so fall back to ln -sfn (replaces the
      # link in place without dereferencing; not a rename, but never nests).
      if mv -fT "$tmp" "$prefix/current" 2>/dev/null; then :; else
        ln -sfn "$1" "$prefix/current"; rm -f "$tmp"
      fi ;;
  esac
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

if [ "$rollback" = 1 ]; then
  [ -f "$prefix/.previous" ] || die "no previous version recorded in $prefix/.previous"
  prev=$(cat "$prefix/.previous")
  valid_version "$prev" || die "corrupt $prefix/.previous"
  [ -x "$prefix/$prev/blastbox-agent" ] || die "previous version $prev is not installed"
  cur=$(current_target || true)
  flip_current "$prev"
  if [ -n "$cur" ] && [ "$cur" != "$prev" ]; then
    printf '%s\n' "$cur" > "$prefix/.previous"
  fi
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

mkdir -p "$prefix"
stage=$(mktemp -d "$prefix/.stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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
mkdir -p "$dest"
cp "$stage/$bin" "$dest/blastbox-agent.new"
chmod 0755 "$dest/blastbox-agent.new"
mv -f "$dest/blastbox-agent.new" "$dest/blastbox-agent"

# 5. flip current atomically; remember what it pointed at
cur=$(current_target || true)
flip_current "$version"
if [ -n "$cur" ] && [ "$cur" != "$version" ]; then
  printf '%s\n' "$cur" > "$prefix/.previous"
fi
say "installed $version to $dest (current -> $version)"
