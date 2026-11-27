# Releasing blastbox-agent

Releases are built and signed by `.github/workflows/agent-release.yml`. Nobody
signs on a laptop; there is no long-lived signing key (cosign keyless, Sigstore).

## Cut a release

```text
git tag agent-vX.Y.Z <commit on main>
git push origin agent-vX.Y.Z
```

The tag push is the only trigger. The workflow runs `go test ./...`, builds
darwin/linux x amd64/arm64 twice in two clean checkouts, fails if the two
builds differ (`cmp`), writes `SHA256SUMS`, signs it with
`cosign sign-blob --bundle SHA256SUMS.sigstore.json`, and creates the GitHub
release `agent-vX.Y.Z` with the binaries, `SHA256SUMS`, the bundle, `sbom.txt`
(`go version -m` per binary) and `conformance-digest.txt`. `SHA256SUMS` lists the
sidecars too, so the signature covers them. The workflow then runs
`cosign verify-blob` with the same identity the installer pins.

## What the signature proves

The signer identity is the workflow file at the tag ref
(`agent-release.yml@refs/tags/agent-vX.Y.Z`). Anyone who can push a tag can run
that file from any commit, including one whose copy of the workflow has been edited.
The workflow's "tag is on main" check runs inside that same file, so it is a
tripwire for mistakes and not a trust anchor. Two things bind a release to reviewed
code:

```text
a repository tag ruleset on agent-v* (restrict creation, deletion and update to release maintainers)
the operator's pinned --sha256, taken from a release verified out of band
```

Enable immutable releases as well, so a published release's assets and tag cannot
be swapped under the same version.

`publish.yml` (PyPI) skips releases whose tag starts with `agent-v`. Keep that
guard; without it an agent release would publish the Python package.

## Reproducibility

Build flags: `CGO_ENABLED=0 go build -trimpath -buildvcs=true -ldflags "-s -w
-buildid= -X main.version=X.Y.Z"` with Go pinned in the workflow. To check a
release locally, build the same tag with the same Go version and compare the
sha256 with `SHA256SUMS`.

## Install and verify

```text
agent/install.sh --version X.Y.Z --sha256 <sha256 of your platform's binary>
```

Take the sha256 from `SHA256SUMS` of a release you have verified out of band.
The installer checks the pinned sha256 first, then runs
`cosign verify-blob` requiring identity
`https://github.com/wmetcalf/blastbox/.github/workflows/agent-release.yml@refs/tags/agent-vX.Y.Z`
and issuer `https://token.actions.githubusercontent.com`, then installs to
`<prefix>/X.Y.Z/blastbox-agent` and flips `<prefix>/current`.
Use cosign v3.x to verify; the bundle is written by cosign v3.
`--rollback` flips back to the version in `<prefix>/.previous`. One run at a time
holds `<prefix>/.lock`; remove it by hand only if a killed run left it behind. `--no-cosign`
(only with `--sha256`) skips the signature check and is weaker; use it only
where cosign cannot be installed.

## Rotating the pin

The expected signer identity is derived from the repo, workflow path and tag in
`install.sh` and the workflow. If the workflow file is renamed or the repo
moves, change both together and ship a new installer before the next release.
