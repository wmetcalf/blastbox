Security scan complete. Report paths:

- Primary report: [report.md](/tmp/codex-security-scans/blastbox/c7e9f28495e1_20260626T144948Z/report.md)
- Canonical findings: [findings.json](/tmp/codex-security-scans/blastbox/c7e9f28495e1_20260626T144948Z/findings.json)
- Coverage: [coverage.json](/tmp/codex-security-scans/blastbox/c7e9f28495e1_20260626T144948Z/coverage.json)
- SARIF: [results.sarif](/tmp/codex-security-scans/blastbox/c7e9f28495e1_20260626T144948Z/exports/results.sarif)

Finding count: 5 reportable findings: 4 medium, 1 low.

Top findings:
- Medium: Ingress job/artifact API is open when no API key or proxy is configured.
- Medium: UrlGrab redirects can read worker-local files into artifacts.
- Medium: Credential-bearing `httpproxy` URLs are passed into worker env.
- Medium: Libvirt VM egress can apply without mandatory MAC and IPv6 fail-closed guards.
- Low: Open engine allowlist lets submitters create unbounded metrics labels.

Verified finalizer exit 0, complete coverage over 97 reviewed files, and discovery/validation/attack-path receipts for every finding. No project source files were modified. Goal usage recorded: 1,016,114 tokens, 3,095 seconds.