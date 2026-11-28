# blastbox-agent (Go)

Pull worker agent. Build: `CGO_ENABLED=0 go build ./cmd/blastbox-agent` (Go 1.22, stdlib plus
`BurntSushi/toml`). Checks: `CGO_ENABLED=0 go vet ./... && go test ./... && gofmt -l .`.

## Optional config keys

```toml
# Seconds without a successful ingress round trip before the agent logs an ERROR.
# Default 90, minimum 15.
ingress_unreachable_after_s = 90

[sound]
on_connect = "modem"   # "" (default, off) or "modem"
```

`blastbox-agent run --config PATH --modem-sound` turns the modem sound on without editing the
config.

## Ingress unreachable

The agent tracks the last successful ingress round trip (any HTTP answer, 2xx to 5xx, counts as
reachable). When none succeeds for longer than `ingress_unreachable_after_s` it logs once at
ERROR:

```text
ingress unreachable for 95s: <cause> [ingress host:port]
```

then repeats at most every 10 minutes while it stays down, and logs INFO when the ingress
answers again. Causes: `EADDRNOTAVAIL` (local source address not available), connection
refused, no route (`ENETUNREACH`/`EHOSTUNREACH`), timeout, TLS verification failure, DNS failure.
This is local logging only: the heartbeat cannot be sent while the ingress is unreachable, and
the control plane's `node_silent` alert covers the other side. The agent never runs sudo and
never touches routes.

### Route finding

No route pin is needed for plain outbound HTTPS to the ingress. On the Mac, a static host route
to the ingress left over from an old DHCP address made every connect fail with `EADDRNOTAVAIL`
("can't assign requested address") for hours, although the default route would have worked. If
you see that cause: run `route -n get <ingress-host>`, and if it shows a static route, delete
it (`sudo route -n delete -host <ingress-host>`, run by you, not by the agent).

## Modem connect sound (off by default)

When enabled, the agent plays a ~4 s dial-up handshake once per process: on the first successful
session handshake after the agent starts (service start, enable, boot). It does not play on
reconnects after a network drop or on session renewal.

* The sound is synthesised in Go, deterministically (8 kHz mono 16-bit PCM WAV): DTMF digits,
  440+480 Hz ringback, a 2100 Hz ANSam answer tone with 180 degree reversals every 450 ms and
  15 Hz AM, then LFSR-scrambled noise band-limited to about 600-3400 Hz with two carrier-ish
  tones. No recordings are embedded.
* The WAV is written once to `<state_dir>/modem.wav` (tmp + rename, mode 0600) and regenerated
  if missing. Nothing is generated or played when the sound is off.
* Playback is best effort and asynchronous, so it never delays a handshake or a claim. macOS
  uses `/usr/bin/afplay`; Linux uses `paplay` if on PATH, else `aplay -q`, else nothing. The
  player runs with an explicit argv, a minimal environment and no shell, is killed after 10 s,
  and a failure is logged at DEBUG only.
