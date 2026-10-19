"""``blastbox attest verify`` -- verify a job's execution receipt from the client side.

Lives in the lean client package (no ``blastbox[host]`` needed; ``cryptography`` comes with
``blastbox[verify]``) and is registered on the main ``blastbox`` CLI; also reachable as
``python -m blastbox.client.cli``.

Exit status: 0 verified; 1 NOT verified (no receipt, bad signature, unknown key, any binding
mismatch, a non-retryable fetch failure); 2 usage or key-configuration error; 3 not verified
YET -- a retryable condition (the job is still running, 429/5xx, network error, timeout).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import sys
from pathlib import Path

EXIT_VERIFIED = 0
EXIT_NOT_VERIFIED = 1
EXIT_USAGE = 2
EXIT_RETRY = 3

#: Where the bearer token is read from when --token-file is not given: the same variable the
#: ingress reads its token from.
TOKEN_ENV = "BLASTBOX_API_KEY"


def add_parser(sub: argparse._SubParsersAction) -> None:
    pa = sub.add_parser("attest", help="verify execution receipts (client side)")
    pas = pa.add_subparsers(dest="attest_action", required=True)
    pv = pas.add_parser(
        "verify",
        help="fetch a job's receipt + metadata from an ingress and verify them against pinned "
             "keys",
        description="Fetch GET /v1/jobs/{id}/attestation and /metadata from the ingress, verify "
                    "the receipt's ES256 signature under a PINNED dispatcher key (selected by "
                    "the receipt's key_id; an unpinned key_id fails), and bind it to this job, "
                    "to the fetched metadata.json bytes and, with --input, to the bytes you "
                    "submitted. Exit 0 verified, 1 not verified, 2 usage/key error, 3 retry "
                    "later (job not finished, server/network trouble).")
    pv.add_argument("--url", required=True, help="the ingress base URL (http:// or https://)")
    pv.add_argument("--job", required=True, help="the job id POST /v1/jobs returned")
    pv.add_argument("--key", action="append", required=True, metavar="PATH",
                    help="a pinned dispatcher public key: the PEM (the output of `blastbox "
                         "attest-key` works as-is) or the JSON body of GET "
                         "/v1/attestation/key. Repeat once per signing host")
    pv.add_argument("--input", metavar="FILE",
                    help="the file you submitted; its sha256 must equal the signed "
                         "input_sha256 (without it the input is NOT checked)")
    pv.add_argument("--engine", help="require the signed engine to be this")
    pv.add_argument("--max-age", type=float, metavar="SECONDS",
                    help="refuse a receipt issued longer ago than this")
    pv.add_argument("--cacert", metavar="PEM",
                    help="CA bundle to verify the ingress's TLS certificate against (e.g. the "
                         "blastbox PKI CA); default: the system trust store")
    pv.add_argument("--token-file", metavar="PATH",
                    help=f"file holding the ingress bearer token (default: ${TOKEN_ENV}, if "
                         "set). Never passed on the command line")
    pv.add_argument("--timeout", type=float, default=30.0, metavar="SECONDS",
                    help="per-request time budget (default 30)")
    pv.add_argument("--max-metadata-bytes", type=int, default=None, metavar="N",
                    help="largest metadata.json to download (default 64 MiB)")
    pv.add_argument("--metadata-out", metavar="PATH",
                    help="after a successful verification, write the VERIFIED metadata.json "
                         "bytes here (act on these, not on a separate fetch)")
    pv.add_argument("--json", action="store_true", help="print the verified fields as JSON")
    pv.set_defaults(func=_cmd_verify)


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _write_atomic(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` whole or not at all: a reader never sees a partial file."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "xb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _token(args: argparse.Namespace) -> str | None:
    if args.token_file is not None:
        text = Path(args.token_file).read_text(encoding="utf-8").strip()
        if not text:
            raise ValueError(f"{args.token_file} is empty")
        return text
    return (os.environ.get(TOKEN_ENV) or "").strip() or None


def _show(value: object) -> str:
    # json.dumps escapes control characters, so a signed string can never drive the terminal.
    return json.dumps(value)


def _print_human(receipt) -> None:  # noqa: ANN001 - VerifiedReceipt, imported lazily
    print(f"VERIFIED: job {receipt.job_id}")
    print(f"  signed by key_id   {receipt.key_id} (host {_show(receipt.host)})")
    print(f"  engine             {_show(receipt.engine)}")
    print(f"  status             {_show(receipt.status)}")
    print(f"  worker_runtime     {_show(receipt.worker_runtime)}")
    print(f"  worker_tier        {_show(receipt.worker_tier)}")
    print(f"  input_sha256       {receipt.input_sha256} "
          + ("(matches --input)" if receipt.input_bound
             else "(NOT checked: pass --input to bind it to the file you submitted)"))
    print(f"  metadata_sha256    {receipt.metadata_sha256} (matches the fetched metadata.json)")
    print(f"  started/finished   {receipt.started_at_ms} / {receipt.finished_at_ms} (epoch ms)")
    print(f"  issued_at_ms       {receipt.issued_at_ms}")
    net = receipt.network
    if net is None:
        print("  network            NOT ATTESTED (the signer did not enforce/verify the posture "
              "for this run; this does not mean 'no network')")
    else:
        print(f"  network            policy {_show(net.policy_effective)}, exit "
              f"{_show(net.exit)}, downgraded {_show(net.downgraded)}, inspect "
              f"{_show(net.inspect)}")


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        from blastbox.client import verify as v
    except ImportError as exc:
        _err(f"error: {exc}")
        return EXIT_USAGE

    # An option given with an EMPTY value (`--cacert "$CA"` with CA unset) is a usage error,
    # never "absent": treating it as absent would silently drop what the caller asked for
    # (input binding, a private CA, the token file, the metadata output).
    empty = ["--key"] if "" in args.key else []
    empty += [name for name, value in (
        ("--input", args.input), ("--cacert", args.cacert), ("--token-file", args.token_file),
        ("--metadata-out", args.metadata_out), ("--engine", args.engine),
    ) if value == ""]
    if empty:
        _err(f"error: {empty[0]}: empty value")
        return EXIT_USAGE

    try:
        keys = v.load_pinned_keys(*(Path(p) for p in args.key))
    except v.VerifyKeyRefused as exc:
        _err(f"error: --key {exc}")
        return EXIT_USAGE
    expect_input = None
    if args.input is not None:
        try:
            expect_input = _sha256_file(args.input)
        except OSError as exc:
            _err(f"error: --input {args.input}: {exc.strerror or exc}")
            return EXIT_USAGE
    try:
        token = _token(args)
    except (OSError, ValueError) as exc:
        _err(f"error: --token-file: {exc}")
        return EXIT_USAGE
    ctx = None
    if args.cacert is not None:
        try:
            ctx = ssl.create_default_context(cafile=args.cacert)
        except (OSError, ssl.SSLError) as exc:
            _err(f"error: --cacert {args.cacert}: {exc}")
            return EXIT_USAGE
    kwargs: dict = {}
    if args.max_metadata_bytes is not None:
        kwargs["max_metadata_bytes"] = args.max_metadata_bytes
    try:
        result = v.fetch_and_verify(
            args.url, args.job, keys=keys, expect_input_sha256=expect_input,
            expect_engine=args.engine, max_age=args.max_age, token=token,
            timeout=args.timeout, ssl_context=ctx, **kwargs)
    except v.ReceiptError as exc:
        retry = isinstance(exc, v.FetchError) and exc.retryable
        _err(f"NOT VERIFIED ({exc.code}{', retryable' if retry else ''}): {exc}")
        if args.json:
            print(json.dumps({"verified": False, "code": exc.code, "retryable": retry,
                              "error": str(exc)}))
        return EXIT_RETRY if retry else EXIT_NOT_VERIFIED
    except (TypeError, ValueError) as exc:
        _err(f"error: {exc}")
        return EXIT_USAGE

    if args.metadata_out is not None:
        try:
            _write_atomic(Path(args.metadata_out), result.metadata)
        except OSError as exc:
            _err(f"error: --metadata-out {args.metadata_out}: {exc.strerror or exc}")
            return EXIT_USAGE
    if args.json:
        print(json.dumps(result.receipt.as_dict(), sort_keys=True))
    else:
        _print_human(result.receipt)
    return EXIT_VERIFIED


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="blastbox")
    sub = p.add_subparsers(dest="command", required=True)
    add_parser(sub)
    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
