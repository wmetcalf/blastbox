"""Generic host-side transport for the remote HTTP worker agent (`blastbox.worker.http_agent`).

The dispatcher posts one job's input bytes to a remote worker over HTTP and gets back a tar of the
worker's sealed output dir (metadata.json + artifacts), which it extracts into the job's output/ dir --
exactly as if a local sandbox had written there. Engine-agnostic: works for any engine served by the
generic agent, over either an EC2 instance (`ip:port`) or a Lambda MicroVM (`url` + JWE token).

Plugs into `VmJobDispatcher(validate=...)` (or a pool_manager-style claim loop) via `make_remote_validate`.
"""

from __future__ import annotations

import io
import json
import logging
import os
import shutil
import tarfile
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

_log = logging.getLogger("blastbox.host.runtime.remote_http")

# Injectable HTTP seam (tests pass a fake returning canned tar bytes; default hits the network).
HttpOpen = Callable[[urllib.request.Request, float], Any]


def _default_open(req: urllib.request.Request, timeout: float) -> Any:
    return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 (url is host-built)


class _Slot(Protocol):
    """The subset of a runtime slot this transport needs (AwsWorkerSlot / VmSlot both satisfy it)."""
    ip: str | None
    url: str | None
    auth_token: str | None
    agent_port: int


def slot_base_url(slot: _Slot) -> str:
    """Resolve the worker's base URL: a Lambda-MicroVM `url`, else `http://<ip>:<port>` (EC2/VM)."""
    if getattr(slot, "url", None):
        return str(slot.url).rstrip("/")
    ip = getattr(slot, "ip", None)
    if ip:
        return f"http://{ip}:{getattr(slot, 'agent_port', 8765)}"
    raise ValueError("slot has no reachable endpoint (no url and no ip)")


def _safe_extract_tar(tar_bytes: bytes, dest: Path) -> list[str]:
    """Extract regular files from ``tar_bytes`` into ``dest``, rejecting path traversal. Returns the
    relative paths written."""
    dest = dest.resolve()
    written: list[str] = []
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            target = (dest / m.name).resolve()
            if target != dest and not str(target).startswith(str(dest) + os.sep):
                _log.warning("remote_http: dropping traversal member %r", m.name)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with src, target.open("wb") as out:
                shutil.copyfileobj(src, out)
            written.append(str(target.relative_to(dest)))
    return written


def detonate_remote(
    base_url: str,
    input_path: Path,
    output_dir: Path,
    *,
    token: str | None = None,
    agent_port: int = 8765,
    timeout: float = 600.0,
    http_open: HttpOpen | None = None,
) -> dict[str, Any]:
    """POST ``input_path`` to the remote agent's ``/detonate``; extract the returned sealed output tar
    into ``output_dir``; return the parsed ``metadata.json`` (empty dict if the worker produced none)."""
    opener = http_open or _default_open
    url = base_url.rstrip("/") + "/detonate?name=" + quote(input_path.name)
    headers = {"Content-Type": "application/octet-stream"}
    if token:
        headers["X-aws-proxy-auth"] = token
        headers["X-aws-proxy-port"] = str(agent_port)
    req = urllib.request.Request(url, data=input_path.read_bytes(), method="POST", headers=headers)
    with opener(req, timeout) as resp:
        tar_bytes = resp.read()
    output_dir.mkdir(parents=True, exist_ok=True)
    _safe_extract_tar(tar_bytes, output_dir)
    meta = output_dir / "metadata.json"
    if meta.exists():
        return json.loads(meta.read_text())
    return {}


def make_remote_validate(
    claim: Callable[[], _Slot],
    release: Callable[[_Slot], None],
    output_dir_for: Callable[[Path], Path],
    *,
    token: str | None = None,
    timeout: float = 600.0,
    http_open: HttpOpen | None = None,
) -> Callable[[Path], tuple[dict[str, Any] | None, bool]]:
    """Build a ``validate(input_path) -> (metadata, ok)`` for a network-endpoint dispatcher.

    ``claim``/``release`` manage a warm slot from the pool (AWS or VM); ``output_dir_for(input_path)``
    gives the job's output dir the sealed artifacts land in. The worker's own JWE (``slot.auth_token``)
    is preferred over the static ``token``. A transport/agent failure returns ``(None, False)`` so the
    dispatcher fails the job rather than emitting a bogus verdict.
    """

    def validate(input_path: Path) -> tuple[dict[str, Any] | None, bool]:
        slot = claim()
        try:
            base = slot_base_url(slot)
            meta = detonate_remote(
                base, input_path, output_dir_for(input_path),
                token=getattr(slot, "auth_token", None) or token,
                agent_port=getattr(slot, "agent_port", 8765),
                timeout=timeout, http_open=http_open,
            )
            return meta, True
        except Exception as exc:  # noqa: BLE001
            _log.warning("remote_http: validate failed: %s", exc)
            return None, False
        finally:
            release(slot)

    return validate
