"""Client-side helpers for consumers of a blastbox ingress.

Lean by design: nothing here imports the host stack (FastAPI, the dispatcher, the job stores).
:mod:`blastbox.client.verify` needs only ``cryptography`` (``pip install 'blastbox[verify]'``)
and is imported from there explicitly::

    from blastbox.client.verify import fetch_and_verify, load_pinned_keys, verify_receipt
"""
