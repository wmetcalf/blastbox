# Repository Guidelines

## Project Structure & Module Organization

`blastbox` uses a Python `src/` layout. Core package code lives in `src/blastbox/`:
`contract/` defines typed result envelopes, `worker/` contains engine harness and sandbox support,
`host/` contains ingress, dispatch, job stores, pools, and runtime backends, and `bench/` contains
benchmarks. Tests mirror these areas under `tests/` (`tests/contract`, `tests/worker`,
`tests/host`, `tests/bench`, `tests/perf`, and `tests/integration`). Runtime assets are
under `deploy/`, with Firecracker and gVisor helpers in `deploy/firecracker/` and `deploy/gvisor/`.
Notes and plans are kept in `docs/`.

## Build, Test, and Development Commands

- `python -m pip install -e '.[dev]'`: install the package plus test, type, and lint tools.
- `python -m pip install -e '.[host,dev]'`: include host API, job store, and observability dependencies.
- `pytest`: run the default test suite configured in `pyproject.toml`.
- `pytest -m integration`: run integration tests that need sandbox/runtime dependencies.
- `pytest -m perf`: run performance gates; these skip when required host capabilities are missing.
- `ruff check src tests scripts`: lint Python sources and helper scripts.
- `mypy src`: type-check the package.
- `blastbox --help`: inspect the installed CLI entry point.

## Coding Style & Naming Conventions

Target Python 3.12 and keep modules typed; `src/blastbox/py.typed` marks the package as PEP 561 typed.
Use 4-space indentation, snake_case for modules/functions, PascalCase for classes and Pydantic models,
and UPPER_SNAKE_CASE for constants. Keep engine-facing contracts small and explicit. Prefer standard
library path and JSON helpers over ad hoc string handling for filesystem and metadata work.

## Testing Guidelines

Tests use pytest. Name files `test_*.py` and place them near the corresponding subsystem directory
under `tests/`. Add focused unit tests for contract, host, worker, or runtime changes; use marked
integration, docker, and perf tests only when behavior requires external runtimes. Keep new tests
deterministic and ensure sandbox-dependent cases skip cleanly when prerequisites are absent.

## Commit & Pull Request Guidelines

Recent commits use concise prefixes such as `fix:`, `harden:`, and `docs(review):`. Follow that style:
write an imperative, lower-case subject that explains the behavioral change. Pull requests should
include a short problem statement, the implementation summary, test results, linked issues or design
docs when relevant, and deployment/runtime notes for Firecracker, gVisor, sandbox, or security changes.

## Security & Configuration Tips

Treat worker output as untrusted. Preserve host-side re-sealing, path confinement, and limit checks when
changing contracts or runtimes. Document new environment variables near the feature and avoid weakening
fail-closed runtime selection without an explicit test and rationale.
