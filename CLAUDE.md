<!-- markdownlint-disable MD022 MD025 MD026 -->
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
#
# QuReddy repository guidance for Claude Code and other coding agents.
<!-- markdownlint-enable MD022 MD025 MD026 -->

## Contents

1. [Instruction hierarchy](#instruction-hierarchy)
2. [Architecture](#architecture)
3. [Deliberate QuReddy divergences](#deliberate-qureddy-divergences)
4. [Temporary workspace policy](#temporary-workspace-policy)
5. [Change procedure](#change-procedure)

## Instruction hierarchy

Read and apply these sources in order:

1. **Platform guidance from the parent checkout.** This is the BQP-wide contract for
   licensing, canonical repositories, Python/OpenSSL baselines, worktree and PR
   procedure, and cross-repository architecture. It is auto-loaded because Claude
   Code walks up from the working directory. Platform policy remains authoritative
   for cross-repo and safety rules; record any deliberate repo exception below.
2. **This file (QuReddy guidance).** These are rules specific to this repository.
   They refine, but do not silently weaken, the platform contract.
3. **`AGENTS.md` (QuReddy operating card).** This records the numbered ten-step
   development process and fast command path. Follow it in order and mark skipped
   steps `NOT RUN` with a reason.
4. **Task-scoped skills under `.claude/skills/` and the installed BreachSAFE skill
   library.** Use the narrowest applicable skill and follow its audit/implementation
   boundary. If a skill conflicts with platform or repository guidance, stop and
   resolve the conflict explicitly.

For code comments and docstrings, use the single repository contract in
[`docs/contributors/coding-rules.md` §10](docs/contributors/coding-rules.md#section-10--comments-and-docstrings).
Comments are part of the review surface: preserve the reason, invariant, boundary,
failure semantics, provenance, and test intent that a future agent or human needs.

## Architecture

The engine is a layered package under `src/qureddy/`. `import-linter` (contract `#360`,
run with `lint-imports`) enforces the dependency direction: a lower layer importing a
higher one fails the gate. Read the direction as "imports downward only".

```text
cli  ->  output  ->  scanners  ->  core        (import-linter layers)
                                     ^
                        collectors  -+          (adapter: imports core only)
```

| Layer (`qureddy.<pkg>`) | Holds | May import |
|---|---|---|
| `cli` | Typer app and subcommands: `main` (app assembly, exit-code wrapper), `scan`, `ssh`, plus `_options`, `_render`, `_errors`, `_help`, `_execute` | `output`, `scanners`, `collectors`, `core` |
| `output` | Result rendering: `console/` (tables, verdict, evidence), `json`, `jsonl`, and the `cbom*` CycloneDX emitters | `scanners`, `core` |
| `scanners` | Probing engines by protocol: `tls/`, `ssh/`, and shared `common/` (posture, rollup, findings) | `core` |
| `core` | Domain foundation: `models`, `contracts`, `policy`, `evaluation`, `targets`, `certificate`, `ciphers`, `signatures`, `pqc`, `registry`, `logging`. Imports nothing above it | none |

`collectors/` (`native.py`: `NativeSSHCollector`, `NativeTLSCollector`) is a target-acquisition
adapter that imports only `core.contracts`, `core.errors`, and `core.targets`, and is consumed
by `cli.ssh`. It sits outside the four-layer `import-linter` contract.

**CLI entry point.** `[project.scripts]` in `pyproject.toml` binds the console script
`qureddy = "qureddy.cli:main"`. It points at `main()` (in `cli/main.py`), not the Typer `app`
object, because the `main()` wrapper translates `click.UsageError` to exit code 4; binding
`:app` would let Click return exit 2 for usage errors and collide with the target-scan-failure
code. `python -m qureddy` reaches the same `main()` via `__main__.py`.

## Deliberate QuReddy divergences

- **License:** QuReddy is an Apache-2.0 repository. Do not apply the platform
  PolyForm default to existing QuReddy source or new QuReddy-owned files without a
  reviewed licensing decision; preserve third-party notices and run `reuse lint`.
- **Canonical source:** only `github.com/breachsafe/qureddy` is authoritative. Do not
  use similarly named personal or legacy repositories for source, release, or issue
  decisions.
- **Distribution:** TestPyPI is the only Python package index in scope for the
  foreseeable future. Releases publish to TestPyPI only. Production PyPI is out of
  scope: do not probe it, publish to it, or treat a production PyPI 404 as a failure.
- **Runtime baseline:** Python commands, hooks, environments, and CI use Python 3.14+
  everywhere, and native
  OpenSSL validation uses the pinned 3.5.7 LTS contract.
- **SSH scope:** the SSH acquisition redesign and `ssh-audit` work remain parked in
  the 0.5.0 backlog unless a maintainer explicitly changes that scope.

## Temporary workspace policy

All QuReddy temporary worktrees, pressure-test outputs, build artifacts, and disposable
logs MUST use the RAM-backed workspace when it is mounted:

```bash
export TMPDIR=/Volumes/ramlogs/tmp/qureddy
mkdir -p "$TMPDIR"
chmod 700 "$TMPDIR"
```

Check free space before large runs. Keep the canonical checkout, Git history, credentials,
virtual environments, and irreplaceable artifacts on persistent storage. Do not replace,
symlink, or globally redirect macOS `/tmp`. If the RAM volume is absent or too small, use
system `/tmp` only as a documented exception and report it in the handoff.

## Change procedure

Use an isolated worktree, pressure-test in a temporary environment, run the relevant
quality/release/anti-pattern gates, open a focused PR, and merge only after hosted
checks and artifact identity checks pass. Never treat a green job that did not execute
as a passing gate.
