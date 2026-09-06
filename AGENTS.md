<!--
SPDX-FileCopyrightText: 2026 BreachSAFE
SPDX-License-Identifier: Apache-2.0
-->

# QuReddy agent fast path

This file is the compact operating card for coding agents. Read `CLAUDE.md` for
the complete policy; this file intentionally avoids restating it.

## Contents

1. [Non-negotiable context](#non-negotiable-context)
2. [Ten-step change loop](#ten-step-change-loop)
3. [Fast command card](#fast-command-card)
4. [Handoff format](#handoff-format)

## Non-negotiable context

- Canonical repository: `github.com/BreachSAFE/qureddy`.
- Python baseline: 3.14+; use `uv run --locked` for project commands.
- Release index: TestPyPI only. Production PyPI is out of scope.
- Existing repository license is Apache-2.0; preserve it unless a maintainer makes
  an explicit licensing decision.
- Keep SSH acquisition/`ssh-audit` migration parked in the 0.5.0 backlog.
- Do not infer that a green command ran all checks. Record commands and exit codes.
- Code comments and docstrings must preserve reviewer/agent context; follow the
  [commenting contract](docs/contributors/coding-rules.md#section-10--comments-and-docstrings).

## Ten-step change loop

1. Inventory the issue, current tree, local guidance, and applicable skills.
2. Steelman the problem and the smallest defensible fix.
3. Reproduce the current behavior in an isolated `/tmp` workstream first.
4. Pressure-test alternatives, malformed input, compatibility, and regressions.
5. Implement the smallest surgical change in a focused worktree.
6. Add or update regression tests that fail before the fix.
7. Run the project gates and record real exit codes.
8. Run the anti-pattern/architecture self-check, including size and duplication review.
9. Update the issue, commit, push, and open/merge only with explicit authorization.
10. For a release, verify the package, image, and real CLI smoke path separately.

If a step is not run, report `NOT RUN` and why. Never replace an isolated
reproduction with a patched-state test.

## Fast command card

```bash
cd <repo-root>
uv sync --locked --extra dev
uv run --locked pytest tests/test_<area>.py -q
just gates
just hooks
just docs
just release-gate
```

Use `just test-unit` for a quick local loop and `just gates` before handoff.
Use `just test-live` only when network access is intentional. For a temporary
workstream, copy the candidate tree into a fresh `/tmp/qureddy-<issue>-*`
directory, run the same locked commands there, and preserve its logs.

## Handoff format

End each milestone with only:

```text
State: <clean|dirty>; commit/tag: <value>
Changed: <files and one-line purpose>
Evidence: <commands with pass/fail and key counts>
Open: <issue IDs or NOT RUN items>
Next: <one concrete action>
```

Do not paste entire source files or repeated command output unless the user asks
for a specific excerpt. Link to files and quote only the relevant lines.
