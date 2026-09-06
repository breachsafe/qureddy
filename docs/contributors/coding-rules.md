# Coding Rules — BreachSAFE QuReddy

[![Contributor guide](https://img.shields.io/badge/QuReddy-contributor%20guide-6e7781?style=flat-square)](../README.md#3-contributor-documentation)

These are the engineering standards for QuReddy. They apply to every contributor: humans, AI agents, and reviewers. They are not aspirational.

This document is concrete enough to be a checklist. The default is: when your code disagrees with this document, change the code. But this document is sometimes wrong (engineering rules age, projects evolve, edge cases exist). When you genuinely believe a rule is wrong for the situation in front of you, surface the conflict per Section 20 ("When You Disagree With This Document") rather than silently violating or silently following.

This document covers Python authoring rules, CI/CD gates, security bar, and self-scanning discipline. Project orientation lives in `docs/explanation/architecture.md`.

QuReddy targets the **OpenSSF Best Practices passing tier**. Rules below are mapped to OpenSSF criteria where applicable.

> **Note on repository-only references.** Two rules reference `docs/SECURITY_EXCEPTIONS.md` and `docs/STANDARDS.md`; keep those references explicit until the corresponding repository files exist. Do not create empty placeholder files.

## Contents

1. [Scope and Discipline](#section-1--scope-and-discipline)
2. [File and Function Size](#section-2--file-and-function-size)
3. [Naming](#section-3--naming)
4. [Type Hints and Static Typing](#section-4--type-hints-and-static-typing)
5. [Imports](#section-5--imports)
6. [Error Handling](#section-6--error-handling)
7. [Subprocess Discipline](#section-7--subprocess-discipline)
8. [Logging](#section-8--logging)
9. [Testing](#section-9--testing)
10. [Comments and Docstrings](#section-10--comments-and-docstrings)
11. [Output and CLI](#section-11--output-and-cli)
12. [Security Hygiene](#section-12--security-hygiene)
13. [Dependencies](#section-13--dependencies)
14. [Distribution and Platform Support](#section-14--distribution-and-platform-support)
15. [When You Don't Know](#section-15--when-you-dont-know)
16. [What “Done” Means](#section-16--what-done-means)
17. [Things You Do Not Do](#section-17--things-you-do-not-do)
18. [Voice in Code](#section-18--voice-in-code)
19. [Voice in Responses](#section-19--voice-in-responses)
20. [When You Disagree With This Document](#section-20--when-you-disagree-with-this-document)
21. [CI/CD Pipeline](#section-21--cicd-pipeline-7-phases)
22. [Quality Gates](#section-22--quality-gates-tier-1-per-pr-tier-2-per-release)
23. [Pre-commit Hooks](#section-23--pre-commit-hooks)
24. [Self-Scanning](#section-24--self-scanning)
25. [Documentation Link Discipline](#section-25--documentation-link-discipline)
26. [Security Bar](#section-26--security-bar-hard-merge-blockers)
27. [Branch Protection and Merge Hygiene](#section-27--branch-protection-and-merge-hygiene)
28. [Anti-Theater Rules](#section-28--anti-theater-rules)
29. [OpenSSF Best Practices Alignment](#section-29--openssf-best-practices-alignment)
30. [PR Review Checklist](#30-quick-reference--pr-review-checklist-tier-1-must-pass)
31. [Release Checklist](#31-quick-reference--release-checklist-tier-2-must-pass-before-tag)

---

## Section 1 — Scope and Discipline

**Rule 1.1 — Build only what was asked.**
Do not add features, refactor unrelated code, or pre-build for hypothetical futures. If you see something worth fixing outside the task, note it in the PR description as "out of scope, flagged" and move on.
Failure mode: the 2,000-line PR that touches everything and reviews like archaeology.

**Rule 1.2 — Smallest change that meets the spec.**
If the spec can be met in 50 lines, ship 50 lines. Do not pad with helpers, abstractions, or future-proofing. Add the second helper when you have the second use case, not the first.

**Rule 1.3 — One thing per PR.**
A PR adds the cert scanner, OR refactors the parser, OR fixes the JSON output. Not all three. If you find yourself splitting a PR description into "Part 1" and "Part 2," it should be two PRs.

**Rule 1.4 — Out-of-scope work is a comment, not a commit.**
If you notice technical debt while working, write it down. Do not fix it in the same PR. Either open a follow-up issue or add a `# TODO(reason): description` comment with a link to the issue.

**Rule 1.5 — Mechanical formatting changes are separate from behavior changes.**
A PR that runs `ruff format` over the codebase does not also change behavior. Mixed PRs make review impossible because every line of the diff has to be inspected.

---

## Section 2 — File and Function Size

**Rule 2.1 — Functions: 30 lines normal, 50 lines hard ceiling.**
Counted from `def` line to last line of the function body, excluding blank lines and docstrings. Functions over 50 lines either get split or carry a comment explaining why splitting would hurt clarity. The 30-line norm anchors smaller functions; the 50-line ceiling is the absolute upper bound that triggers PR review pushback.
Failure mode: 200-line functions where bug fixes touch four unrelated branches and break two of them.

**Rule 2.2 — Files: 300 lines normal, 400 lines hard ceiling.**
Counted from line 1 to last line, excluding blank lines and module docstrings. Files over 400 lines almost always have a wrong abstraction. Split before you cross 500.
The TLS scanner directory has separate files (`scanner.py`, `openssl_probe.py`, `parse.py`) instead of one `tls.py` for exactly this reason.

**Rule 2.2.1 — Edge bands and per-band actions.**

Files that approach the ceiling without crossing it accumulate silently across PRs. The 400-line cliff produces a pattern where every PR adds 5-15 LOC, files quietly drift from "fine" to "over the ceiling" between merges, and the breach gets filed as a follow-up issue *after* it lands. The bands below catch each transition before the breach.

| Band | LOC range | What it means | Required action |
|---|---|---|---|
| **Green** | 0–319 | Plenty of room | None |
| **Yellow** | 320–360 | At the edge | Note in PR review's "Concerns" section. PR may merge. |
| **Orange** | 361–400 | Imminent breach | **File a refactor follow-up issue at PR-review time.** PR may merge. |
| **Red** | 401+ | Hard ceiling breached | **Block merge** unless the PR body documents `ANTIPATTERN ACCEPTED: file-size-ceiling, because <reason>` AND links the refactor follow-up issue. |

Same edge bands apply to functions per Rule 2.1, scaled to the 50-line ceiling: Green ≤30, Yellow 31–40, Orange 41–50, Red 51+.

The CI workflow `.github/workflows/file-size-gate.yml` enforces Red-band breaches in `src/qureddy/`. Yellow and Orange bands surface as warnings in the workflow output and reviewer skill output; they are not gate-blocking by themselves but are mandatory PR-review items. Test-file splits should mirror the production package or group a coherent behavior when production is single-file. The CI gate currently does not check `tests/`; the rule still applies and is enforced at PR review.

**Rationale.** The cliff version of Rule 2.2 was honor-system. A historical
staging audit after PR #83 (`cli.py` 429 lines and `openssl_probe.py` 424 lines)
showed that good-faith adherence to "no file over 400 lines" still ships
breaches when authors measure the *delta* their PR adds rather than the
*post-merge* file size. Edge bands surface the trajectory, not just the
threshold.

**Rule 2.3 — Modules have one responsibility.**
A file named `parse.py` parses. It does not also fetch, classify, or render. If the module name has "and" or "utils" in it, the responsibility is wrong.
Failure mode: `helpers.py` becoming the dumping ground that nobody understands six months later.

**Rule 2.4 — No `utils.py`, `common.py`, or `helpers.py`.**
If you do not know where a function belongs, the function is wrong, not the file system. Either it has a real home or it should not exist yet.

**Rule 2.5 — Classes: 200 lines or fewer.**
Counted from `class` line to last method line. Classes over 200 lines are doing too much. Split into two classes with clear responsibilities.

---

## Section 3 — Naming

**Rule 3.1 — Names describe what, not how.**
`parse_certificate_chain` not `cert_parser_func`. `TLSEvidence` not `TLSData`. `ScanResult` not `ResultObj`.

**Rule 3.2 — No abbreviations except universal ones.**
Universal: TLS, SSH, RSA, KEX, HMAC, PEM, DER, URL, URI, JSON, XML, HTTP, HTTPS, SNI, OID, IP, DNS, TCP, UDP, FIPS, ML-KEM, ML-DSA, SLH-DSA, CBOM, SBOM. Anything else gets spelled out: `certificate` not `cert` in type names, `configuration` not `config` in module names, `dependency` not `dep`.
Exceptions: `cls`, `self`, `cfg` for argparse Namespace. Local variable abbreviations (`for i in range(n)`) are fine in tight scopes.

**Rule 3.3 — Module names are lowercase, snake_case, singular.**
`scanner.py` not `Scanner.py` not `scanners.py`. The directory pluralizes (`scanners/`), the file inside is singular.

**Rule 3.4 — Class names are CapWords.**
`TLSScanner`, `ScanTarget`, `ParsedNegotiation`. Never `tls_scanner` or `Tls_Scanner`.

**Rule 3.5 — Constants are UPPER_SNAKE_CASE.**
`DEFAULT_TIMEOUT_SECONDS = 30`, `MVP_POLICY = (...)`. Module-level constants only; do not capitalize local "constants."

**Rule 3.6 — Boolean variables and functions read as truth statements.**
`is_supported`, `has_hybrid_pq`, `should_redact`. Not `supported`, `hybrid`, `redact`. The reader should be able to substitute the name into `if X:` and have it read as English.

**Rule 3.7 — No vendor names in core code unless we are targeting that vendor specifically.**
`SymitarCertScanner` is wrong. `LegacyDERCertScanner` is right. Vendor specifics live in vendor-specific modules or config, not in core abstractions.

---

## Section 4 — Type Hints and Static Typing

**Rule 4.1 — Every public function has type hints on every parameter and return value.**

```python
def parse_target(input_str: str, sni_override: str | None = None) -> ScanTarget:
    ...
```

**Rule 4.2 — `mypy --strict` must pass.**
No `# type: ignore` without a specific error code AND a comment explaining why. `# type: ignore[arg-type]  # pydantic v2 dynamic field validation` is acceptable. Bare `# type: ignore` is not.

**Rule 4.3 — `from __future__ import annotations` at the top of every file.**
Enables forward references and makes type hints lazy by default.

**Rule 4.4 — Prefer specific types over `Any`.**
`dict[str, str]` not `dict[str, Any]` unless the value really is heterogeneous. If you find yourself using `Any` more than once or twice in a module, the design is wrong. When `Any` is genuinely needed, use it explicitly with a comment.

**Rule 4.5 — Use `pydantic.BaseModel` for structured data, `Enum` for fixed vocabularies, `pathlib.Path` for filesystem paths.**
Not `dict` for structured data. Not strings for fixed vocabularies. Not `str` for paths.

**Rule 4.6 — Prefer `tuple[X, ...]` over `list[X]` for collections that do not need to be mutated.**
QuReddy uses tuples for findings, evidence, dependencies, references. Tuples are immutable, hashable, and serialize cleanly to JSON arrays. Use lists only when mutation is required and intentional.

**Rule 4.7 — Models are frozen by default.**
`model_config = ConfigDict(frozen=True, extra="forbid")` on every Pydantic model unless there is a specific reason to allow mutation. `extra="forbid"` catches typos in field names and prevents silent acceptance of unknown data.

**Rule 4.8 — All datetimes are timezone-aware UTC.**
`datetime.now(timezone.utc)` not `datetime.now()`. Naive datetimes are forbidden. Ruff's `DTZ` rules enforce this.

---

## Section 5 — Imports

**Rule 5.1 — Imports go at the top of the file.**
No conditional imports inside functions except for genuinely lazy-loaded expensive imports, with a comment explaining why.

**Rule 5.2 — Three groups, in order, with blank lines between.**
Standard library, then third-party, then first-party. Ruff's isort enforces this; do not fight it.

**Rule 5.3 — Absolute imports only.**
`from qureddy.core.models import ScanResult`, not `from ..core.models import ScanResult`. Absolute imports are explicit, grep-able, and resilient to file moves.

**Rule 5.4 — No `from x import *`.** Ever.

**Rule 5.5 — No re-exports through `__init__.py` unless the symbol is genuinely public API.**
Empty `__init__.py` files are fine. `__init__.py` files that import everything from submodules just to "make imports shorter" create circular import risks and obscure where things live. If `qureddy.core.models.ScanResult` is the canonical path, that is the canonical path. Do not also expose it as `qureddy.ScanResult`.

**Rule 5.6 — Environment variables read at the boundary, not in business logic.**
The CLI module (`cli.py`) reads `os.environ` and passes typed values down. Library code accepts parameters; it does not call `os.getenv` directly. Failure mode: business logic that reads the environment cannot be tested without setting environment variables.

---

## Section 6 — Error Handling

**Rule 6.1 — Raise specific exceptions, not bare `Exception`.**
Every error type in QuReddy descends from `QureddyError` (defined in `core/errors.py`). Library code raises specific subclasses. CLI top-level catches `QureddyError` and converts to clean exit codes.

**Rule 6.2 — Never `except: pass`.**
Bare except clauses swallow `KeyboardInterrupt` and `SystemExit`. Even `except Exception: pass` masks bugs and makes the system silently wrong. If you catch an exception, do one of:

- Re-raise after logging context: `log.warning("...", exc_info=True); raise`
- Transform into a domain error: `raise TLSHandshakeFailed(...) from e`
- Handle it specifically with a comment explaining why suppression is correct

**Rule 6.3 — `except` blocks catch specific types.**

```python
try:
    result = subprocess.run(...)
except subprocess.TimeoutExpired:
    raise TLSHandshakeFailed("OpenSSL timed out") from None
except FileNotFoundError as e:
    raise LocalOpenSSLMissing(str(e)) from e
```

**Rule 6.4 — `raise X from e` to preserve the cause chain.**
When transforming an exception, use `from e` so the original traceback is preserved. Use `from None` only when the original exception is genuinely irrelevant to the user.

**Rule 6.5 — The CLI top-level is the only place that catches `QureddyError` broadly.**
In `cli.py`, the outermost handler catches `QureddyError`, logs it, and sets the exit code. Inside the call stack, exceptions propagate as specific types.

**Rule 6.6 — Log AND raise is a code smell.**
If a function logs an error and then raises, the caller will likely log it again. Pick one. Exception: structured log at WARNING with context, then raise, when the context is genuinely useful for debugging.

---

## Section 7 — Subprocess Discipline

**Rule 7.1 — All OpenSSL subprocess execution lives in one module.**
`src/qureddy/scanners/tls/openssl_probe/executor.py`. It is the only file under `src/qureddy/scanners/tls/` that may call `subprocess.run` / `Popen` / `call`; every probe (`probe.py`, `_capability_io.py`, `cert_probe.py`, `legacy_probe.py`) routes through `executor.run_openssl`, which returns an `OpenSSLOutcome` and never raises for a process outcome. Launch failures become the typed exit-3 errors via `executor.raise_for_launch`. Enforced by `scripts/check_openssl_boundary.py`, wired into `scripts/release_gate.py`.
When new external tools are added (e.g., `ssh-audit` for the SSH scanner), each gets its own dedicated probe module.

**Rule 7.2 — `subprocess.run`, never `os.system` or `subprocess.Popen` without justification.**
`os.system` does not capture output cleanly and uses shell parsing. `subprocess.Popen` is fine when you genuinely need streaming I/O, but justify it in a comment.

**Rule 7.3 — Args as a list, never a shell string. `shell=False` always.**

```python
subprocess.run(["openssl", "s_client", "-connect", f"{host}:{port}"], ...)
```

`shell=True` is a shell injection vulnerability. Forbidden.

**Rule 7.4 — Always set `timeout`.**
Default for QuReddy probes is 30 seconds. No subprocess call goes without one.

**Rule 7.5 — Always capture stdout and stderr.**

```python
subprocess.run([...], capture_output=True, text=True, ...)
```

Inspect both, even if you only care about stdout. Stderr often contains the real error.

**Rule 7.6 — `check=False`, inspect returncode manually.**
`check=True` raises `CalledProcessError` which loses useful context. Inspect the return code and raise a domain-specific exception with the relevant evidence.

**Rule 7.7 — Hash subprocess output, do not log it.**
Subprocess stdout/stderr can contain large amounts of data. Log SHA-256 hashes and short previews; never log full output. If you need the full output for debugging, save it to a fixture under `tests/fixtures/`.

---

## Section 8 — Logging

**Rule 8.1 — Every module gets a logger.**

```python
from qureddy.core.logging import get_logger
log = get_logger(__name__)
```

The logger name is `__name__`, which gives `qureddy.scanners.tls.openssl_probe` automatically.

**Rule 8.2 — All logs go to stderr. All scan output goes to stdout. Never mix them.**
Non-negotiable. The user must be able to do:

```
qureddy scan tls google.com --format json > findings.json 2> scan.log
```

If logs leak into stdout, every downstream consumer breaks.

**Rule 8.3 — Structured logging only.**
Pass key-value context to log calls. Do not format strings:

```python
log.info("starting hybrid probe", host=host, port=port, group="X25519MLKEM768")
```

Not:

```python
log.info(f"starting hybrid probe to {host}:{port}")
```

**Rule 8.4 — Log levels, used consistently.**

- DEBUG: flow detail useful only when debugging (parser decisions, internal state)
- INFO: milestones (scan started, probe completed, finding produced)
- WARNING: recoverable problem (probe failed but scan continues)
- ERROR: scan failure (probe failed and scan cannot continue)
- CRITICAL: never used in normal flow

**Rule 8.5 — Never log secrets, full PEMs, full traces, or full subprocess output.**
Cert subjects: yes. SHA-256 fingerprints: yes. Full cert PEM bodies: no. API keys, tokens, credentials: no, ever.

**Rule 8.6 — Subprocess invocations log at INFO with redacted args, timeout, return code, and duration.**
Every subprocess call produces a log line at start and at end. The end-line includes return code and duration in milliseconds. This is the audit trail.

**Rule 8.7 — No `print()` in library code.**
Library code (anything under `src/qureddy/scanners/`, `src/qureddy/core/`) never prints. It returns data or raises. Only the output adapters (`src/qureddy/output/`) write to stdout, and only the logging configuration writes to stderr.

---

## Section 9 — Testing

**Rule 9.1 — Every non-trivial function has a test.**
"Non-trivial" means: branches, loops, parsing, classification, anything beyond a one-liner. Trivial getters and pure data classes do not need tests; they are tested transitively.

**Rule 9.2 — Tests use real fixtures.**
Captured OpenSSL output from a real scan goes in `tests/fixtures/openssl/`. Captured certs go in `tests/fixtures/certs/`. Tests parse the fixtures.
Synthetic test data is acceptable only when fixtures are unavailable. Document why.

**Rule 9.3 — Every test runs every time. No skipped tests, no marker-gated suites at the pytest layer.**
The full suite runs on every PR and every local `pytest` invocation. No `@pytest.mark.acceptance`, no `tests/integration/` directory that runs on a different schedule, no `@pytest.mark.slow` exclusions, no `pytest -m "not X"` shortcuts.

This is a pytest-layer rule. CI may organize the same tests into multiple **jobs** for fail-fast and isolation reasons (the 7-phase pipeline in §21 splits unit, integration, live, etc. into separate CI jobs). Splitting at the CI-job layer is fine and encouraged. What this rule forbids is splitting at the pytest layer with markers that exclude tests from default `pytest` invocations. Locally, `pytest` should run everything.

Slow CI is acceptable; missing coverage is not.

**Rule 9.4 — Network-dependent tests are explicitly allowed and required.**
Hitting real targets (Cloudflare, badssl.com, AWS endpoints) catches middlebox, MTU, SNI, and certificate-edge-case regressions that captured fixtures cannot. Live tests live in `tests/live/` and run with the default `pytest` invocation.

**Rule 9.5 — Test runner uses `pytest-rerunfailures` globally.**
Each test gets up to 3 attempts with a 1-second delay before being declared failed. Configured in `pyproject.toml`, not via per-test decorators. The retry knob absorbs transient internet hiccups; it does not mask flaky tests you wrote yourself.

**Rule 9.6 — Tests do not depend on time, randomness, or test-ordering.**
If a test would pass at noon and fail at midnight, it is wrong. If it would pass on your machine but fail in CI, it is wrong. Use `freezegun` or fixed timestamps; seed random sources; explicit environment in `conftest.py`.

**Rule 9.7 — One assertion per concept, not per test.**
A test can have multiple `assert` lines if they verify the same concept. A test should not verify five unrelated concepts. Split it.

**Rule 9.8 — Test names describe what they verify.**
`test_parser_rejects_clienthello_only_hybrid_group` not `test_parser_1`. The name should make the intent clear without reading the body.

**Rule 9.9 — `@pytest.mark.parametrize` for similar cases, not for fundamentally different cases.**
Five tests of "parse various forms of valid input" use parametrize. Do not parametrize across "valid input" and "invalid input"; the assertions differ and the test reads worse.

**Rule 9.10 — No mocks of the thing under test.**
If you are testing `parse_negotiated_group`, do not mock `parse_negotiated_group`. Mock dependencies (file I/O, subprocess) but not the function being tested.

**Rule 9.11 — Coverage is a smell detector, not a goal.**
Aim for >=80% line coverage as a sanity check. Do not write tests purely to hit coverage numbers; that produces tests that do not test.

**Rule 9.12 — Error paths and boundary values are tested, not just happy paths.**
For every public function: test the success case, test each documented exception, test boundary values (empty, max, off-by-one).

---

## Section 10 — Comments and Docstrings

**Rule 10.1 — Every public class and function has a docstring.**
Use Google style. Document intent and observable contract; include Args, Returns, and
Raises sections where they add information not already obvious from the signature.

**Rule 10.1.1: Comments are context for two readers.**
Write for the human reviewer deciding whether the behavior is safe and the future agent
trying not to regress it. Preserve facts that are expensive to rediscover:

- **Why:** the problem or trade-off that makes this implementation necessary.
- **Invariant:** what must remain true for the result to be correct.
- **Boundary:** which layer owns the behavior and which consumers depend on it.
- **Failure semantics:** what absence, uncertainty, timeout, or rejection means.
- **Security/provenance:** the threat, standard, source, or evidence rule behind a decision.
- **Compatibility:** the external schema, tool, runtime, or legacy behavior being preserved.
- **Transition:** a temporary path, its replacement, and the tracking issue when known.
- **Test intent:** the regression or false-green case the test is meant to pin.

Use only the dimensions that apply. A short, precise comment is better than a checklist
dump. Keep the durable rationale beside the behavior it constrains.

**Rule 10.2 — Comments explain why, not what.**
The code says what. Comments explain why the code is the way it is.

```python
# OpenSSL 3.5.7 LTS emits "Server Temp Key" but not "Negotiated TLS1.3 group"
# in -brief mode for X25519MLKEM768. Parse the former.
match = re.search(r"Server Temp Key:\s*(\S+)", stdout)
```

For policy or classification code, state the consequence of getting the decision wrong:

```python
# Preserve an observed but unrated suite as an explicit unknown asset. Dropping it
# would make “unclassified” indistinguishable from “not observed”; do not guess a
# strength or primitive until the reviewed registry replaces this transitional table.
return AlgorithmProperties(
    primitive=cipher_primitive(suite),
    classical_security_level=cipher_classical_bits(suite),
)
```

**Rule 10.2.1: Explain the contract at the narrowest useful layer.**
Module docstrings explain ownership and source boundaries. Public docstrings explain
the callable contract. Inline comments explain a non-obvious branch, ordering rule,
security decision, compatibility constraint, or test seam. Do not duplicate an ADR;
link it and summarize only the local consequence.

**Rule 10.2.2: Claims in comments must be checkable.**
Link standards, issues, or source artifacts for externally derived claims. Name the
schema/version or tool behavior when compatibility depends on it. Do not claim that a
gate, sanitizer, fallback, or test exists unless the repository actually enforces it.

**Rule 10.2.3: Update comments with behavior.**
When a change invalidates a comment, update or delete it in the same change. Never use
line numbers, personal blame, stale incident narratives, speculative future promises,
or comments that merely paraphrase the next line. Use a tracked `TODO(reason)` only
for deliberately deferred work.

**Rule 10.2.4: Tests document the failure mode.**
Test names, class docstrings, and focused comments should identify the behavior pinned:
the input, boundary, expected contract, and regression risk. Do not write comments that
assert a test is complete when the test covers only one path.

**Rule 10.3 — No commented-out code. Ever.**
Git remembers. If it is not running, delete it.

**Rule 10.4 — TODOs require an owner and a reason.**
`# TODO(reason): description` — and only if there is a tracking issue. Floating `# TODO: fix this` becomes permanent debt.

**Rule 10.5 — No decorative banners; useful diagrams are required.**
Use a module docstring for a compact ownership or data-flow diagram. Label every
branch. Do not add ASCII art for decoration.

**Rule 10.5.1 — Every new or modified source file has a useful diagram.**
The diagram shows the file's role, inputs, outputs, and key boundaries. Use a tree for
ownership, a flow for control/data, a state map for lifecycle, or a table for mappings.
Place it in the module docstring or nearest source-level documentation. A stale,
decorative, or vague diagram fails this rule.

**Rule 10.5.2 — Fixes and cleanup revalidate documentation.**
Before approval, compare the changed code with its diagram and comments. Update stale
ownership, flow, invariants, failure semantics, or test-intent text in the same change.
The diagram, comments, and code must describe the same behavior.

**Rule 10.6 — Do not repeat the type hint in the docstring.**
The signature already documents types. The docstring documents intent.

**Rule 10.7 — No `# noqa` or `# fmt: off` without a specific code AND a comment.**
`# noqa: E501  # URL must not be wrapped` is acceptable. Bare `# noqa` is not.

**10/10 review gate.** Before approval, ask: Can a reviewer explain why this code exists,
what must not change, who owns the boundary, what uncertainty/failure means, what
security or provenance rule applies, what compatibility is preserved, whether the path
is transitional, and which test prevents regression? If not, improve the code structure
or add the smallest durable comment that answers the missing question.

---

## Section 11 — Output and CLI

**Rule 11.1 — `stdout` is for scan results, `stderr` is for everything else.**
Scan results: Rich table or JSON output. Logs, progress messages, errors: stderr. The user must be able to redirect them independently.

**Rule 11.2 — No `print()` in library code.**
Restated from Rule 8.7 because of how often this gets violated.

**Rule 11.3 — CLI errors produce specific exit codes.**

- 0: scan completed successfully
- 1: reserved for high-severity findings when that policy is enabled
- 2: target scan failed
- 3: local dependency missing or unsupported
- 4: usage/configuration error
- 70: internal qureddy error (BSD `sysexits.h` `EX_SOFTWARE`)

The current policy does not emit code 1 because its maximum severity is `low`. Adding a high-severity policy rule may enable exit 1.

Code 70 is reserved for internal qureddy bugs (an unhandled exception
escaping `main()`'s last-resort catch). It is distinct from code 2 so
CI scripts branching on `$? == 2` can trust that 2 means "target scan
failed", not "qureddy itself crashed". Per BSD `sysexits.h`,
`EX_SOFTWARE = 70` is the canonical "internal software error" code.
See [`docs/reference/exit-codes.md`](../reference/exit-codes.md) for
the full table and worked CI examples.

**Rule 11.4 — JSON output is machine-stable.**
Field names, types, and structure are part of the API. Adding fields is okay. Removing or renaming fields is a breaking change requiring a `schema_version` bump. Current schema is `qureddy.scan.v1`.

**Rule 11.5 — JSON output uses `model.model_dump(mode="json")` with `schema_version`.**
Do not hand-build dicts for output. Pydantic produces stable serialization; manual dict assembly drifts.

**Rule 11.6 — Findings, evidence, and assets sorted deterministically.**
Same input must produce byte-identical output. Sort lists by `id`, dependencies by name, etc.

---

## Section 12 — Security Hygiene

**Rule 12.1 — Never disable TLS verification in production code paths.**
`verify=False` in requests, `ssl.CERT_NONE` in ssl context. If a target has a bad cert, that is a finding. The scanner does not work around bad TLS.

**Rule 12.2 — `pathlib.Path.resolve()` for any user-supplied path.**

```python
path = Path(user_input).resolve()
if not path.is_relative_to(allowed_root):
    raise ConfigurationError(f"Path outside allowed root: {path}")
```

Prevents path traversal attacks.

**Rule 12.3 — `secrets` module for security-relevant randomness.**
Use `secrets.token_hex()`, `secrets.compare_digest()`. Never `random.choice` for tokens, comparisons, or anything security-relevant.

**Rule 12.4 — Never `eval`, `exec`, or `pickle.loads` on untrusted input.**
JSON for structured data crossing trust boundaries. Do not pickle anything from outside the process.

**Rule 12.5 — Redact secrets before logging or returning.**
If a function might handle credentials, hash or mask them at the boundary. Test the redaction.

**Rule 12.6 — Files, temp files, subprocesses use context managers or explicit cleanup.**
`with open(...)`, `with tempfile.NamedTemporaryFile(...)`, `with subprocess.Popen(...)`. Resource leaks become hangs.

**Rule 12.7 — No module-level mutable state.**
Globals are frozen tuples/strings/ints/Enums. Module-level mutable lists or dicts create test-pollution and threading bugs.

---

## Section 13 — Dependencies

**Rule 13.1 — Every new dependency must justify itself.**

- Replaces at least 50 lines of code we would have written
- Actively maintained (commit in last 12 months)
- License and distribution terms compatible with this Apache-2.0 open-source release; preserve all upstream notices
- Recognizable maintainer or organization

If you are tempted to add a dependency for a one-off task, write the 5 lines yourself.

**Rule 13.2 — Pin dependencies in `uv.lock`.**
Reproducible builds. Lock file is committed. Updates happen deliberately, with PR review.

**Rule 13.3 — Reject AGPL and GPL dependencies.**
QuReddy is open source under the Apache License 2.0. Dependencies must be reviewed for compatibility with its distribution terms; AGPL, GPL, and LGPL dependencies are rejected by default, and every bundled dependency retains its original notices.

**Rule 13.4 — Prefer the standard library.**
`pathlib`, `datetime`, `subprocess`, `re`, `json`, `secrets`, `hmac`, `urllib.request`, `urllib.parse`. The stdlib is well-maintained, well-known, and free. (Note: `urllib3` and `requests` are third-party. The stdlib equivalent is `urllib.request`. Reach for third-party HTTP only if stdlib genuinely falls short.)

---

## Section 14 — Distribution and Platform Support

QuReddy ships as a native Python package. A container image is tracked separately in issue #72 and must pass its own reproducibility, SBOM, vulnerability, and multi-architecture gates before publication.

1. Native Python package via the documented TestPyPI two-index `pipx install breachsafe-qureddy` command. macOS 14+, modern Linux distributions, Windows 10 22H2+.
2. Container image published at an immutable release tag and digest after issue #72 passes.

Both paths target the same modern platforms. Neither runs on EOL operating systems (Windows XP/7/8.1, RHEL 6, Ubuntu 16.04 and earlier).

CI runs the full test suite on **all three platforms** (ubuntu-latest, macos-latest, windows-latest).

Code is written to work on both install paths:

- File paths use `pathlib.Path`, never hardcoded `/tmp` or `/usr/local`
- Subprocess calls find tools via `PATH`, not absolute paths
- Configuration locations are platform-aware (use `platformdirs`)
- Container black-box tests run when the image work in issue #72 is enabled.

---

## Section 15 — When You Don't Know

If you don't know how something should work, you say so explicitly. You do not make up an answer that sounds confident. You ask, or you flag the assumption clearly:

```
ASSUMPTION: I am assuming X because the spec is silent on it. If wrong, change to Y.
```

If you're about to invent a library, API, or function name that you're not 100% sure exists, you stop and verify. Hallucinated imports are the single biggest source of bugs in agentic code.

---

## Section 16 — What "Done" Means

A task is done when **every** item below is true. Not when "tests pass." Not when "code compiles." Done is the full bar.

1. The asked-for functionality works end-to-end
2. All quality gates from Section 22 pass
3. Self-scans from Section 24 pass for the relevant change category
4. Internal documentation links verified (Section 25)
5. No security bar violation from Section 26
6. Tests cover happy path, error paths, and boundary values
7. CHANGELOG.md updated when behavior changes
8. Anti-pattern audit completed and recorded in PR description
9. Any security or self-scan exceptions documented with expiration
10. The diff is the smallest one that meets the spec
11. Mechanical formatting is in a separate commit from behavior changes
12. Reviewer approval recorded (self-review allowed for solo work; the PR record is non-negotiable)

When you finish a task, you respond with:

1. What you did (one paragraph)
2. The diff or new files
3. What you did NOT do that you considered (out-of-scope items, flagged for later)
4. Any assumptions you made
5. Any open questions for the human

---

## Section 17 — Things You Do Not Do

- Refactor unrelated code
- Add features that weren't requested
- Change file structure without explicit instruction
- Add dependencies without justification
- Write more than one file when one was asked for
- Write speculative abstractions for "future flexibility"
- Generate boilerplate that isn't going to be used today
- Add metaclasses, decorators, or complex inheritance unless the spec explicitly requires them
- Use `*args` and `**kwargs` to "be flexible" — be specific about parameters
- Add comments that explain what the code obviously does
- Add `if __name__ == "__main__":` blocks to library modules

---

## Section 18 — Voice in Code

No marketing language in docstrings or comments. No "leverage," no "intersection of," no "robust enterprise-grade solution." Plain English. Same voice the rest of the project uses.

No em dashes anywhere, including in comments and docstrings.

No emoji in code, comments, or docstrings.

No ASCII art banners in source files.

---

## Section 19 — Voice in Responses

When you respond to me with a code task, you:

1. Confirm you understand the task in one sentence
2. Note any ambiguity or assumption before coding
3. Produce the code
4. Summarize what you did and didn't do
5. Stop

You do not over-explain. You do not pad with "Let me know if you need anything else!" or "Hope this helps!" You do not narrate your thinking unless asked.

---

## Section 20 — When You Disagree With This Document

This document is wrong sometimes. Engineering rules age, projects evolve, edge cases exist. When you disagree:

1. Open a PR that proposes changing this document, with reasoning
2. Do not violate the current rules in regular code while you wait
3. If the issue is urgent, mark the violation with `ANTIPATTERN ACCEPTED: <rule>, because <reason>` and link to the issue

The rules are stricter than the average Python project on purpose. Crypto-touching code in security tools costs more when it goes wrong than the discipline costs to maintain.

---

## Section 21 — CI/CD Pipeline (7 Phases)

CI runs as 7 sequential phases. Each phase produces an artifact. Phase 7 (Audit) reads every prior phase's artifact and verifies the run was complete and clean. **A passing exit code from `pytest` is not enough.** The audit phase asserts on specific facts: test count, coverage percent, scanned file count, security finding count, etc.

This structure exists because skim-passing is the failure mode. The audit phase catches tests that pass only because required work was skipped.

### Phase 1 — Static Analysis

No code execution. Pure inspection.

```
ruff check .
ruff format --check .
mypy src/qureddy --strict
bandit -r src/qureddy
pip-audit
pip-licenses --fail-on='AGPL;GPL;LGPL'
trufflehog filesystem . (or gitleaks detect)
```

Artifact: `phase-1-static.json`

### Phase 2 — Unit Tests

Hermetic. No network. No subprocess to real OpenSSL.

```
pytest tests/test_*.py --ignore=tests/live --cov=qureddy --cov-report=xml --cov-fail-under=80
```

Artifact: `phase-2-unit.xml`, `coverage-unit.xml`

### Phase 3 — Integration Tests (Real OpenSSL, No Network)

Real OpenSSL 3.5.7 LTS subprocess. Verifies capability detection and `-brief` parsing against a real binary, but no network connections.

```
pytest tests/test_openssl_probe.py
```

Artifact: `phase-3-integration.xml`

### Phase 4 — Live Tests (Network Required)

Real network connections to the canonical 6 targets. Required to pass on every PR. `pytest-rerunfailures` absorbs transient hiccups (3 attempts, 1s delay).

```
pytest tests/live/
```

Artifact: `phase-4-live.xml`

### Phase 5 — Self-Scan (Once Scanner Exists)

`qureddy` runs against its own canonical target list. The scan must complete without `failure_category` being set at the pipeline level. **Findings of any severity are allowed and reported, not blocked.**

```
qureddy scan tls www.cloudflare.com --format json > self-scan-cloudflare.json
qureddy scan tls pq.cloudflareresearch.com --format json > self-scan-pq-cloudflare.json
qureddy scan tls www.google.com --format json > self-scan-google.json
qureddy scan tls example.com --format json > self-scan-example.json
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one --format json > self-scan-1111.json
qureddy scan tls tls-v1-2.badssl.com:1012 --format json > self-scan-tls12.json
```

Artifact: `phase-5-self-scan/*.json`

This phase verifies the shipped scanners against the authorized target matrix.

### Phase 6 — Build Verification

Build the package; scan the built artifacts.

```
uv build
uv run --locked pip-audit
```

Artifact: `phase-6-build/dist/*`

### Phase 7 — Audit

`scripts/audit_phase.py` reads every prior phase artifact and asserts on specific facts. Failure of this phase blocks merge.

```
python scripts/audit_phase.py
```

Audit checks:

- Phase 1 ran and reported 0 critical issues
- Phase 2 collected at least 20 unit tests; coverage >= 80%
- Phase 3 collected at least 5 integration tests
- Phase 4 ran against all 6 canonical targets
- Phase 5 either ran successfully OR scanner doesn't exist yet
- Phase 6 produced both sdist and wheel artifacts
- No phase was skipped due to early exit
- No phase produced unexpected SKIP markers in test output
- The PR template checklist (when present) has all required items checked

Artifact: `phase-7-audit.json`, `phase-7-audit.md`

---

## Section 22 — Quality Gates (Tier 1 Per-PR, Tier 2 Per-Release)

CI quality gates are split into two tiers based on cost-benefit at MVP scale.

**Tier 1 — every PR.** Lightweight gates that catch real bugs without spending much CI time. Branch protection requires every Tier 1 gate to pass before merge.

| Gate | Phase | Tool | Notes |
|---|---|---|---|
| Lint | 1 | `ruff check` | |
| Format | 1 | `ruff format --check` | check-only, never rewrites |
| Type check | 1 | `mypy --strict` | |
| Static security | 1 | `bandit` (MEDIUM threshold) | |
| Secrets scan | 1 | `gitleaks` (or `trufflehog`) on diff | |
| Unit tests | 2 | `pytest` excluding `tests/live/` (>=80% coverage) | |
| Integration tests | 3 | `pytest tests/test_openssl_probe.py` | needs OpenSSL 3.5.7 LTS on runner |
| Live tests | 4 | `pytest tests/live/` | needs network; 3 retries via `pytest-rerunfailures` |
| Audit | 7 | `scripts/audit_phase.py` | reads phase artifacts, asserts on counts |

**Tier 2 — every release tag.** Heavier gates that block release artifacts but are too noisy or slow for per-PR cycles.

| Gate | Tool | Notes |
|---|---|---|
| Dependency CVEs | `pip-audit` (HIGH/CRITICAL block) | per-PR generates noise from upstream CVEs you don't control; fix on release cadence |
| License compatibility | `pip-licenses` (AGPL/GPL/LGPL block) | runs on `pyproject.toml` change at minimum; full sweep on release |
| Self-scan | `qureddy scan tls <target>` × 6 targets | runs against the authorized target matrix |
| Build verification | `uv build` (sdist + wheel) | |
| Build dependency audit | `pip-audit` | release-time and build verification |
| Internal link check | `lychee` on `*.md` | release-time + when docs change |

**Rationale for the split:** release-only checks are expensive and depend on final artifacts. Tier 1 catches changes during review; Tier 2 verifies what we ship.

Promote a Tier 2 gate to per-PR execution when its runtime and signal justify the cost.

CI runs on the matrix: **ubuntu-latest × macos-latest × windows-latest × Python 3.14**. All three platforms must pass for both tiers. OpenSSL 3.5.7 LTS is installed per-platform during CI setup.

---

## Section 23 — Pre-commit Hooks

Pre-commit hooks run locally before push. Configured in `.pre-commit-config.yaml`. Contributors install once with `pre-commit install`.

Required hooks:

- `ruff check --fix`
- `ruff format`
- `trailing-whitespace`
- `end-of-file-fixer`
- `check-yaml`
- `check-toml`
- `check-added-large-files` (max 500 KB)
- `check-merge-conflict`
- `detect-private-key`

`mypy` is intentionally **not** in pre-commit. Pre-commit `mypy` is slow and shares state poorly with the IDE daemon. CI catches it.

Hook versions are pinned. `pre-commit autoupdate` runs deliberately, with a PR review.

---

## Section 24 — Self-Scanning

QuReddy scans itself before release. We are a security tool. We dogfood our own scanner and catch the same mistakes we claim to detect. Failing to scan our own code would be the loudest possible signal that the project does not believe its own claims.

**Rule 24.1 — QuReddy scans its own supported targets before every release.**
Once the scanner exists for a target type, the release workflow runs `qureddy` against the project's own infrastructure and committed fixtures. Output is captured as a CI artifact and reviewed.

**Rule 24.2 — Required scans before every release:**

- Dependency vulnerability scan (`pip-audit`)
- Dependency license scan (`pip-licenses`)
- Secrets scan (`trufflehog` against full history)
- Static security scan (`bandit -r src/qureddy`)
- Built-artifact dependency audit (`pip-audit`)
- Generated artifact scan (sdist and wheel scanned for unexpected contents)
- QuReddy scan against its own supported targets and fixture set
- SBOM/CBOM generation check (the artifact is produced and validated)

**Rule 24.3 — Required scans before merge when relevant:**

- `ruff check` (always)
- `ruff format --check` (always)
- `mypy --strict` (always)
- `pytest` with coverage threshold (always)
- Secrets scan on the diff (always)
- Dependency vulnerability and license check (when `pyproject.toml` or `uv.lock` changes)
- `bandit` (when source under `src/qureddy/` changes)
- `qureddy` self-scan (when scanner logic, output adapters, policy, or evidence handling changes)

**Rule 24.4 — Self-scan results are saved as CI artifacts.**
Each release workflow uploads:

- `qureddy-self-scan.json` — output of QuReddy run against project's targets
- `qureddy-self-scan.cbom.json` - validated CycloneDX 1.7 CBOM artifact
- `pip-audit.json`, `bandit.json`, `pip-licenses.json`

Retained for at least 90 days. Linked from GitHub release notes.

**Rule 24.5 — A scan failure has two acceptable resolutions.**

1. Fix the underlying issue before merge
2. Document the accepted finding with `SELF-SCAN ACCEPTED: <finding>, because <reason>, expires <date or issue>` and obtain reviewer approval

There is no third option.

**Rule 24.6 — Self-scan acceptances expire.**
Every `SELF-SCAN ACCEPTED` entry has a date or issue link. The release workflow checks for expired acceptances and fails. Permanent exceptions do not exist.

**Rule 24.7 — A task touching scanner, security, or release code is not done until self-scans have run.**
"Done" is not "tests pass." Done is "tests pass and the relevant self-scans either passed or have a documented, reviewed exception."

**Rule 24.8 — Self-scan "passes" definition.**
The scan must complete with `failure_category` null at the pipeline level (no `local_openssl_lacks_group`, no `target_connect_failed`). Findings of any severity are allowed and reported but do not block CI. "QuReddy detected that GitHub still uses classical X25519" is a successful scan, not a failure.

---

## Section 25 — Documentation Link Discipline

Documentation links rot. Internal rot is fixable; external rot is partially out of our control.

**Rule 25.1 — Internal documentation links must point to real files or real anchors.**
If you add or change a link in `README.md`, `CHANGELOG.md`, `docs/**/*.md`, or release notes, verify the target exists.

**Rule 25.2 — Internal link check runs on every PR that modifies documentation.**
Tool: `lychee` configured to verify only relative and same-repo links. Failures block merge. External URLs are checked on a separate cadence.

**Rule 25.3 — Link targets follow the file structure, not invented paths.**
Case-sensitive and slug-aware.

**Rule 25.4 — External link checking is scheduled, not per-PR.**
External URLs checked weekly in a scheduled CI workflow. Failures produce a tracking issue, not a blocked PR. Transient outages do not block development.

**Rule 25.5 — Release notes get a final link audit before tagging.**
Manual verification before publishing.

**Rule 25.6 — README badges link to real, accurate destinations.**
Broken badges are removed. A broken badge looks worse than no badge.

---

## Section 26 — Security Bar (Hard Merge Blockers)

Every rule in this section is a hard merge blocker. Insecure implementation choices are release blockers, not technical-debt items. The reputational cost of shipping insecure code in a security tool exceeds the technical cost.

**Rule 26.1 — Do not merge code that disables TLS verification in production paths.**
`verify=False`, `ssl.CERT_NONE`, custom verify callbacks that always return True. None of these appear in shipped code.

**Rule 26.2 — Do not merge code that uses `shell=True` with user-controlled input.**
The QuReddy codebase does not use `shell=True`. Period.

**Rule 26.3 — Do not merge code that logs secrets.**
Forbidden: API keys, tokens, private keys, passwords, full PEM bodies, full TLS handshake traces, full subprocess output that may contain credentials. When in doubt, hash and log the hash.

**Rule 26.4 — Do not merge code that uses `eval`, `exec`, or `pickle.loads` on untrusted input.**
JSON for structured data. `eval` and `exec` do not appear in shipped code under any framing.

**Rule 26.5 — Do not merge code that reads user-controlled paths without resolving and validating them.**
User-supplied paths go through `pathlib.Path(...).resolve()` and are checked against an allowed root.

**Rule 26.6 — Do not merge code that performs network or subprocess calls without timeouts.**
Default for QuReddy is 30 seconds. A missing timeout is a hang waiting to happen.

**Rule 26.7 — Do not merge code that swallows security-relevant errors.**
Failed signature verification, failed cert parse, failed capability check are findings or hard errors, not "best-effort."

**Rule 26.8 — Do not merge code that uses `random` instead of `secrets` for security-sensitive randomness.**
Token generation, comparison nonces, identifiers that must not be predictable: `secrets` only.

**Rule 26.9 — Do not merge code that accepts unknown config fields silently at trust boundaries.**
Every Pydantic model that consumes external input uses `extra="forbid"`.

**Rule 26.10 — Do not merge code that changes findings, severities, or evidence without tests.**
Findings are the product. Changing how a finding is classified, what severity it carries, or what evidence supports it requires explicit tests.

**Rule 26.11 — Security-sensitive changes require focused tests, scans, and explanation.**
PRs that change TLS handshake handling, certificate parsing, signature verification, secrets handling, subprocess invocation, path handling, or deserialization must include:

- Focused unit tests for the unsafe-input case
- Secrets scan output (clean)
- Static security scan output (clean at MEDIUM)
- Dependency and license check (when dependencies changed)
- Explicit explanation of any accepted residual risk

**Rule 26.12 — Security exceptions are time-bounded and reviewed.**

```
SECURITY EXCEPTION ACCEPTED: <rule>, because <reason>, expires <date or issue>
```

Tracked in `docs/SECURITY_EXCEPTIONS.md` (created when the first exception is recorded) until expired or closed.

**Rule 26.13 — Refuse insecure shortcuts even when asked.**
If a contributor (human or AI) requests an insecure shortcut, the request is refused. Examples: "just use `verify=False` for now," "let's `shell=True` because escaping is annoying," "log the full response so we can debug." This rule explicitly applies to AI agents. **An AI implementing QuReddy code does not produce insecure code on request, regardless of how the request is framed.**

**Rule 26.14 — `SECURITY.md` documents the disclosure process.**
GitHub Security Advisories as the channel, response SLA (5 business days), coordinated disclosure timeline, contact information. Stale SECURITY.md is itself a security smell.

**Rule 26.15 — Crypto primitives are FIPS-aligned where applicable.**
QuReddy reports on crypto. We do not use weak crypto in our own code. SHA-1 only for legacy compatibility checks (with a comment). MD5 only for non-security checksums (with a comment). RSA below 2048 not at all. Random IVs are 96 bits or longer for AES-GCM.

---

## Section 27 — Branch Protection and Merge Hygiene

**Rule 27.1 — `main` branch is protected.**
GitHub branch protection:

- Require pull request before merging
- Require the current Linux, macOS, and Windows `Local release gate` checks to pass
- Require the PR CI matrix (static, unit, integration, build, CBOM, packaging), MAX
  code-quality, changed-line coverage, and CodeQL checks to pass
- Require branches to be up to date before merging
- Require conversation resolution
- Restrict force pushes
- Restrict deletions
- Require linear history

The repository's GitHub ruleset/branch-protection settings are the source of truth and
must be verified after every repository-settings change. If the settings API reports no
active protection, direct pushes and administrator merges are not considered acceptable;
restore protection before the next release. A workflow file alone is not enforcement.

Public-network live probes, Semgrep auto rules, and ecosystem scoring are advisory
scheduled/manual signals. They are never required merge checks. The repository-owned local
release gate remains authoritative if hosted Actions is unavailable.

**Rule 27.2 — Mandatory PR workflow.**
Every change goes through a PR. Solo contributors create PRs and self-review. The PR audit trail is the artifact. Direct pushes to `main` are forbidden.

**Rule 27.3 — Squash-and-merge by default.**
Feature branches accumulate WIP commits. Squash to a single, well-described commit on `main`. The commit message follows Conventional Commits.

**Rule 27.4 — No merging without review.**
At least one approving review on every PR. Self-merging is allowed for solo work but the PR record is non-negotiable. When a second contributor joins, self-merging is forbidden.

**Rule 27.5 — Administrator bypass is disabled when protection is active.**
During an active security incident or hosted-platform outage, the maintainer may temporarily
change the ruleset only after the same candidate commit passes the complete local release
gate; the reason, evidence-manifest digest, and follow-up action must be recorded in a public
issue or security advisory. A temporarily bypassed commit is not eligible for a package
release until the normal protected checks pass and the ruleset is restored. If protection is
absent, this rule is not satisfied and the release gate must stop.

**Rule 27.6 — Sensitive approvals become stale after changes.**
New commits dismiss approvals on workflow, packaging, release-script, dependency-lock, or
security-policy changes. The updated candidate must be re-reviewed.

**Rule 27.7 — Stale branches are pruned.**
Merged branches are deleted. Open branches inactive for 30 days get tagged for review or deletion.

---

## Section 28 — Anti-Theater Rules

Quality theater is when the project performs the appearance of quality without the substance. Avoid:

**Rule 28.1 — Do not add tools just for badge collection.**
Every tool in CI must produce actionable output that contributors actually act on. A tool that runs and is ignored is worse than no tool.

**Rule 28.2 — Do not lower thresholds to make CI pass.**
Coverage drops below 80%? Add tests or document why. Don't lower the threshold to 60%.

**Rule 28.3 — Do not add CI jobs that have to be ignored.**
A flaky test gets fixed, not retried 5 times beyond the standard 3. A slow scan gets optimized, not skipped on every PR.

**Rule 28.4 — Do not generate documentation that isn't read.**
Auto-generated API docs that nobody reads are pollution. Hand-written docs (README, ARCHITECTURE, CONTRIBUTING) get maintained because contributors actually use them.

**Rule 28.5 — The CI configuration is reviewed in PRs like any code.**
CI changes are not "infrastructure" exempt from review. Adding or removing jobs requires the same scrutiny as adding or removing tests.

---

## Section 29 — OpenSSF Best Practices Alignment

QuReddy targets OpenSSF Best Practices Badge. Tier targets:

- **Passing** — current target
- **Silver** — subsequent improvement
- **Gold** — longer-term improvement

The rules above are written to satisfy the badge criteria. Specific OpenSSF requirements explicitly addressed:

| OpenSSF criterion | This document |
|---|---|
| Public repository with version control | Repository is public on GitHub |
| Bug reporting process | `SECURITY.md` (Rule 26.14) |
| Vulnerability reporting process | `SECURITY.md`, 5-day SLA (Rule 26.14) |
| Cryptographic key management documented | This file, Section 12 |
| Two-factor auth required for committers | GitHub setting + Rule 27.1 |
| Reproducible builds | `uv.lock` committed (Rule 13.2) |
| Static analysis on every release | Phase 1 (Section 21) |
| Test new functionality has tests added | Rule 9.1 |
| CHANGELOG entries for every release | Rule 24.1 implies, `CHANGELOG.md` keep-a-changelog format |
| Memory-safe language preferred | Python (memory-safe) |
| TLS for all HTTPS | Implicit; we are a TLS scanner |
| No hardcoded credentials | Rule 26.3 + secrets scanning |
| Continuous integration | Section 21 (7-phase CI) |
| Documentation of architecture | Repository architecture documentation |

---

## 30. Quick Reference — PR Review Checklist (Tier 1: Must Pass)

The minimum checklist for every PR. Long enough to catch real issues, short enough to actually use.

**Code:**

- [ ] No file over 400 lines
- [ ] No function over 50 lines (30 line norm)
- [ ] No class over 200 lines
- [ ] `mypy --strict` passes
- [ ] `ruff check` passes
- [ ] `ruff format --check` passes
- [ ] Every public function has a docstring
- [ ] Every Pydantic model is frozen unless explicitly mutable
- [ ] All collections are tuples unless mutation is required
- [ ] No `print()` in library code

**Tests:**

- [ ] `pytest` passes (all phases) with >=80% coverage
- [ ] Error paths and boundary values tested
- [ ] No new `@pytest.mark.skip` or `@pytest.mark.acceptance`

**Security (Tier 1 per-PR):**

- [ ] `bandit` passes at MEDIUM threshold
- [ ] Secret scan on diff clean (`gitleaks` or `trufflehog`)
- [ ] No `verify=False`, `shell=True`, `eval`/`exec`, `pickle.loads`
- [ ] Subprocess calls are list-form with explicit timeout
- [ ] OpenSSL subprocess calls live only in `openssl_probe.py`

(`pip-audit` and `pip-licenses` run as Tier 2 per-release per Section 22; per-PR, they only fire when `pyproject.toml` or `uv.lock` changes.)

**Process:**

- [ ] Anti-pattern audit recorded in PR description
- [ ] CHANGELOG.md updated when behavior changes
- [ ] Audit phase (`scripts/audit_phase.py`) passes

If any of these are unchecked, the PR is not ready.

---

## 31. Quick Reference — Release Checklist (Tier 2: Must Pass Before Tag)

In addition to Tier 1:

- [ ] `pip-audit` passes (no HIGH or CRITICAL CVEs)
- [ ] `pip-licenses` passes (no AGPL/GPL/LGPL)
- [ ] Built-artifact dependency audit passes (`pip-audit`)
- [ ] Build verifies (`uv build` succeeds, both sdist and wheel)
- [ ] Internal documentation links verified (`lychee`)
- [ ] External documentation links checked within last 7 days
- [ ] Self-scan run for all canonical targets, results archived
- [ ] CHANGELOG entry for the release
- [ ] Release notes drafted
- [ ] No expired `SELF-SCAN ACCEPTED` or `SECURITY EXCEPTION ACCEPTED` markers
- [ ] SBOM/CBOM generated and validated
- [ ] Sigstore signing succeeded
- [ ] TestPyPI trusted publisher configuration verified (public PyPI is deliberately deferred)
