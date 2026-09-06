<!-- SPDX-License-Identifier: Apache-2.0 -->

# Review process

[![Contributor guide](https://img.shields.io/badge/QuReddy-contributor%20guide-6e7781?style=flat-square)](../README.md#3-contributor-documentation)

How a bug fix lands in QuReddy. This is the operational form of the multi-tier reviewer/arbiter pattern.

For *why* the project uses three label tiers (Reviewer / Arbiter / Decision), see [§3, Why three tiers](#3-why-three-tiers). This document is the diagram and the cookbook.

## Contents

1. [The pipeline](#1-the-pipeline)
2. [The label tiers](#2-the-label-tiers)
3. [Why three tiers](#3-why-three-tiers)
4. [Workflow per fix](#4-workflow-per-fix)
5. [Filterable views](#5-filterable-views)
6. [Hard rules](#6-hard-rules)
7. [When the apparatus doesn't apply](#7-when-the-apparatus-doesnt-apply)
8. [Comment review](#8-comment-review)

## 1. The pipeline

```mermaid
flowchart LR
    issue([Bug issue<br/>filed]) --> branch([fix/N-slug<br/>branch])
    branch --> pr([PR opened])

    pr --> review_a["Reviewer A<br/>(automated review 1)"]
    pr --> review_b["Reviewer B<br/>(automated review 2 / human / other)"]
    pr --> validate["Validator<br/>(validate-fix skill)"]

    review_a -->|review:automated-1:&lt;verdict&gt;| labels1[(Issue/PR labels)]
    review_b -->|review:automated:&lt;verdict&gt;| labels1
    validate -->|validation:automated:&lt;verdict&gt;| labels1

    labels1 --> arbiter["Arbiter<br/>(project lead)"]
    arbiter -->|arbiter:binding:&lt;verdict&gt;| labels2[(Binding label)]
    arbiter -->|decision:&lt;outcome&gt;| labels2

    labels2 --> gate{decision:approved?}
    gate -->|yes| merge([Squash-merge<br/>to main])
    gate -->|needs-changes| author[Author<br/>addresses notes]
    gate -->|rejected| close([Close PR])

    author --> pr
    merge --> close_issue[Issues<br/>auto-closed]
```

## 2. The label tiers

| Tier | Prefix | Who applies | Count per issue | What it means |
|---|---|---|---|---|
| **Reviewer** | `review:<role>-<instance>:<verdict>` | Each individual reviewer | 0..N | Recommendation; informational |
| **Arbiter** | `arbiter:binding:<verdict>` | Only the arbiter | 0 or 1 | Arbiter's verdict, mirrors reviewer namespace for filterability |
| **Validator** | `validation:automated-<instance>:<verdict>` | The validator | 0..N | Mechanical: bug confirmed pre-patch, gone post-patch |
| **Decision** | `decision:<outcome>` | Only the arbiter | 0 or 1 | **Binding.** The merge gate reads this and nothing else. |

### `<role>-<instance>` naming convention

Each automated review adds an instance suffix so concurrent reviews don't collide. The convention is:

- `review:automated-1:<verdict>` — first automated review
- `review:automated-2:<verdict>` — second automated review
- `review:automated-N:<verdict>` — Nth automated review
- `review:lead:<verdict>` — project lead (single-instance role; no suffix needed)
- `review:human:<verdict>` — human reviewer (single-instance role; no suffix needed)
- `validation:automated-N:<verdict>` — same shape for validator labels

**Rule:** when an automated review applies a reviewer or validator label, the review must include an instance suffix. Bare automated labels are deprecated; historical labels remain only for audit-trail compatibility.

**Why instance-suffixed:** concurrent sessions are real here. The 2026-04-27 audit caught two sessions committing on each other's branches. Race-prone label semantics ("the latest applier wins") is the wrong default; multiple labels coexisting on the same issue is the correct audit trail.

Verdicts: `approve`, `approve-with-changes`, `reject`.
Decision outcomes: `approved`, `needs-changes`, `rejected`.
Validation verdicts: `validated`, `partial`, `failed`, `needs-clarification`.

## 3. Why three tiers

**Reviewer asks: "does this implementation address the root cause?"**
Root cause vs symptom. Schema stability. Security invariants. Rejects fixes that paper over bugs or violate contracts.

**Validator asks: "does this fix actually work?"**
Pre-patch reproduction fails. Post-patch reproduction passes. Required regression test is present. No previously-passing test went red.

**Arbiter asks: "given all the inputs, do we merge?"**
Reads every reviewer comment and the validator's verdict. Settles disagreements explicitly. Sets the binding `decision:*` label. The merge gate (CI or human) reads only that one.

The validator is independent of the reviewer because "tests pass" and "issue resolved" are different questions. CI says the first; the validator answers the second by checking out the base commit, running the issue's reproduction (which must fail), then running it on the PR's HEAD (where it must pass).

## 4. Workflow per fix

### 1. Author opens PR

PR body contains `Closes #N` (or multiple when issues are coupled). PR template auto-fills with `### Fidelity to the issue's proposed fix` checkbox.

### 2. Reviewers post verdicts

Each reviewer runs the `python-oss-crypto-reviewer` skill, posts a `## Review:` comment ending with the standard signature block, and applies the matching `review:<name>:<verdict>` label.

```bash
gh pr comment <n> --repo breachsafe/qureddy --body "$(cat review.md)"
gh pr edit <n> --repo breachsafe/qureddy --add-label "review:automated-1:approve"
```

Multiple reviewers can run concurrently. None of them gate merge — they're recommendations.

### 3. Validator runs

The `validate-fix` skill (or its manual procedure if not yet auto-loaded) runs the issue's reproduction at base and at HEAD, runs the new tests 3× to defeat `pytest-rerunfailures` masking, runs the full suite for regression, and runs the Tier 1 quality gates.

```bash
gh pr comment <n> --repo breachsafe/qureddy --body "$(cat validation.md)"
gh pr edit <n> --repo breachsafe/qureddy --add-label "validation:automated-1:validated"
```

### 4. Arbiter decides

The arbiter reads every reviewer comment and the validator's verdict, settles disagreements explicitly with rule citations, runs tests one more time, and posts the binding decision.

```bash
gh pr comment <n> --repo breachsafe/qureddy --body "$(cat arbitration.md)"
gh pr edit <n> --repo breachsafe/qureddy \
    --add-label "arbiter:binding:approve" \
    --add-label "decision:approved"
```

### 5. Merge

Squash-merge per [coding-rules §27.3](coding-rules.md). The `Closes #N` reference auto-closes referenced issues.

```bash
gh pr merge <n> --repo breachsafe/qureddy --squash --delete-branch
```

## 5. Filterable views

```bash
# Ready to merge
gh issue list --repo breachsafe/qureddy --label "decision:approved"

# Reviewed by automated review 1, awaiting the arbiter
gh issue list --repo breachsafe/qureddy \
  --label "review:automated-1:approve" \
  -- -l "arbiter:binding:*"

# Disagreement between two reviewers
gh issue list --repo breachsafe/qureddy \
  --label "review:automated-1:approve" \
  --label "review:automated-2:reject"

# New PRs needing first review
gh pr list --repo breachsafe/qureddy --state open \
  --json number,labels | jq '[.[] | select(.labels | length == 0) | .number]'
```

## 6. Hard rules

These come from the reviewer and validator skills:

1. **Author cannot review their own PR.** Self-approval is forbidden.
2. **Arbiter must read all reviewer comments before deciding.** Arbiter doesn't shortcut.
3. **Do not edit prior review comments.** Re-review = new comment + label swap. Audit trail is append-only.
4. **No merge without binding decision.** The `decision:*` label is the merge gate. Without it, no merge.
5. **Tests must pass 3× without `Rerun:` markers.** `pytest-rerunfailures` cannot mask deterministic failures. See the cautionary tale in [issue #15](https://github.com/breachsafe/qureddy/issues/15) where 5 hard-failing tests showed as "192 passed."
6. **Reviewer disagreement triggers escalation, not loops.** Per the reviewer skill: "If you can't tell whether you or they are right, propose the test that would settle it. Then run it."

## 7. When the apparatus doesn't apply

- **Docs-only PRs** can skip the validator (nothing to validate against an issue's reproduction). **A reviewer pass (Reviewer mode, non-binding) is still required** — at minimum a `## Review:` comment with verdict and signature block, even when the verdict is `approve` and the diff is one line. Issue #48 documents the canonical failure: PRs #26, #36, #40 self-merged with zero reviews, and the apparatus that was *defining itself* in those PRs got bypassed by its own definitions.
- **Solo work** by the project lead can self-merge per [coding-rules §27.4](coding-rules.md), but the PR record is still required, including at least one reviewer comment. "Self-merged with no review" is acceptable — "merged with no record" is not. The audit trail must distinguish "reviewed and approved" from "self-merged knowingly" from "merged without thinking."
- **CI/dependency bumps** from Dependabot follow GitHub's standard auto-merge rules, not this apparatus.

For everything else — bug fixes, feature work, architecture changes — the full pipeline applies.

## 8. Comment review

Reviewers apply the canonical [commenting and docstring contract](coding-rules.md#section-10--comments-and-docstrings)
to changed code. A comment is reviewable context. It should explain
durable rationale, invariants, ownership boundaries, failure semantics, security or
provenance constraints, compatibility limits, transition context, or test intent.
If the code is self-explanatory and none of those facts needs preserving, do not add
a comment. For every new or modified source file, check code, diagram, and comments as
one contract. Flag stale, speculative, line-number-dependent, or code-restating text.

### On enforcement

The repository is public, but mechanical protection must be verified in GitHub settings;
the workflow files alone do not enforce it. Before merging or releasing, confirm that
`main` requires a pull request, an independent approval, the local release gates, the PR
CI matrix, MAX code-quality, changed-line coverage, and CodeQL, with no bypass actors. If
the settings check fails, stop the release and restore protection. Any emergency ruleset
change must be recorded and reverted before a package release.

Until then: the rules above are followed because they are written down, and PRs that violate them are flagged in retrospective audit (e.g., issue #48). The cost of following them — one `## Review:` comment per docs PR — is small enough that the absence of CI enforcement is not a license to skip.
