# 06. Privileged triggers: `pull_request_target` and TOCTOU (PTW: Privileged Trigger Weakness)

**CWE:** CWE-862 (Missing Authorization)
**OWASP CI/CD category:** CICD-SEC-4 (Poisoned Pipeline Execution)
**Zenith Engine rules:** `R1000` (`pull_request_target` detected), `R1001` (checkout of the PR HEAD under `pull_request_target`), `R1021` (TOCTOU pattern)
**Observed real-world frequency:** 131 alerts (0.6% of the total). Rare, but among the **highest-severity** when it does show up.

## What it is

`pull_request` and `pull_request_target` are nearly identical except for one critical detail: `pull_request_target` runs **in the base repository's context**, with access to its secrets and a `GITHUB_TOKEN` with write permissions by default, **even when the PR comes from an external fork**. This is intentional: it lets you automate actions on fork PRs (labeling them, commenting, running checks) without exposing secrets to the fork's code.

The problem shows up when, on top of using `pull_request_target`, the workflow **checks out the PR's own code** (`ref: ${{ github.event.pull_request.head.ref }}`) and then runs it (build, tests, linters with plugins...). At that point you're executing **untrusted code, written by whoever opened the PR**, with access to the base repository's secrets. This is the classic entry point for a **Pwn Request** / *Poisoned Pipeline Execution*.

Zenith Engine detects three layers of the same problem:
- `R1000` (HIGH): the workflow uses `pull_request_target`. Not necessarily a flaw by itself, but it flags the spot that needs closer review.
- `R1001` (CRITICAL): on top of that, it does a `checkout` with `ref: github.event.pull_request.head...`, so the attacker's code enters the privileged environment.
- `R1021` (CRITICAL): **TOCTOU** pattern (*Time-Of-Check to Time-Of-Use*): the workflow runs `gh pr checkout <number>` using the PR number, which by the time it actually executes may already point to a commit *different* from the one that was reviewed/approved. It shows up when there's a prior check (a maintainer reviews the PR and adds a label like `safe-to-test`, comments `/ok-to-test`, approves an `environment`...): the attacker pushes a new malicious commit right after that approval, but before the checkout happens.

## Why it matters

This pattern is behind multiple high-profile real-world incidents in open source projects (publicly documented by GitHub Security Lab since 2021): a seemingly innocent PR modifies a test or config file that the privileged workflow later runs (`npm test`, `make`, a build script), and that code exfiltrates `secrets.*` to an external server, with no manual approval from a maintainer, because `pull_request_target` doesn't require the same approval gate that `pull_request` does for fork PRs under some organization settings.

## How to fix it

1. **Avoid `pull_request_target` unless it's strictly necessary.** If you only need to label or comment on the PR, use a plain `pull_request` (no secrets access) plus a separate job with `pull_request_target` that **never checks out the PR's code**, only calls the GitHub API.
2. If you need to run the PR's code (tests, build), keep it in a workflow with `pull_request` (no `_target`). You lose automatic access to secrets, which is exactly what you want.
3. If you truly need `pull_request_target` plus running the fork's code, require **manual approval** from a maintainer before every run (`environment:` with *required reviewers*), and always check out the **exact, already-validated SHA**, never `head.ref` or the PR number at execution time.
4. For the TOCTOU pattern: always use `ref: ${{ github.event.pull_request.head.sha }}` (the exact commit that was evaluated), not `gh pr checkout <number>`, which dynamically resolves to the PR's latest commit at the moment that step runs. Careful: `head.sha` **only closes the TOCTOU gap**; the code is still the PR author's and runs in a privileged context. Always combine it with point 3 (prior review), no secrets in the environment and `persist-credentials: false` on the checkout.

5. **Use `actions/checkout` v7 or later.** Since v7 (2026), `actions/checkout` **refuses** to fetch a fork PR's code when the workflow is triggered by `pull_request_target` or `workflow_run`, unless you explicitly ask for it with `allow-unsafe-pr-checkout: true`. With the v4 used in `vulnerable.yml`, the attack just works; with v7, the same workflow fails instead of running the attacker's code. In `fixed.yml`, the `test-approved` job sets that parameter on purpose, after applying points 3 and 4: having to write it forces a conscious decision and leaves a trace in code review.

## A note on the limits of automated detection

`R1001` looks for the substring `github.event.pull_request.head` inside the checkout's `ref:`, so **`fixed.yml` still triggers the alert** on the `test-approved` job. And it's right to: `head.sha` pins *which* commit runs (closing the TOCTOU gap), but that commit is still the PR author's code, running under `pull_request_target`. The risk R1001 points at is still there; what makes it acceptable are controls that pattern-based static analysis can't see: the prior human review (the job only fires on the `labeled` event + `safe-to-test`), no secrets in the environment, `permissions: contents: read` and `persist-credentials: false`.

An alert that keeps firing after a fix isn't necessarily a false positive: you need to understand what risk the rule points at and whether the controls the tool can't see actually mitigate it.

## Run the simulation

```bash
cd educational/en/06-privileged-triggers-pull-request-target
pip install pyyaml requests
python3 simulate.py
```

The script detects `R1000`/`R1001`/`R1021`, and also **simulates the TOCTOU attack**: it models the timeline of a real PR (the maintainer reviews the commit and adds the `safe-to-test` label → the author pushes an additional malicious commit → the workflow's late checkout) and shows exactly which code would have ended up running with access to the base repository's secrets.

## Your turn

[`exercise.yml`](exercise.yml) runs fork PR tests with the repository's privileges, uploads coverage with a secret and retries with `gh pr checkout` by number. Keep the tests running on every PR without exposing secrets or a privileged token to the fork's code.

```bash
cp exercise.yml my_solution.yml      # work on the copy
python3 ../check.py                  # repeat until you see "PASSED"
python3 ../check.py --all            # extra challenge: every engine rule
```

The checker runs this lesson's same real rules and also verifies you haven't "solved" the exercise by deleting whatever was failing.

<details>
<summary>Hints</summary>

- Running a PR's code doesn't need `pull_request_target`. Which event gives you the PR's code with a read-only token and no secrets?
- With that event, `actions/checkout` without `ref:` already fetches the PR's code.
- Coverage can be stored as an artifact, with no secret. If it has to go to a service, that belongs in another workflow that doesn't run PR code.

</details>

The solution is in [`../solutions/06.yml`](../solutions/06.yml). Try it before looking.
