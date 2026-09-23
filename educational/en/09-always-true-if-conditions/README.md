# 09. `if` conditions that always evaluate to true (CFW: Control Flow Weakness)

**CWE:** CWE-571 (Expression is Always True)
**OWASP CI/CD category:** CICD-SEC-1 (Insufficient Flow Control Mechanisms)
**Zenith Engine rules:** `R1022` (`R1022_JOB` / `R1022_STEP`)
**Observed real-world frequency:** 6 alerts (<0.1% of the total). It's the rarest in the catalog, almost a copy-paste "code smell", but when it shows up it usually disables a security control someone believed was active.

## What it is

A job- or step-level `if:` in GitHub Actions is only evaluated as a condition when it's written as **a single, complete expression**: `if: ${{ condition }}`. There's an extremely easy formatting mistake to make, and very hard to spot at a glance, that makes the condition **always evaluate to true**, no matter its content:

```yaml
# Runs ALWAYS, no matter what vars.DEPLOY_ENABLED is:
if: "${{ vars.DEPLOY_ENABLED == 'true' }} == true"

# Also runs ALWAYS: two expressions in the same if,
# GitHub only evaluates a single, complete ${{ }} as a condition:
if: ${{ github.ref == 'refs/heads/main' }} && ${{ github.actor == 'trusted-bot' }}
```

`R1022` detects exactly this pattern: a string that contains `${{` but that **isn't, in its entirety, a single expression** (it doesn't start with `${{`, doesn't end with `}}`, or contains more than one `${{` in the same `if` field). In that case GitHub Actions doesn't evaluate the field as *one* condition: it replaces each `${{ }}` with its result as text (e.g. `false && true`) and the `if:` receives that non-empty string, which is **always "truthy"**.

## Why it matters

This is about as dangerous as a flaw gets, because it's **completely invisible in day-to-day use**: the workflow "works", jobs run, nobody sees any error. The only sign something's wrong is that a job which **should** have been skipped (say, a production deploy that's only supposed to run when `github.ref == 'refs/heads/main'`) also runs on any other branch, including branches from external fork PRs.

It commonly shows up from a typo when combining two conditions with `&&` without realizing each one needs to sit inside the same `${{ }}`, or from copying an `if:` from another workflow and tacking on a "quick" extra check at the end without wrapping it correctly.

## How to fix it

Wrap **the entire condition**, including logical operators, inside a single `${{ ... }}` block:

```yaml
# Bad (always true)
if: ${{ github.ref == 'refs/heads/main' }} && ${{ github.actor == 'trusted-bot' }}

# Good (actually evaluated)
if: ${{ github.ref == 'refs/heads/main' && github.actor == 'trusted-bot' }}
```

As a further good practice, avoid nesting `${{ }}` inside an `if:` at all. GitHub Actions already evaluates the entire content of `if:` as an expression, so you don't even need to write `${{ }}`:

```yaml
if: github.ref == 'refs/heads/main' && github.actor == 'trusted-bot'
```

> **Note:** the deploy switch in this lesson is a *configuration variable* (`vars.DEPLOY_ENABLED`), not a secret. The `secrets` context **can't be used in `if:`**: GitHub rejects the workflow with `Unrecognized named-value: 'secrets'`. If a condition depends on a secret, map it to a job-level `env:` first and check `env.MY_VARIABLE`.

## Run the simulation

```bash
cd educational/en/09-always-true-if-conditions
pip install pyyaml requests
python3 simulate.py
```

The script runs the real `R1022` rule and also **evaluates the conditions exactly as GitHub's runner would**: for every `if:` in the workflow, it shows whether GitHub would treat it as a real expression to evaluate or as a literal (always-true) string, and simulates which jobs would run under two different scenarios (`push to main` vs. `push to a feature branch`) for both `vulnerable.yml` and `fixed.yml`.

## Your turn

[`exercise.yml`](exercise.yml) has three `if:` conditions that look right and always evaluate to true. Make each one actually get evaluated. None may disappear.

```bash
cp exercise.yml my_solution.yml      # work on the copy
python3 ../check.py                  # repeat until you see "PASSED"
python3 ../check.py --all            # extra challenge: every engine rule
```

The checker runs this lesson's same real rules and also verifies you haven't "solved" the exercise by deleting whatever was failing.

<details>
<summary>Hints</summary>

- A condition has to be **one single** expression.
- Inside an `if:` you don't need `${{ }}`: GitHub already evaluates it all as an expression.
- `failure()` and `cancelled()` are functions: combine them with `||` inside the same expression.

</details>

The solution is in [`../solutions/09.yml`](../solutions/09.yml). Try it before looking.
