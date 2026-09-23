# 05. Outdated runtime and unknown runner (GRCW: GitHub Runner Compatibility Weakness)

**CWE:** CWE-477 (Use of Obsolete Function) / CWE-440 (Expected Behavior Violation)
**OWASP CI/CD category:** CICD-SEC-8
**Zenith Engine rules:** `R1023` (action with an outdated runtime: Node 12/16), `R1024` (unknown or unsupported runner label)
**Observed real-world frequency:** 876 alerts (4.0% of the total).

## What it is

Unlike the previous lessons, this one isn't about an active attacker; it's about **reliability and future-proofing**:

- **`R1023`**: many older actions (`actions/checkout@v2`, `actions/setup-node@v2`...) run on a **Node.js 12 or 16** runtime, both already out of support. GitHub has been progressively dropping support for these versions on its hosted runners. The outcome isn't predictable: the step may fail outright, degrade silently, or GitHub may force a migration to Node 20 that breaks behavior the action assumed.
- **`R1024`**: the `runs-on` value doesn't match any recognized runner label (`ubuntu-latest`, `windows-2022`, `macos-14`...). It could be a typo (`runs-on: bunutu-latest`), a misspelled self-hosted runner label, or the name of a runner image that existed but has since been retired.

## Why it matters

This isn't a security vulnerability in the classic sense, but it is a **CI/CD chain availability failure**: a deploy pipeline that stops running (or fails non-deterministically) the day GitHub drops support for Node 16 is just as operationally serious as a vulnerability, especially if nobody notices until an urgent release can't ship.

An action with an outdated runtime is also usually an action that's **no longer actively maintained**, exactly the kind of action most likely to accumulate unpatched CVEs (see lesson [`10`](../10-known-vulnerable-components/)).

## How to fix it

**For `R1023`:**
1. Identify the affected actions: `engine/outdated_runtime_actions.txt` in this repo maintains the list Zenith Engine uses.
2. Update to the latest major version of each action (for example `actions/checkout@v2` → `@v7`, `actions/setup-node@v2` → `@v7`), which already runs on Node 24. Moving to a "not so old" version isn't enough: Node 20 also reached end of life in April 2026, and GitHub switched its runners to Node 24 by default in June 2026 and removed Node 20 in September 2026. To see what an action runs on, check `runs.using` in its `action.yml`.
3. Check the changelog for the new major version: major bumps usually include breaking changes to the available `with:` inputs.

**For `R1024`:**
1. Check the official list of GitHub-hosted runners and fix the typo or the obsolete label.
2. If it's a self-hosted runner with a custom label, verify the label matches exactly (case-sensitive) the one configured on the runner registered for the repository/organization.

## An R1023 limit worth knowing

The `engine/outdated_runtime_actions.txt` list only covers versions that run on Node 12 or 16. Since Node 20 was removed, versions like `actions/checkout@v4` or `actions/setup-node@v4` are outdated too, and R1023 doesn't flag them yet. It's another example of a rule only knowing what its data list tells it: check `runs.using` yourself.

## Run the simulation

```bash
cd educational/en/05-outdated-runtime-unknown-runner
pip install pyyaml requests
python3 simulate.py
```

The script loads the project's `engine/outdated_runtime_actions.txt` (the same data source `R1023` uses in production) and `R1024`'s list of known labels, and shows for each action in `vulnerable.yml` whether it's still guaranteed to work on GitHub's current runners.

## Your turn

[`exercise.yml`](exercise.yml) hasn't been touched in months: its runners don't exist and two actions use a retired Node.js runtime. Get it working again.

```bash
cp exercise.yml my_solution.yml      # work on the copy
python3 ../check.py                  # repeat until you see "PASSED"
python3 ../check.py --all            # extra challenge: every engine rule
```

The checker runs this lesson's same real rules and also verifies you haven't "solved" the exercise by deleting whatever was failing.

<details>
<summary>Hints</summary>

- Read the Linux runner label slowly.
- `macos-10.15` was retired years ago: look for a current macOS label.
- Move `actions/setup-python` and `actions/cache` up to a current major version and pin them by hash.

</details>

The solution is in [`../solutions/05.yml`](../solutions/05.yml). Try it before looking.
