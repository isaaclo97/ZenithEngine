# 10. Components with a known CVE/GHSA (KVCW: Known Vulnerable Component Weakness)

**CWE:** CWE-1395 (Dependency on Vulnerable Third-Party Component)
**OWASP CI/CD category:** CICD-SEC-3 (Dependency Chain Abuse)
**Zenith Engine rules:** `R1025`
**Observed real-world frequency:** 2 alerts (<0.1% of the total) in the scanned corpus. It's the rarest, but conceptually the most direct: this isn't a bad practice or a risk pattern, it's **an already-identified, published vulnerability** in the exact version the workflow is using.

## What it is

Unlike the other rules (which look for risk patterns: missing hardening, broad permissions, mutable tags...), `R1025` queries a **database of real advisories**: the [GitHub Advisory Database](https://github.com/advisories) filtered to the `actions` ecosystem. For every `uses: owner/action@version` in the workflow, it checks whether that exact version falls inside the vulnerable range of any published CVE/GHSA for that action.

In production, `check_known_vulnerable_component_1025` (`engine/rules/vulnerabilities.py`) does this in two phases:
1. It tries to fetch the live advisory list from `api.github.com/advisories?ecosystem=actions`.
2. If the API isn't reachable (no network, rate limit...), it automatically falls back to a local snapshot (`engine/known_vulnerabilities.json`) so it keeps working.

It only evaluates actions pinned to an **exact numeric version** (`@v4.1.0` or `@4.1.0`; the leading `v` is ignored), not to a floating major (`@v4`) or a hash, because, as the code's own comment explains, there's no safe way to know which exact version a floating tag like `@v4` resolves to today without querying the repository, and assuming the best or worst case would produce false positives or false negatives.

## Why it matters

This rule turns an abstract list of "best practices" into something very concrete: **"this exact line in your workflow has a publicly documented exploit"**. It's not a risk assumption: it's the same database GitHub uses for Dependabot alerts, applied to CI/CD actions instead of application dependencies.

The best-known historical example in this space is, again, **`tj-actions/changed-files`** (CVE-2025-30066, March 2025): after the supply-chain compromise, GitHub published a GHSA covering the affected version range. Any workflow still pinned to one of those exact versions (even after the maintainer cleaned up the tag) remained detectable by this rule until it was explicitly updated to a version released after the patch.

## How to fix it

1. When `R1025` flags an action, the alert includes the advisory's `id` (CVE or GHSA) and its URL. Check it first to understand the exact scope and whether your specific use of the action is affected.
2. Update to the first version released after the vulnerable range noted in the advisory (not just "the latest one", in case the latest introduces breaking changes you'd rather evaluate separately).
3. Pin the new version by commit hash (lesson [`01`](../01-unpinned-dependencies/)), not just by tag, so a future compromise of that tag doesn't affect you automatically again.
4. If the action has no available patch and is essential, isolate its execution as much as possible: no access to secrets (lesson [`02`](../02-excessive-github-token-permissions/)) and `harden-runner` in `block` mode (lesson [`03`](../03-runner-hardening-egress/)).

## Tension with lesson 01 (pinning by hash)

`R1025` can only look up an action's advisory when its reference is a **numeric version** (`@v0.35.0`): that's how GitHub publishes affected ranges in its advisories. If you instead pin the action by **commit hash** (the recommendation in lesson [`01`](../01-unpinned-dependencies/)), `R1025` can't correlate that hash with any version range and **won't evaluate that action** against the CVE database. This isn't a contradiction between lessons: pinning by hash is still the right call for guaranteeing immutability; you just need to pair it with an update process (Dependabot/Renovate) that does know about versions and brings you security patches. The integrity guarantee comes from the hash; staying current on CVEs comes from your update process, not from Zenith Engine looking at the hash.

## Run the simulation

```bash
cd educational/en/10-known-vulnerable-components
pip install pyyaml requests
python3 simulate.py
```

To keep this lesson **deterministic and network-independent**, the script forces the use of the local snapshot `engine/known_vulnerabilities.json` (the same fallback the real application uses when the GitHub API isn't reachable) instead of attempting the live call, so the result doesn't change depending on which CVEs have been published since you wrote this lesson.

## Your turn

[`exercise.yml`](exercise.yml) uses three actions with a published advisory for the exact version they use. Upgrade them to a version with no known vulnerabilities.

```bash
cp exercise.yml my_solution.yml      # work on the copy
python3 ../check.py                  # repeat until you see "PASSED"
python3 ../check.py --all            # extra challenge: every engine rule
```

The checker runs this lesson's same real rules and also verifies you haven't "solved" the exercise by deleting whatever was failing.

<details>
<summary>Hints</summary>

- Run `python3 ../check.py exercise.yml` first: each alert includes the advisory's identifier and link, with the affected version range.
- Move up to the first fixed version or a later one.
- Ideally, pin them by hash with the version in a comment. Keep in mind R1025 can no longer look them up then (see "Tension with lesson 01" above).

</details>

The solution is in [`../solutions/10.yml`](../solutions/10.yml). Try it before looking.
