# 01. Unpinned dependencies (UDW: Unpinned Dependency Weakness)

**CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**OWASP CI/CD category:** CICD-SEC-8 (Ungoverned Usage of 3rd Party Services)
**Zenith Engine rules:** `R1002` (action without a pinned hash), `R1012` (branch used as version), `R1017` (use of `@latest`)
**Observed real-world frequency:** 10,345 alerts, **by far the most common weakness** (47% of everything detected).

## What it is

When a `step` uses `uses: owner/action@REF`, `REF` can be three very different things in terms of security guarantees:

1. **A commit hash** (`@a1b2c3...`, 40 hex characters): immutable. That content never changes.
2. **A tag** (`@v4`, `@v4.1.0`): **mutable**. The action's owner (or anyone who compromises their account) can repoint the `v4` tag to a completely different commit at any time, and your workflow will run it automatically on the next execution without anyone ever touching your `.yml`.
3. **A branch** (`@main`, `@master`) or **`@latest`**: moves with every new commit to the action's repository. Your pipeline can run different code on every `run`, with zero control or review.

Zenith Engine splits this into three rules:
- `R1002` fires for any reference that isn't a hash (MEDIUM severity, the general case).
- `R1012` escalates to HIGH when the reference isn't even a version-shaped tag (`v4`, `4.1.0`) or a hash, i.e. when it looks like a branch name (`main`, `master`, `develop`).
- `R1017` escalates to CRITICAL when the reference is literally `@latest`, the most dangerous case because it explicitly points at "whatever is newest", without even the illusion of stability that a fixed branch name gives you.

## Why it matters

This is exactly the attack vector behind the **`tj-actions/changed-files`** compromise (March 2025, CVE-2025-30066): a mutable tag (`v35`, `v36`...) was repointed to a malicious commit that dumped CI secrets into execution logs. Any workflow using `tj-actions/changed-files@v35` (instead of a hash) started executing malicious code automatically, without anyone having changed a single line of their own `.yml`. Thousands of repositories were affected overnight.

Pinning by hash isn't paranoia: it's the only way to guarantee that "what you reviewed" and "what actually runs" are the same thing.

## How to spot it manually

Search your workflows for any `uses:` whose part after `@` isn't 40 hex characters:

```bash
grep -rn "uses:" .github/workflows/ | grep -vE "@[0-9a-f]{40}"
```

## How to fix it

1. Replace the tag with the exact commit hash it currently points to (`git ls-remote https://github.com/owner/action v4`, or look at the release page on GitHub).
2. Leave the tag as a comment next to it, so it's still human-readable:
   ```yaml
   - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
   ```
3. Use **Dependabot** or **Renovate** with `github-actions` support in `.github/dependabot.yml`: both automatically update the hash when a new version ships, opening a reviewable PR instead of applying the change silently.
4. If you can't pin by hash (e.g. an internal action that changes a lot), at minimum use a semantic-version tag (`@v4`) instead of a branch or `@latest`, and consider enabling **step-security/harden-runner** with `disable-sudo` and network monitoring (see lesson [`03-runner-hardening-egress`](../03-runner-hardening-egress/)) to catch anomalous behavior if the tag ever gets hijacked.

## Run the simulation

```bash
cd educational/en/01-unpinned-dependencies
pip install pyyaml requests
python3 simulate.py
```

The script runs the real `R1002`/`R1012`/`R1017` engine rules, and also **simulates the attack on `tj-actions/changed-files`**: it shows how the same tag (`@v35`) can "resolve" to two different commits across two different pipeline runs, without the `.yml` changing by a single line.

## Your turn

[`exercise.yml`](exercise.yml) publishes the project documentation using five actions, and none is pinned immutably: there are tags, a branch and an `@latest`. Make everything it runs immutable without removing any step.

```bash
cp exercise.yml my_solution.yml      # work on the copy
python3 ../check.py                  # repeat until you see "PASSED"
python3 ../check.py --all            # extra challenge: every engine rule
```

The checker runs this lesson's same real rules and also verifies you haven't "solved" the exercise by deleting whatever was failing.

<details>
<summary>Hints</summary>

- Every `uses:` must end in `@` followed by 40 hexadecimal characters.
- To find a version's hash: `git ls-remote https://github.com/<owner>/<repo> refs/tags/<tag>`. For an annotated tag, the commit is the line ending in `^{}`.
- Keep the version in a comment (`# v7.0.1`) so a human knows what's behind the hash.

</details>

**Finish with `python3 ../check.py --online`.** Offline, the checker can only see that the hash has 40 characters: it would accept a made-up one. With `--online` it asks GitHub whether that hash really is the version your comment claims.

The solution is in [`../solutions/01.yml`](../solutions/01.yml). Try it before looking.
