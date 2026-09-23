# 08. Secrets exposure (SEW: Secrets Exposure Weakness)

**CWE:** CWE-200 (Exposure of Sensitive Information) / CWE-522 (Insufficiently Protected Credentials)
**OWASP CI/CD category:** CICD-SEC-6 (Insufficient Credential Hygiene)
**Zenith Engine rules:** `R1014` (hardcoded credential or token), `R1019` (secret exposed in logs)
**Observed real-world frequency:** 63 alerts (0.3% of the total). Rare, but **always CRITICAL**: once it shows up, the secret is compromised immediately and permanently (it must be rotated; fixing the `.yml` isn't enough).

## What it is

Two different ways for a secret to stop being secret:

- **`R1014`**: a field with a sensitive name (`password`, `token`, `secret`, `api_key`, `access_key`, `private_key`, `auth*`, `credential*`) in a step's `env:` or `with:` has a **literal value** instead of `${{ secrets.X }}`. The value ends up written in plain text inside the `.yml`, visible to anyone with read access to the repository and, if the repo is public, to anyone on the Internet, indexed by code search engines and by automated secret-scanning tools that constantly crawl GitHub.
- **`R1019`**: the workflow correctly uses `${{ secrets.X }}` (not hardcoded), but the value of that variable later gets **printed** in a `run:` via `echo`, `print`, `cat`, or similar, usually with no ill intent, almost always for debugging ("let's see what this variable holds"). The result is the same: the secret ends up in plain text, this time in the workflow's **execution logs**, visible to anyone with read access to the repository's Actions (which in many repos is more people than have write access).

## Why it matters

GitHub automatically masks in the logs any value that *exactly* matches a secret already known to the system (replacing it with `***`). But that protection has known, widely documented gaps:
- If the secret gets transformed before being printed (`base64`, concatenated with other text, split into parts), the masking no longer recognizes it as the original value.
- A hardcoded secret (`R1014`) never even goes through the masking system: GitHub has no idea that string is sensitive.
- Anyone with permission to re-run the workflow with `debug` enabled, or with access to a fork that also receives the secret via `pull_request_target`, may be able to extract it.

And unlike almost every other flaw in this catalog, **the fix isn't just correcting the `.yml`**: a secret that has appeared in plain text (in a commit, in a log) must be treated as compromised and **rotated**, because git history and past execution logs may still be reachable even after the current file gets fixed.

## How to fix it

**For `R1014`:**
```yaml
# Bad
- uses: some-action@v1
  with:
    api_key: "sk_live_EXAMPLE-not-a-real-key"

# Good
- uses: some-action@v1
  with:
    api_key: ${{ secrets.STRIPE_API_KEY }}
```
If the secret already leaked into a commit, **rotate it immediately** with the corresponding provider on top of fixing the `.yml`. Rewriting git history isn't enough, GitHub and any clone may have already indexed it.

**For `R1019`:**
```yaml
# Bad
- env:
    TOKEN: ${{ secrets.DEPLOY_TOKEN }}
  run: echo "Using token: $TOKEN"

# Good: don't print it. If you need to confirm the variable exists, check
# only its length or presence, never its value:
- env:
    TOKEN: ${{ secrets.DEPLOY_TOKEN }}
  run: |
    if [ -z "$TOKEN" ]; then echo "TOKEN is not set"; exit 1; fi
    echo "TOKEN is set (length: ${#TOKEN})"
```

## Run the simulation

```bash
cd educational/en/08-secrets-exposure
pip install pyyaml requests
python3 simulate.py
```

The script detects `R1014`/`R1019` and **simulates the real execution log** GitHub Actions would produce for each step in `vulnerable.yml` (including which parts GitHub would actually mask automatically and which it wouldn't), comparing it against the log `fixed.yml` would produce.

## Your turn

[`exercise.yml`](exercise.yml) deploys an application, but it has a password written in the file and two different ways of printing a secret to the logs. One of them **evades** GitHub's masking. No secret may stay in the file or in the logs, and the steps' parameters must remain.

```bash
cp exercise.yml my_solution.yml      # work on the copy
python3 ../check.py                  # repeat until you see "PASSED"
python3 ../check.py --all            # extra challenge: every engine rule
```

The checker runs this lesson's same real rules and also verifies you haven't "solved" the exercise by deleting whatever was failing.

<details>
<summary>Hints</summary>

- The registry password has to come from `secrets.*`. And in real life you'd also have to rotate it.
- Cutting a secret with `cut` produces text that no longer matches the secret, so GitHub doesn't mask it.
- If you need to check a secret is configured, check whether it's empty or how long it is, never its content.

</details>

The solution is in [`../solutions/08.yml`](../solutions/08.yml). Try it before looking.
