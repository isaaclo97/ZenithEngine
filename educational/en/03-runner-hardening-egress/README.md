# 03. Missing runner hardening (HGW: Hardening Gap Weakness)

**CWE:** CWE-223 (Omission of Security-relevant Information)
**OWASP CI/CD category:** CICD-SEC-10 (Insufficient Logging & Visibility / lack of network isolation)
**Zenith Engine rules:** `R1004` (harden-runner missing or in `audit` mode)
**Observed real-world frequency:** 5,197 alerts (23.7% of the total), **the second most common weakness**.

## What it is

By default, a GitHub Actions `job` runs on an ephemeral machine with **unrestricted outbound network access**: any `step` can `curl`, `wget`, resolve DNS, or open sockets to any destination on the Internet, with nothing logging or blocking it.

[`step-security/harden-runner`](https://github.com/step-security/harden-runner) is the de facto standard action for closing this gap: it's placed as the job's first step and, depending on the policy (`egress-policy: block` + `allowed-endpoints: ...`), **blocks any outbound connection that isn't explicitly allowed** and produces an audit log of all the job's network traffic.

Zenith Engine detects two variants:
- **`R1004_MISSING`** (LOW): the job has no `harden-runner` at all: zero visibility, zero network filtering.
- **`R1004_AUDIT`** (MEDIUM): `harden-runner` is present but configured with `egress-policy: audit`, which only **logs** traffic without blocking it. It's useful for tuning the policy before switching to `block`, but while it stays in `audit` it doesn't stop anything.

## Why it matters

Almost every CI/CD supply-chain attack (a compromised dependency, a backdoored action, leaked secrets) shares a final step: **getting the stolen data out, or pulling down the next stage of the payload, over the network**. If the job has unrestricted egress:

- A secret captured by a compromised dependency can be exfiltrated over HTTP/DNS to an external server with no trace beyond the logs of the command itself (which the attacker controls; see lesson [`08`](../08-secrets-exposure/)).
- There's no automatic alert or block: the team finds out, if it finds out at all, from the secret being misused days or weeks later.

With `harden-runner` set to `block`, exfiltration to an unauthorized domain simply **fails** on the spot, and gets logged with the process name and the exact destination it tried to reach.

## How to fix it

Add `step-security/harden-runner` as the first step of every job:

```yaml
steps:
  - uses: step-security/harden-runner@e14015d583714f6e62063499dc959a02595150a1 # v2.21.1
    with:
      egress-policy: audit   # phase 1: just observe and build the list of real endpoints
```

1. **Observation phase**: deploy with `egress-policy: audit` for a few runs and check step-security's log (or the insight automatically generated in the job summary) to see which domains the pipeline legitimately contacts (npm registry, PyPI, GitHub API...).
2. **Enforcement phase**: switch to `egress-policy: block` and add those domains to `allowed-endpoints`:
   ```yaml
   - uses: step-security/harden-runner@e14015d583714f6e62063499dc959a02595150a1 # v2.21.1
     with:
       egress-policy: block
       allowed-endpoints: >
         github.com:443
         api.github.com:443
         registry.npmjs.org:443
   ```
3. Repeat for every job, including the "trivial" ones (lint, tests): those are precisely the ones that get the least attention and are most often copy-pasted from other workflows.

## Run the simulation

```bash
cd educational/en/03-runner-hardening-egress
pip install pyyaml requests
python3 simulate.py
```

The script detects `R1004_MISSING`/`R1004_AUDIT` job by job and **simulates the egress policy**: given a list of domains the job tries to contact during execution, it shows which connections would have been allowed or blocked under each configuration (`no harden-runner`, `audit`, `block` with `fixed.yml`'s allowlist).

## Your turn

[`exercise.yml`](exercise.yml) has two jobs: one with no network control at all and another with `harden-runner` in `audit` mode. Limit both jobs' outbound network to what they actually need: GitHub and the npm registry.

```bash
cp exercise.yml my_solution.yml      # work on the copy
python3 ../check.py                  # repeat until you see "PASSED"
python3 ../check.py --all            # extra challenge: every engine rule
```

The checker runs this lesson's same real rules and also verifies you haven't "solved" the exercise by deleting whatever was failing.

<details>
<summary>Hints</summary>

- `harden-runner` goes as the **first** step of each job.
- `egress-policy: block` blocks everything not listed in `allowed-endpoints`.
- To discover the real list of destinations you run `audit` for a few runs; here's a starting list: `github.com`, `api.github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com` (Node.js downloads) and `registry.npmjs.org`, all on port 443.

</details>

The solution is in [`../solutions/03.yml`](../solutions/03.yml). Try it before looking.
