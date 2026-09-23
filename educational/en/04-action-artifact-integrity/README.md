# 04. Action and artifact integrity (AIW: Artifact Integrity Weakness)

**CWE:** CWE-353 (Missing Support for Integrity Check) / CWE-494 (Download of Code Without Integrity Check)
**OWASP CI/CD category:** CICD-SEC-8 / CICD-SEC-9 (Ungoverned Usage of 3rd Party Services / Improper Artifact Integrity Validation)
**Zenith Engine rules:** `R1007` (unverified organization action), `R1008` (action not found in the Marketplace), `R1010` (artifact published without integrity verification)
**Observed real-world frequency:** 2,134 alerts (9.8% of the total).

## What it is

Three different flavors of the same question: *"is what's actually running / being published really what you think it is?"*

- **`R1007`**: the action belongs to an organization that isn't in `engine/verified_organizations.txt` (organizations with a known good reputation and active maintenance: `actions`, `github`, `docker`, `aws-actions`...). It doesn't mean the action is malicious, but it does mean **nobody has verified its provenance** for you.
- **`R1008`**: the `uses:` reference doesn't match any repository with an `action.yml`/`action.yaml` reachable through the GitHub API. It could be a typo, a deleted action, or (worst case) a **typosquatting** attempt: an attacker registers `actions/checkuot` hoping someone uses it by mistake.
- **`R1010`**: the job publishes an artifact (a Docker image, a PyPI package, a GitHub release, a `goreleaser` binary...) without signing or verifying it with an integrity tool like **cosign** (Sigstore). Without a signature, anyone who compromises the build step can alter the artifact between build and publish, leaving no verifiable evidence.

## Why it matters

`R1007`/`R1008` are the entry point of the **action supply chain**: if you blindly trust any `owner/action@tag` without checking who maintains it, you're delegating your pipeline's security to the security hygiene of an unknown third party with potential access to your secrets (see lesson [`02`](../02-excessive-github-token-permissions/)).

`R1010` protects the other end of the chain: even if your pipeline is flawless, if you publish an unsigned artifact, **nothing stops someone from swapping it out afterward** (in a compromised registry, in transit, or directly in the job itself if an intermediate step gets compromised) and having your end users install that tampered artifact while trusting it came from you.

## How to fix it

**For `R1007`/`R1008`:**
1. Before adopting an action from an individual author or an unknown organization, check: star count, recent activity, whether it carries a GitHub verification badge, whether it's listed in the official Marketplace.
2. Prefer forks/mirrors maintained by organizations you actually control, or vendor the action as a local composite action (`./local-actions/...`) after reviewing its code.
3. If you decide to use it anyway, always pin it by hash (lesson [`01`](../01-unpinned-dependencies/)) so a future compromise of that account doesn't affect you automatically.

**For `R1010`:**
```yaml
- uses: docker/build-push-action@<hash> # v7.4.0
  id: build
  with:
    push: true
    tags: myorg/myimage:${{ github.sha }}

- uses: sigstore/cosign-installer@<hash> # v3.5.0

- env:
    DIGEST: ${{ steps.build.outputs.digest }}
  run: cosign sign --yes "myorg/myimage@${DIGEST}"
```
This signs the image with **Sigstore keyless signing**, using the GitHub Actions workflow's own OIDC identity, so whoever consumes the image can use `cosign verify` to confirm it came exactly from this repository and this workflow.

> **Why `fixed.yml` still gets an R1007:** `sigstore` isn't in `engine/verified_organizations.txt`, so R1007 flags `sigstore/cosign-installer` even though it's the official signing tool. The verified organizations list is a short heuristic, not a registry of everything trustworthy. The alert is still useful: it forces a conscious decision to trust that organization. If you'd rather not depend on any third-party action, the "Your turn" solution downloads cosign from its official release and checks its SHA-256.

## Run the simulation

```bash
cd educational/en/04-action-artifact-integrity
pip install pyyaml requests
python3 simulate.py
```

The script reproduces `R1007`/`R1008` (offline, without calling the real GitHub API)/`R1010`, and simulates the integrity scenario: it generates a fictional "digest" of the artifact at build time and another after a simulated registry tampering, showing how `cosign verify` would catch it while a plain `docker pull` wouldn't.

## Your turn

[`exercise.yml`](exercise.yml) builds and publishes a Docker image. It uses an action with a suspicious name, another from an unknown author, and publishes the image unsigned. Fix it without removing any step (you can add the ones you need).

```bash
cp exercise.yml my_solution.yml      # work on the copy
python3 ../check.py                  # repeat until you see "PASSED"
python3 ../check.py --all            # extra challenge: every engine rule
```

The checker runs this lesson's same real rules and also verifies you haven't "solved" the exercise by deleting whatever was failing.

<details>
<summary>Hints</summary>

- Read the first action's name carefully, letter by letter.
- Linting a Dockerfile doesn't need a third-party action: the official `hadolint/hadolint` image can run in a `run:` step.
- To sign with cosign without relying on a third-party action, download the binary from its official release and check its SHA-256 with `sha256sum -c` before using it. Keyless signing needs `id-token: write`.

</details>

The solution is in [`../solutions/04.yml`](../solutions/04.yml). Try it before looking.
