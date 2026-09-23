# 11. Network exfiltration and attack surface (Zenith Engine-specific rules)

**OWASP CI/CD category:** CICD-SEC-10 (mostly) / CICD-SEC-1 / CICD-SEC-7
**Zenith Engine rules:** `R1005` (known fraudulent domain), `R1009` (direct IP call), `R1015` (DNS exfiltration), `R1018` (exfiltration via the GitHub API), `R1006` (self-hosted runner), `R1013` (`pull_request` without branch restrictions), `R1020` (cloud runner without hardening)
**Observed real-world frequency:** 587 combined alerts (2.7% of the total) under the reference paper's "OTHER" category. These rules sit **outside the taxonomy of the 10 common weaknesses**; they're Zenith Engine detections the paper doesn't classify under any of them. Some have counterparts in other scanners (for example, `zizmor` and `poutine` also flag self-hosted runners), but the network exfiltration ones (R1005, R1009, R1015, R1018) are Zenith's own.

## What it is

This lesson bundles seven smaller rules that share a common thread: **what can leave a CI/CD job, where to, and what machine that job is actually running on**.

| Rule | What it detects | Why it matters |
|---|---|---|
| `R1005` | A `curl`/`wget` to a domain from the `engine/fraudulent_domains.txt` list (domains known for package typosquatting/phishing) | The pipeline downloads from or sends data to a domain with a known abuse reputation |
| `R1009` | A network call to a literal (non-private) IP instead of a domain name | With no DNS in the loop, there's no way to audit/block by domain; usually a sign of C2 or direct exfiltration |
| `R1015` | `dig`/`nslookup` with an abnormally long subdomain (≥20 characters) | The classic **DNS exfiltration** pattern: the stolen data is encoded right into the queried subdomain's name, which almost no egress firewall blocks because DNS traffic "always has to go out" |
| `R1018` | A call to `api.github.com/repos/<owner>/<repo>` for a repository that **isn't** the current one (`github.repository`) | Using the GitHub API as an exfiltration channel: uploading stolen data as the content of a file, issue, or release in a repository the attacker controls, with traffic to `api.github.com`, which almost no egress filter blocks since it's "legitimate GitHub traffic" |
| `R1006` | `runs-on: self-hosted` | A self-managed runner, outside GitHub's ephemeral infrastructure. It persists across runs, which massively widens the blast radius of any compromise (lesson [`01`](../01-unpinned-dependencies/)) |
| `R1013` | `pull_request` trigger without `branches`/`branches-ignore` | The workflow fires for PRs against **any** branch of the repository, unnecessarily widening the attack surface |
| `R1020` | Self-hosted runner with a cloud label (`ec2`, `aws`, `azure`...) without `harden-runner` | A self-managed cloud machine with no egress control combines the worst of both worlds: its identity grants access to cloud infrastructure (for example, credentials from the metadata service) and there's zero network visibility |

## How to fix it

- **`R1005`/`R1009`**: never contact literal IPs or blocklisted domains; always use domain names from known providers, and add `harden-runner` (lesson [`03`](../03-runner-hardening-egress/)) with an explicit allowlist.
- **`R1015`**: if you need DNS resolution within the pipeline, do it only against domains you control; any `dig`/`nslookup` with a "weird", long subdomain should raise suspicion during code review.
- **`R1018`**: if the pipeline needs to write to another repository (e.g. publishing generated documentation), always use `github.repository` or an explicit, auditable constant, never an expression an attacker could control to decide which repo gets written to.
- **`R1006`/`R1020`**: on self-hosted runners, especially in the cloud, always add `harden-runner`, verify the machine is destroyed after each job (no state persists across runs), and never share it between repositories with different trust levels.
- **`R1013`**: always restrict `pull_request` to the branches that actually need it: `branches: [main, develop]`.

## Run the simulation

```bash
cd educational/en/11-network-exfiltration-attack-surface
pip install pyyaml requests
python3 simulate.py
```

The script runs all seven real rules against `vulnerable.yml`/`fixed.yml`, and decodes the simulated DNS-exfiltration payload (R1015) to show exactly what data would be traveling hidden inside the subdomain name.

### With Docker (optional): watch the exfiltration for real

`docker/` spins up a **local HTTP collector** (isolated, on your own machine, with no Internet access) that simulates the attacker's server: it literally runs `vulnerable.yml`'s `curl` command against it, and you'll see the request with the secret arrive right in the collector's own terminal.

```bash
cd educational/en/11-network-exfiltration-attack-surface/docker
docker compose up --build
```

## Your turn

[`exercise.yml`](exercise.yml) sends data to an external service, queries a subdomain with encoded data, publishes to someone else's repository and copies the binary to an IP, all from a self-managed cloud machine with no controls and for any PR. Make it do the same things (build, measure, check and publish) without those risks.

```bash
cp exercise.yml my_solution.yml      # work on the copy
python3 ../check.py                  # repeat until you see "PASSED"
python3 ../check.py --all            # extra challenge: every engine rule
```

The checker runs this lesson's same real rules and also verifies you haven't "solved" the exercise by deleting whatever was failing.

<details>
<summary>Hints</summary>

- Limit the `pull_request` trigger to the branches that need it.
- A GitHub-hosted runner is ephemeral and has no access to your cloud.
- The metrics can stay inside the workflow as an artifact.
- To publish to your own repository use `${{ github.repository }}`, and for the deployment server, a domain name instead of an IP.

</details>

The solution is in [`../solutions/11.yml`](../solutions/11.yml). Try it before looking.
