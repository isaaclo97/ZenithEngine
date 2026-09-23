# 12. Tips: typosquatting and supply chain best practices

**Lesson type:** practical tips. It doesn't map to a Zenith Engine rule: it uses its own educational detector ([`tools/typosquat.py`](../../tools/typosquat.py)) and gathers what you should always do, beyond what any tool detects.
**Related to:** [01](../01-unpinned-dependencies/) (pinning by hash), [04](../04-action-artifact-integrity/) (where actions come from), [10](../10-known-vulnerable-components/) (known vulnerabilities).

## What typosquatting is

It means registering a name that's **almost identical** to something widely used and waiting for someone to mistype it. It works the same way with GitHub actions, npm or PyPI packages, Docker Hub images and domains. The most common variants:

| Trick | Example | Real name |
|---|---|---|
| Missing letter | `actons/checkout` | `actions/checkout` |
| Swapped letters | `reqeusts`, `actions/setup-pyhton` | `requests`, `actions/setup-python` |
| Hyphen removed or added | `crossenv` | `cross-env` |
| Singular for plural | `action/cache` | `actions/cache` |
| Homoglyphs: letters that look like others | `jeIlyfish` (capital I) | `jellyfish` |
| Spelling variant | `colourama` | `colorama` |

The fake package usually works just like the original (sometimes it copies it whole), so nobody notices anything: the malicious code sits on the side, typically in an install script.

## Real cases

- **`crossenv` (npm, 2017):** it imitated `cross-env` and, when installed, sent the machine's environment variables (where credentials usually live) to the attacker's server.
- **`colourama` (PyPI, 2018):** the British spelling of `colorama`. It watched the clipboard and swapped any copied bitcoin address for the attacker's.
- **`jeIlyfish` (PyPI, 2019):** with a capital I instead of the first l in `jellyfish`. It stole SSH and GPG keys. It stayed published for about a year.
- **GitHub actions (2024):** Orca Security researchers showed the trick works the same with actions: they registered organizations with names almost identical to popular ones and found real workflows using them by mistake.
- **Dependency confusion (2021):** Alex Birsan published packages on npm and PyPI with the same names as *internal* packages of large companies (Apple, Microsoft and PayPal, among others) and a higher version. Their build systems installed them instead of the internal ones.
- **This very lab:** while reviewing it we found that several "pinned" hashes were not the version their comment claimed, and one didn't even exist in the repository. Nobody had noticed because the comment looked right. That's the reason for the simulation's `--online` mode.

## Tips

### Before adding an action or a dependency

1. **Copy the name from the official source** (the Marketplace, the project's documentation, the registry page). Don't type it from memory.
2. **Check who publishes it.** An organization with a verified creator badge, a repository linked from the official website, a long history. Stars and downloads can be inflated: they're not a guarantee.
3. **Look at what it actually runs.** Read the `action.yml`: whether it's a container, a script or JavaScript compiled into `dist/`, and whether it downloads more things at run time.
4. **Fewer dependencies means less risk.** If the action does three lines of shell, write those three lines.

### When pinning versions

5. **Pin to the full commit hash**, with the version in a comment (lesson [01](../01-unpinned-dependencies/)).
6. **Check that the hash is that version and belongs to that repository:**
   ```bash
   git ls-remote https://github.com/actions/checkout refs/tags/v7.0.1
   ```
   Watch out for **impostor commits** (documented by Chainguard in 2023): GitHub resolves a hash from any fork through the original repository's name, so `actions/checkout@<hash from a fork>` works even though that commit was never in `actions/checkout`. Tools like `zizmor` detect this.
7. **Automate updates** with Dependabot or Renovate: they change hash and comment together and open a PR you can review.
8. **Don't adopt a version the day it's released.** Many malicious packages are detected and pulled within hours. Renovate (`minimumReleaseAge`) and Dependabot (`cooldown`) let you wait a few days.

### Across the organization

9. **An allowlist of actions:** under *Settings > Actions > General* you can limit which actions can be used. GitHub also lets you require every action to be pinned to a full hash.
10. **Protect workflows with CODEOWNERS** (`/.github/workflows/ @security-team`) so no change to them gets in without review.
11. **Review new dependencies in every PR** with `actions/dependency-review-action`, which can block those with known vulnerabilities.

12. **Don't let Actions approve its own PRs.** Turn off *Settings > Actions > General > Allow GitHub Actions to create and approve pull requests*, and in branch protection require at least **two** human reviewers and enable *Require approval of the most recent reviewable push*. Otherwise a workflow with `pull-requests: write` can approve and merge its own PR (or an attacker's) using the `GITHUB_TOKEN` and bypass review: it's the classic branch-protection bypass (see lesson [02](../02-excessive-github-token-permissions/)).

13. **Be careful with self-hosted runners.** Unlike GitHub's, they aren't destroyed between runs: a compromise persists (malware, credentials on disk, a poisoned cache) and reaches the next job. Make them ephemeral (a fresh one per run, e.g. with Actions Runner Controller on Kubernetes), don't share them across repositories of different trust levels, add outbound network controls, and **don't use them on public repositories**: a PR from a fork could run code on your own machine. See lesson [11](../11-network-exfiltration-attack-surface/).

### Packages (npm, PyPI...)

14. **Install from the lockfile:** `npm ci` instead of `npm install`; `pip install --require-hashes -r requirements.txt`, with the file generated by `pip-compile --generate-hashes`.
15. **Scoped internal names and a single index:** `@company/utils` with the registry configured for that scope; in pip, a single `--index-url` acting as a proxy, **never** `--extra-index-url`.
16. **Turn off install scripts when you can** (`npm ci --ignore-scripts`): `postinstall` is the usual way in for malicious packages.
17. **Publish without long-lived tokens:** npm and PyPI support *trusted publishing*, which authenticates the workflow via OIDC (`permissions: id-token: write`) instead of storing an `NPM_TOKEN` or PyPI token as a secret. No token means no token to steal.
18. **No `curl ... | bash`:** download a specific version, verify its checksum or signature, then run it.

### If it already happened

19. **Rotate every secret** the pipeline had access to, review the logs of the affected runs, search for the malicious name across all your repositories and report it to the registry (npm, PyPI) or to GitHub so it gets taken down.

## Run the simulation

```bash
cd educational/en/12-typosquatting-tips-best-practices
pip install pyyaml requests
python3 simulate.py            # offline
python3 simulate.py --online   # also checks every hash against GitHub
```

The script analyzes `vulnerable.yml` and `fixed.yml`, explains with examples how it decides a name is suspicious (Levenshtein distance to a list of popular names, plus homoglyph normalization) and what its limits are. With `--online` it also asks GitHub, via `git ls-remote`, which commit each version in the comments really points to: `vulnerable.yml` has a hash that matches nothing.

## Your turn

[`exercise.yml`](exercise.yml) is the CI of a Python API. Some typos that could be typosquatting have slipped in, along with a few risky ways of installing things. Fix it without removing any step.

```bash
cp exercise.yml my_solution.yml
python3 ../check.py
```

<details>
<summary>Hints</summary>

- Two actions have a misspelled name. One has its owner in the singular.
- Two PyPI packages have a misspelled name. The right ones belong in `requirements.txt`, with hashes.
- The linter is installed with `wget ... | sh`. Download a specific version and check its SHA-256 before running it.
- Once the names are fixed, pin the actions by hash (with the version in a comment).

</details>

**Finish with `python3 ../check.py --online`**, which checks on GitHub that the hashes you used exist and are the version in their comment. It's the same mistake this lab once had.

The solution is in [`../solutions/12.yml`](../solutions/12.yml).
