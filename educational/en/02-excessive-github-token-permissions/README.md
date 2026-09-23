# 02. Excessive `GITHUB_TOKEN` permissions (EPW: Excessive Permission Weakness)

**CWE:** CWE-250 (Execution with Unnecessary Privileges) / CWE-732 (Incorrect Permission Assignment)
**OWASP CI/CD category:** CICD-SEC-5 (Insufficient PBAC: Pipeline-Based Access Controls)
**Zenith Engine rules:** `R1003` (missing `permissions` block), `R1011` (third-party action with access to `GITHUB_TOKEN`)
**Observed real-world frequency:** 2,183 alerts (10% of the total), the third most common weakness.

## What it is

Every workflow run automatically receives a short-lived `GITHUB_TOKEN`. If the workflow **doesn't explicitly declare** a `permissions:` block (at either workflow or job level), that token inherits the **repository's default permissions**, which in many organizations are still `read/write` over almost everything: contents, issues, pull requests, packages, and so on. (Repositories and organizations created since 2023 start as read-only, but the setting is inherited and changed by hand, so it's better not to assume it.)

`R1003` flags this: no `permissions:` defined = maximum attack surface by default.

`R1011` is more specific: if an **unverified third-party action** has access to that token (either because it receives it explicitly in a `with:`/`env:`, or because it inherits the job's permissions), and that action gets compromised (see lesson [`01`](../01-unpinned-dependencies/) on `tj-actions/changed-files`), the attacker can use the token for whatever it's allowed to do: publish fake releases, delete branches, modify the repository's code, write to Packages...

## Why it matters

The principle is simple: **the blast radius of a compromised `GITHUB_TOKEN` is exactly its permission level**. A CI pipeline that only needs to read code (`contents: read`) but runs with default permissions (`contents: write`, `issues: write`, `pull-requests: write`...) turns any compromised third-party action from lesson 01 into a path to:

- Directly modify the repository (`contents: write`).
- Merge its own malicious pull requests (`contents: write`) and approve them, if the organization has *Allow GitHub Actions to create and approve pull requests* enabled (`pull-requests: write`).
- Publish fake packages under your name (`packages: write`).

## How to fix it

1. **Always** declare a `permissions:` block at workflow level with the minimum possible, and only raise it in the specific job that needs more:
   ```yaml
   permissions:
     contents: read

   jobs:
     release:
       permissions:
         contents: write   # only this job needs write access
   ```
2. If the repository needs broad permissions *in some* job, don't set them globally; declare them only on that job (least-privilege permissions per job, not per workflow).
3. Before giving a third-party action access to the token (`with: token: ${{ secrets.GITHUB_TOKEN }}` or similar), check that the organization is verified (see `engine/verified_organizations.txt`) and that the permission you're granting is the bare minimum required.
4. Enable the organization setting **"Workflow permissions" → "Read repository contents permission"** on GitHub, which changes the whole repository's default permission to read-only unless a workflow explicitly asks for more.

5. **Don't leave the token on disk if you don't need it.** `actions/checkout` stores the `GITHUB_TOKEN` in `.git/config` by default; with `persist-credentials: false` it doesn't. Minimal permissions limit what the token can do; this limits who gets to see it.

## Run the simulation

```bash
cd educational/en/02-excessive-github-token-permissions
pip install pyyaml requests
python3 simulate.py
```

The script doesn't just replicate `R1003`/`R1011`: it **builds the effective permissions table** the `GITHUB_TOKEN` would have for each job in the workflow (the same table you'd see on the "Permissions" tab of a real GitHub run) and shows, for the vulnerable job, exactly which GitHub API operations a compromised third-party action would gain access to.

## Your turn

[`exercise.yml`](exercise.yml) labels new PRs and welcomes their author. It declares no permissions and hands the `GITHUB_TOKEN` to an action from an unknown author. Fix it while keeping every step's parameters (`with:`).

```bash
cp exercise.yml my_solution.yml      # work on the copy
python3 ../check.py                  # repeat until you see "PASSED"
python3 ../check.py --all            # extra challenge: every engine rule
```

The checker runs this lesson's same real rules and also verifies you haven't "solved" the exercise by deleting whatever was failing.

<details>
<summary>Hints</summary>

- Declare `permissions:` at workflow level with the minimum, and raise only on the job what's needed to label and comment.
- Labeling PRs based on changed files is exactly what `actions/labeler` does, from a verified organization.
- The checker requires `repo-token` to still exist: the fix isn't taking the token away, it's giving it to someone who deserves it.

</details>

The solution is in [`../solutions/02.yml`](../solutions/02.yml). Try it before looking.
