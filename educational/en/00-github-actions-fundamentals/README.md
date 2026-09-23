# 00. GitHub Actions fundamentals

**Who it's for:** if you've never written a workflow, or if terms like *job*, *runner* or `GITHUB_TOKEN` sound familiar but you couldn't explain them. Lessons 01 to 12 take all of this for granted.
**What you get:** being able to read any workflow and ask the four security questions that come up throughout the course.

## What CI/CD is and where GitHub Actions fits

**CI** (*continuous integration*) means automatically building and testing every time someone proposes a change. **CD** (*continuous delivery or deployment*) means automatically publishing the result: a package, a Docker image, a website. GitHub Actions is the CI/CD system built into GitHub: you describe what to do in a YAML file and GitHub runs it on its machines.

From a security point of view, a CI/CD pipeline is a very attractive target: **it runs code automatically, it holds credentials to publish, and everything it produces ends up with your users.** Whoever controls it controls what you ship. That's what **supply chain** security is about: everything that goes into your software without you having written it.

## The pieces of a workflow

Open [`example.yml`](example.yml) while you read this table: it's commented line by line.

| Piece | Where it appears | What it is |
|---|---|---|
| **Workflow** | `.github/workflows/*.yml` | A YAML file with an automated process. A repository can have several. |
| **Event** | `on:` | What triggers it: a `push`, a pull request, a comment, a schedule (`schedule`), a button (`workflow_dispatch`)... |
| **Job** | `jobs:` | A unit of work. Each job runs on its own machine. By default they run in parallel; `needs:` chains them. |
| **Runner** | `runs-on:` | The machine the job runs on. `ubuntu-latest` is a GitHub machine, fresh on every run. `self-hosted` is your own machine, which is **not** wiped between runs. |
| **Step** | `steps:` | Each step of a job, in order. It's one of two kinds: `uses:` or `run:`. |
| **Action** | `uses: owner/repo@version` | Code from **another repository** that runs inside your job. It's the most common (and most overlooked) dependency of a pipeline. |
| **Script** | `run:` | Shell commands written in your own workflow. |
| **Parameters** | `with:` / `env:` | `with:` are an action's inputs; `env:` are environment variables for the step or job. |
| **Expression** | `${{ ... }}` | GitHub **replaces it with its value before** running the step. It gives access to contexts: `github.*` (event data), `secrets.*`, `vars.*`, `steps.*`, `needs.*`... |
| **Condition** | `if:` | Decides whether a job or step runs. |
| **Secret** | `secrets.NAME` | An encrypted value (token, password) configured under *Settings > Secrets*. |
| **`GITHUB_TOKEN`** | automatic | A temporary token GitHub creates for every run to talk to its API. What it can do is controlled with `permissions:`. |
| **Artifact** | `upload-artifact` | A file that outlives the job, to pass to another job or download later. |

## The four security questions

Every lesson is a variation on these four questions. Ask them whenever you read a workflow:

1. **Who can trigger this?** A `push` can only come from someone with write access. A `pull_request` or an `issue_comment` can be caused by **anyone with a GitHub account**.
2. **With which privileges does it run?** What the `GITHUB_TOKEN` can do, which secrets it can reach and which machine it runs on.
3. **What foreign code does it run?** Every `uses:` is third-party code; so is every `npm install` or `pip install`. If it changes, your pipeline changes without anyone touching your repository.
4. **What data I don't control comes in?** A PR title, a comment body, a branch name: they're written by whoever triggers the event, and they can reach a script or a command.

## Events: who triggers them and with what access

| Event | Who can cause it | Secrets and a write token? |
|---|---|---|
| `push` | Anyone with write access | Yes |
| `pull_request` | **Anyone**, from a fork | From a fork, **no**: read-only token and no secrets. It's the safe design. |
| `pull_request_target` | **Anyone**, from a fork | **Yes**, with the repository's privileges. Dangerous if it runs the PR's code (lesson 06). |
| `issue_comment`, `issues` | **Anyone** who can comment or open issues | Yes |
| `workflow_dispatch` | Anyone with write access | Yes |
| `schedule` | Nobody: a schedule starts it | Yes |
| `workflow_run` | Another workflow when it finishes | Yes, even if the previous workflow processed data from a fork |

## The `GITHUB_TOKEN` and `permissions:`

If a workflow doesn't declare `permissions:`, the token gets the repository's or organization's **default permissions**. Repositories created in recent years usually default to read-only, but many older repositories and organizations still grant write access to almost everything. That's why the good practice is to always declare it, with the minimum needed:

```yaml
permissions:
  contents: read        # at workflow level: read only

jobs:
  release:
    permissions:
      contents: write   # and more only on the job that needs it
```

One detail you'll see in every fixed workflow in the course: `actions/checkout` **stores the token in `.git/config`** by default, so later steps can `git push`. If the job isn't going to push, turn it off with `persist-credentials: false`. That way the token doesn't sit on disk within reach of every later step, or end up inside an artifact that uploads that folder.

```yaml
- uses: actions/checkout@<hash> # v7.0.1
  with:
    persist-credentials: false
```

## Course map

| Workflow piece | Lessons |
|---|---|
| Actions (`uses:`) and dependencies | [01](../01-unpinned-dependencies/), [04](../04-action-artifact-integrity/), [05](../05-outdated-runtime-unknown-runner/), [10](../10-known-vulnerable-components/), [12](../12-typosquatting-tips-best-practices/) |
| `GITHUB_TOKEN` and `permissions:` | [02](../02-excessive-github-token-permissions/) |
| Runner and network | [03](../03-runner-hardening-egress/), [05](../05-outdated-runtime-unknown-runner/), [11](../11-network-exfiltration-attack-surface/) |
| Events (`on:`) | [06](../06-privileged-triggers-pull-request-target/), [11](../11-network-exfiltration-attack-surface/) |
| `${{ }}` expressions and untrusted data | [07](../07-expression-injection/) |
| Secrets | [08](../08-secrets-exposure/) |
| `if:` conditions | [09](../09-always-true-if-conditions/) |

## Run the simulation

```bash
cd educational/en/00-github-actions-fundamentals
pip install pyyaml requests
python3 simulate.py
```

The script reads `example.yml` with Zenith Engine's real parser and draws its **trust map**: which events trigger it and who can cause them, where each job runs and with which permissions, which third-party actions it runs and how they're pinned, and which expressions bring in untrusted data or secrets. It's exactly the reasoning behind the four questions, done automatically.

## Your turn

[`exercise.yml`](exercise.yml) has six structural errors (and it's missing the `permissions:` block): GitHub wouldn't even run it. Fix it using `example.yml` as a reference.

```bash
cp exercise.yml my_solution.yml      # work on the copy
python3 ../check.py                  # repeat until you see "PASSED"
```

The checker reviews the structure (event, runner, steps, versions, dependencies between jobs), that there's a `permissions:` block and that you haven't deleted any named step.

<details>
<summary>Hints</summary>

- Every workflow needs `on:` and every job needs `runs-on:`.
- A step is `uses:` **or** `run:`, never both. If you need both, that's two steps.
- `uses:` always has `@` and a version. Even better, a commit hash (lesson 01).
- `needs:` has to name a job that exists, spelled exactly the same.

</details>

The solution is in [`../solutions/00.yml`](../solutions/00.yml). Try it before looking.
