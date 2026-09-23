# Educational folder: common flaws in GitHub Actions workflows

This directory accompanies **Zenith Engine** with teaching material about the most common security flaws detected when analyzing real GitHub Actions workflows (over 21,000 alerts from scanning a corpus of real workflows from public repositories).

Each folder is a **self-contained lesson** on one of the "common weaknesses" described in the paper *"Unpacking Security Scanners for GitHub Actions Workflows"* (Fares, Gamage & Baudry), the same taxonomy Zenith Engine uses to classify its 26 rules (see the `Rule → common weakness mapping` table in the project's root `README.md`).

There are also two lessons that don't map to a specific weakness: **00**, with the GitHub Actions fundamentals the rest takes for granted, and **12**, with tips against typosquatting and supply chain best practices.

## Where to start

- **If you've never written a workflow:** start with [00](00-github-actions-fundamentals/) and go in order.
- **If you already know GitHub Actions:** go straight to 01. The order runs from the most frequent (basic hygiene) to the most severe (injection, secrets, privileged triggers).
- **To finish:** [12](12-typosquatting-tips-best-practices/) sums up what to always do, beyond what any tool detects.

Every lesson ends with a **"Your turn"** exercise that grades itself.

## How each lesson is organized

Inside every folder you'll always find:

- **`README.md`**: what the flaw is, why it happens, what real risk it poses (with known incidents where relevant), which Zenith Engine rules detect it, and how to fix it.
- **`vulnerable.yml`**: a realistic workflow containing the flaw.
- **`fixed.yml`**: the same workflow, already fixed. (Lesson 00 uses a single `example.yml`, commented line by line, instead.)
- **`simulate.py`**: a Python script that imports and runs **the real functions from `engine/rules/*.py`** (the same ones the Flask app uses, along with `engine/parser.py` for parsing) against `vulnerable.yml`, and whenever possible **simulates the actual effect of the attack** (what command would end up running, what data would leak, what permissions the token would inherit...). It's then run against `fixed.yml` too, so you can see the before/after contrast. The one exception is `R1008` (lesson 04), which calls the GitHub API in production; here it's replaced by an explicit local mock so the lesson doesn't depend on network access.
- **`exercise.yml`**: the "Your turn" exercise, a different workflow with the same kind of flaw for you to fix.
- **`docker/`** *(only in the lessons where it adds something)*: an isolated environment you bring up with `docker compose up` to observe the impact without touching real GitHub (for example, running the injected command locally, or standing up a "collector" that captures a simulated exfiltration).

## How to run each lesson

```bash
cd educational/en/<folder>
python3 -m venv .venv && source .venv/bin/activate   # optional
pip install pyyaml requests
python3 simulate.py
```

`simulate.py` doesn't need the project's full dependency set (no Flask required); just `pyyaml` and `requests`, both already in the root `requirements.txt`. If you've already installed that file (`pip install -r requirements.txt` from the repo root), there's nothing extra to install.

### "Your turn" exercises

```bash
cp exercise.yml my_solution.yml      # always work on a copy
python3 ../check.py                  # checks my_solution.yml
python3 ../check.py --all            # extra challenge: every engine rule, not just the lesson's
python3 ../check.py --online         # also checks on GitHub that your hashes exist (needs network)
```

[`check.py`](check.py) runs the lesson's same real rules on your solution and also verifies you didn't "solve" it by deleting the failing step, the condition or the data. The solutions are in [`solutions/`](solutions/): look at yours only after you've tried.

## Lesson index

| # | Folder | Common weakness | Zenith rules | Typical severity |
|---|--------|------------------|----------------|-------------------|
| 00 | [`github-actions-fundamentals`](00-github-actions-fundamentals/) | Basic concepts and trust model | (workflow structure, R1003) | |
| 01 | [`unpinned-dependencies`](01-unpinned-dependencies/) | UDW: Unpinned Dependency Weakness | R1002, R1012, R1017 | MEDIUM to CRITICAL |
| 02 | [`excessive-github-token-permissions`](02-excessive-github-token-permissions/) | EPW: Excessive Permission Weakness | R1003, R1011 | MEDIUM to HIGH |
| 03 | [`runner-hardening-egress`](03-runner-hardening-egress/) | HGW: Hardening Gap Weakness | R1004 | LOW to MEDIUM |
| 04 | [`action-artifact-integrity`](04-action-artifact-integrity/) | AIW: Artifact Integrity Weakness | R1007, R1008, R1010 | LOW to MEDIUM |
| 05 | [`outdated-runtime-unknown-runner`](05-outdated-runtime-unknown-runner/) | GRCW: GitHub Runner Compatibility Weakness | R1023, R1024 | LOW to MEDIUM |
| 06 | [`privileged-triggers-pull-request-target`](06-privileged-triggers-pull-request-target/) | PTW: Privileged Trigger Weakness | R1000, R1001, R1021 | HIGH to CRITICAL |
| 07 | [`expression-injection`](07-expression-injection/) | IW: Injection Weakness | R1016 | CRITICAL |
| 08 | [`secrets-exposure`](08-secrets-exposure/) | SEW: Secrets Exposure Weakness | R1014, R1019 | CRITICAL |
| 09 | [`always-true-if-conditions`](09-always-true-if-conditions/) | CFW: Control Flow Weakness | R1022 | HIGH |
| 10 | [`known-vulnerable-components`](10-known-vulnerable-components/) | KVCW: Known Vulnerable Component Weakness | R1025 | CRITICAL |
| 11 | [`network-exfiltration-attack-surface`](11-network-exfiltration-attack-surface/) | Zenith-specific rules (outside the taxonomy) | R1005, R1006, R1009, R1013, R1015, R1018, R1020 | LOW to CRITICAL |
| 12 | [`typosquatting-tips-best-practices`](12-typosquatting-tips-best-practices/) | Tips: typosquatting and supply chain | Own educational detector + R1002 | |

## Observed real-world frequency

The percentages come from scanning, with Zenith Engine, the corpus of 2,722 real workflows from public repositories used in the reference study (Fares, Gamage & Baudry, *"Unpacking Security Scanners for GitHub Actions Workflows"*). Of those, 2,720 had at least one alert, 21,886 in total. The scanned workflows are not included here: they belong to that study. The distribution by weakness was:

| Weakness | # of alerts | % of total |
|---|---:|---:|
| UDW | 10,345 | 47.3% |
| HGW | 5,197 | 23.7% |
| EPW | 2,183 | 10.0% |
| AIW | 2,134 | 9.8% |
| GRCW | 876 | 4.0% |
| Zenith-specific (OTHER) | 587 | 2.7% |
| IW | 362 | 1.7% |
| PTW | 131 | 0.6% |
| SEW | 63 | 0.3% |
| CFW | 6 | <0.1% |
| KVCW | 2 | <0.1% |

In other words: the vast majority of real-world issues are **basic hygiene** (unpinned dependencies and missing runner hardening), while the highest-impact flaws (injection, exposed secrets, privileged triggers) are far rarer but dramatically more dangerous when they do show up, which is why each lesson lists severity alongside frequency.

## Disclaimer

All the material in this folder is **educational**. The `vulnerable.yml` workflows are synthetic examples (they don't belong to any real repository) meant to illustrate the pattern; the `simulate.py` scripts don't run anything against real GitHub or real external services: everything happens locally, either in the Python process itself or in the lesson's isolated Docker container. The one exception is optional: `simulate.py --online` in lesson 12 asks GitHub (`git ls-remote`, read-only) which commit each version points to.
