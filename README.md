# Zenith Engine 🔍

Static security analysis tool for GitHub Actions workflows.

Upload a `.yml` or `.yaml` file and get an immediate analysis of its vulnerabilities, classified according to the **OWASP CI/CD Security Risks TOP 10**.

---

## What does it detect?

Zenith Engine applies 26 custom detection rules organized into 8 categories:

| Category | Examples of what it detects |
|-----------|---------------------------|
| Triggers | Dangerous `pull_request_target`, TOCTOU pattern, expression injection, always-true `if` condition |
| Permissions | Missing `permissions` block, third-party actions with token access |
| Actions | Mutable tags, use of `@latest`, branches used as versions, unverified actions, outdated runtime (Node 12/16) |
| Credentials | Hardcoded tokens, secrets exposed in logs |
| Network | Direct IP calls, DNS exfiltration, exfiltration via the GitHub API |
| Runners | Self-hosted without hardening, unconfigured EC2 instances, unknown runner label |
| Artifacts | Publishing Docker images without integrity verification |
| Vulnerabilities | Actions pinned to a version with a known public CVE/GHSA |

For each vulnerability detected, it shows:
- Severity level: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`
- Matching OWASP CI/CD category
- The exact line number in the file
- A concrete suggestion for fixing it

---

## Language

The web UI and alert text are available in **Spanish** and **English**. The ES/EN switcher is in the header of every page; the preference is stored in a session cookie and can be forced with `?lang=es` or `?lang=en` in the URL.

All i18n logic lives in `engine/i18n/`:

```
engine/i18n/
├── __init__.py   # translation engine: translate(lang, key, **params)
├── es.json       # Spanish catalog
└── en.json       # English catalog
```

Each rule (`engine/rules/*.py`) contains no literal text: it calls `create_alert(rule_id='R1000', ..., lang=lang, **params)`, and `create_alert` resolves `R1000.rule` / `R1000.description` / `R1000.suggestion` against the active language's catalog, interpolating the named parameters (`uses`, `job_name`, `key`, etc.) with `str.format`.

**To add a new language** (e.g. French):
1. Copy `engine/i18n/en.json` to `engine/i18n/fr.json` and translate every value (the `{param}` placeholders must stay unchanged).
2. Add `'fr'` to `SUPPORTED_LANGUAGES` in `engine/i18n/__init__.py`.
3. Add the matching `ui.*` keys to `fr.json` too (web UI text: buttons, headings, etc.).

No rule or HTML template needs to change — everything is resolved by key at runtime.

---

## Rule → common weakness mapping

To compare Zenith Engine against other workflow scanners (actionlint, poutine, zizmor, scorecard, semgrep, frizbee, pinny, scharf, ggshield), it uses the **10 common weaknesses** taxonomy proposed in *"Unpacking Security Scanners for GitHub Actions Workflows"* (Fares, Gamage & Baudry). Each Zenith Engine rule maps to its corresponding weakness:

| Rule | Description | Common weakness | CWE |
|---|---|---|---|
| R1000 | `pull_request_target` trigger detected | PTW – Privileged Trigger Weakness | CWE-862 |
| R1001 | Checkout of the PR head in a `pull_request_target` context | PTW – Privileged Trigger Weakness | CWE-862 |
| R1002 | Action without a pinned hash | UDW – Unpinned Dependency Weakness | CWE-829 |
| R1003 | No permissions defined | EPW – Excessive Permission Weakness | CWE-250 / CWE-732 |
| R1004 | Egress policy in audit mode / harden-runner missing | HGW – Hardening Gap Weakness | CWE-223 |
| R1005 | Outbound call to a suspicious domain | *(outside the taxonomy — Zenith-specific)* | — |
| R1006 | Self-hosted runner detected | *(outside the taxonomy — Zenith-specific)* | — |
| R1007 | Unverified third-party action | AIW – Artifact Integrity Weakness | CWE-353 / CWE-494 |
| R1008 | Action not found in the Marketplace | AIW – Artifact Integrity Weakness | CWE-353 / CWE-494 |
| R1009 | Outbound call to a raw IP address | *(outside the taxonomy — Zenith-specific)* | — |
| R1010 | No artifact integrity verification | AIW – Artifact Integrity Weakness | CWE-353 / CWE-494 |
| R1011 | Third-party action with access to `GITHUB_TOKEN` | EPW – Excessive Permission Weakness | CWE-250 / CWE-732 |
| R1012 | A branch is used as the action version | UDW – Unpinned Dependency Weakness | CWE-829 |
| R1013 | `pull_request` trigger without branch restrictions | *(outside the taxonomy — Zenith-specific)* | — |
| R1014 | Hardcoded credential or token | SEW – Secrets Exposure Weakness | CWE-200 / CWE-522 |
| R1015 | Possible data exfiltration via DNS | *(outside the taxonomy — Zenith-specific)* | — |
| R1016 | Expression injection in a `run` command | IW – Injection Weakness | CWE-20 / CWE-94 |
| R1017 | Use of `@latest` on a third-party action | UDW – Unpinned Dependency Weakness | CWE-829 |
| R1018 | Possible exfiltration via the GitHub API | *(outside the taxonomy — Zenith-specific)* | — |
| R1019 | Secret exposed in pipeline logs | SEW – Secrets Exposure Weakness | CWE-200 / CWE-522 |
| R1020 | Self-hosted runner on a cloud instance without hardening | HGW – Hardening Gap Weakness | CWE-223 |
| R1021 | TOCTOU pattern detected | PTW – Privileged Trigger Weakness | CWE-862 |
| R1022 | `if` condition always evaluates to true | CFW – Control Flow Weakness | CWE-571 |
| R1023 | Action with an outdated runtime incompatible with current runners | GRCW – GitHub Runner Compatibility Weakness | CWE-477 / CWE-440 |
| R1024 | Unknown or unsupported runner label | GRCW – GitHub Runner Compatibility Weakness | CWE-477 / CWE-440 |
| R1025 | Component with a known vulnerability | KVCW – Known Vulnerable Component Weakness | CWE-1395 |

Rules R1005, R1006, R1009, R1013, R1015, and R1018 are Zenith Engine-specific (network exfiltration and trigger attack-surface detection) and have no equivalent among the paper's 10 common weaknesses.
---

## Installation

Clone the repository and install the dependencies:

```bash
git clone https://github.com/isaaclo97/ZenithEngine
cd ZenithEngine
pip install -r requirements.txt
```

---

## Usage

Launch the application:

```bash
python3 app.py
```

Open your browser at `http://127.0.0.1:5000`, upload your `.yml` file, and get the analysis.

---

## Project structure

```
zenith-engine/
├── app.py                          # Flask entry point
├── requirements.txt
├── engine/
│   ├── parser.py                   # YAML parser
│   ├── engine.py                   # Rule orchestrator (analyze_workflow)
│   ├── create_alert.py             # Alert builder (i18n-aware)
│   ├── i18n/
│   │   ├── __init__.py             # translate(lang, key, **params)
│   │   ├── es.json                 # Spanish catalog
│   │   └── en.json                 # English catalog
│   ├── fraudulent_domains.txt
│   ├── verified_organizations.txt
│   ├── outdated_runtime_actions.txt   # data for R1023
│   ├── known_vulnerabilities.json     # local fallback for R1025
│   └── rules/
│       ├── triggers.py             # R1000, R1001, R1013, R1016, R1021, R1022
│       ├── permissions.py          # R1003, R1011
│       ├── actions.py              # R1002, R1007, R1008, R1012, R1017, R1023
│       ├── credentials.py          # R1014, R1019
│       ├── network.py              # R1004, R1005, R1009, R1015, R1018
│       ├── runners.py              # R1006, R1020, R1024
│       ├── artifacts.py            # R1010
│       └── vulnerabilities.py      # R1025
├── templates/
│   ├── index.html
│   └── results.html
└── static/
    └── style.css
```

---

## Technologies

- Python 3
- Flask
- PyYAML

---

## Academic context

This tool was originally developed as a Bachelor's Thesis (Trabajo de Fin de Grado, TFG) at **Universidad Loyola** by Pablo Romero Toro, supervised by Jordi García Quintanilla and Isaac Lozano Osorio.

Original repository: [github.com/RomeroPablo02/TFG-Cloud-](https://github.com/RomeroPablo02/TFG-Cloud-)
