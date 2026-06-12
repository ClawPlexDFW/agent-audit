<div align="center">

# agent-audit

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![No deps](https://img.shields.io/badge/dependencies-0-success.svg)](requirements.txt)
[![Privacy: local-only](https://img.shields.io/badge/privacy-100%25_local--only-blueviolet.svg)]()

**A read-only structural audit tool for AI agent installs (Hermes-compatible).**

Produces a structured findings list (JSON), a self-contained HTML report, a
markdown summary, and a side-by-side before/after diff page — all generated
locally. No network. No telemetry. No dependencies.

[About](#about-the-project) ·
[Getting Started](#getting-started) ·
[Usage](#usage) ·
[Roadmap](#roadmap) ·
[Contributing](#contributing) ·
[License](#license)

</div>

---

## About The Project

AI agent installs grow. Skills get added, configs drift, secrets get logged,
state DBs balloon, prompt-injection attempts land in config files, and the
agent loop becomes a god-file. Most agent operators discover these problems
during an incident.

`agent-audit` is a senior-engineer-grade structural audit you can run on
demand, against your own install, in under a minute. It produces:

* **A health score** (0-100) computed from severity-weighted findings
* **A findings list** with severity, area, category, evidence, location, and
  remediation guidance for every issue
* **A self-contained HTML report** (dark theme, no external assets) that you
  can attach to a PR or share with a team
* **A before/after diff page** so you can show the impact of fixes

The tool is intentionally **not** a security scanner. It's a *structural
hygiene* tool. It tells you where to look. It does not run an LLM to judge
content.

### What it checks

| Area       | What it looks for                                                                              |
|------------|------------------------------------------------------------------------------------------------|
| **core**   | God-files (>5K lines), exception handling patterns, retry/backoff, prompt-cache discipline      |
| **tools**  | Tool count, secret-accepting tool schemas, registry size                                        |
| **skills** | Skill count, missing frontmatter, stub skills                                                  |
| **state**  | state.db size, session count, retention hygiene                                                |
| **logs**   | Log file sizes, secret redaction, growth rate                                                  |
| **config** | Missing sections, empty fallback lists, runaway `max_turns`                                     |
| **security** | Prompt-injection signatures (with FP-classification), `.env` perms, `config.yaml` perms       |

### Built With

* Python 3.10+ standard library only — `argparse`, `dataclasses`, `html`,
  `json`, `os`, `pathlib`, `re`, `sqlite3`, `sys`, `typing`
* No external packages, no telemetry, no network calls

### Screenshots

<table>
<tr>
<td width="50%">

**Audit report (light/dark theme, severity color-coded)**

`example-anonymized-report.html` — produced by running
`audit_framework.py --self --anonymize`

</td>
<td width="50%">

**Before/After diff page**

`example-before-after.html` — produced by running
`build_before_after.py --before ... --after ...`

</td>
</tr>
</table>

---

## Getting Started

### Prerequisites

* Python 3.10 or newer
* An AI agent install to audit. The tool is tuned for the
  [Hermes Agent](https://github.com/...) file layout
  (`~/.hermes/config.yaml`, `~/.hermes/skills/`, etc.) but is
  trivially adaptable to other layouts by editing the
  `check_*` functions in `audit_framework.py`.

### Installation

```bash
git clone https://github.com/your_username/agent-audit.git
cd agent-audit

# No install step. No requirements. Pure stdlib.
python3 audit_framework.py --help
```

---

## Usage

### Audit the local `~/.hermes` install

```bash
python3 audit_framework.py --self --output ./report
```

This produces:

```
./report/
├── audit_report.html         # Self-contained HTML report
├── audit_findings.json       # Machine-readable findings
└── AUDIT_SUMMARY.md          # Markdown summary (for PRs)
```

### Audit a custom path

```bash
python3 audit_framework.py --target /path/to/install --output ./report
```

### Anonymized output (for sharing in PRs / public channels)

```bash
python3 audit_framework.py --self --output ./public --anonymize
```

Strips `/home/<user>/` and `/Users/<user>/` from all locations. Does NOT
auto-redact API keys or other content — strip those yourself before
sharing.

### Track remediation over time

```bash
# First run — produces baseline
python3 audit_framework.py --self --output ./before

# Edit ./fixes.json to mark findings as resolved, applied, etc.
# Then re-run with --fix-track:
python3 audit_framework.py --self --output ./after --fix-track ./fixes.json
```

`fixes.json` format:

```json
{
  "fixes": [
    {"id": "CFG-001", "status": "resolved", "resolved_at": "2026-01-01T00:00:00Z", "notes": "..."},
    {"id": "STATE-001", "status": "partially_resolved", "notes": "..."}
  ]
}
```

Valid `status` values: `open` (default), `in_progress`, `resolved`,
`partially_resolved`, `applied`, `wontfix`, `deferred`, `noted`,
`pending_approval`.

### Build a before/after diff page

```bash
python3 build_before_after.py \
    --before ./before/audit_findings.json \
    --after  ./after/audit_findings.json \
    --output ./before-after.html
```

Renders a single-page diff with health-score delta, severity delta, and
per-finding resolution status.

### Health score

```
100 − 10·CRITICAL − 5·HIGH − 2·MEDIUM − 0.5·LOW
```

* `resolved`, `applied`, `wontfix` findings are excluded from the score
* `partially_resolved` findings are half-credit
* Floored at 0

---

## Roadmap

* [x] Core audit checks (core, tools, skills, state, logs, config, security)
* [x] HTML report with dark theme
* [x] Anonymized output
* [x] Fix tracking + before/after diff
* [ ] Pluggable check system (drop-in `checks/*.py` modules)
* [ ] Adapter for LangGraph / CrewAI / AutoGen / OpenAI Agents SDK layouts
* [ ] Auto-redaction of known secret patterns (sk-, sk-ant-, gho_, etc.)
* [ ] JSON Schema for findings + JSON-Schema validation in CI
* [ ] GitHub Actions workflow: audit-on-PR, comment with findings

See the [open issues](https://github.com/your_username/agent-audit/issues)
for the full list of proposed features (and known issues).

---

## Contributing

Contributions are what make the open source community such an amazing place
to learn, inspire, and create. Any contributions you make are **greatly
appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

**Before opening a PR:**

* Run the tool against your own install — paste the diff in the PR
  description
* If you're adding a new check, follow the `check_*` pattern in
  `audit_framework.py` and add a finding in the same shape as the existing
  ones
* If you're touching the HTML/CSS, screenshot before/after

---

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more
information.

---

## Contact

Tyler Delano — [@tylerdotai](https://github.com/tylerdotai)

Project Link:
[https://github.com/tylerdotai/agent-audit](https://github.com/tylerdotai/agent-audit)

---

## Acknowledgments

* [Best-README-Template](https://github.com/othneildrew/Best-README-Template)
  by [othneildrew](https://github.com/othneildrew) — README structure
* [Shields.io](https://shields.io) — badge assets
* The Hermes Agent project for shipping a structurally-auditable install
  layout

<div align="right">

[Back to top ⬆️](#agent-audit)

</div>
