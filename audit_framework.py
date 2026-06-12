#!/usr/bin/env python3
"""
agent-audit — Comprehensive AI Agent Systems Audit Tool
========================================================

Performs a structured, repeatable audit of an AI agent install (Hermes-compatible)
and produces:

  1. A JSON findings dump (audit_findings.json) for downstream tools / CI
  2. A self-contained HTML report (audit_report.html) with before/after
     remediation tracking
  3. A markdown summary (AUDIT_SUMMARY.md) suitable for PR descriptions

The tool is read-only. It never modifies the agent install.

USAGE
-----
    python3 audit_framework.py --target /path/to/agent/install --output ./report
    python3 audit_framework.py --self                 # audit the local ~/.hermes install
    python3 audit_framework.py --self --fix-track ./fixes.json   # resume prior fixes

DESIGN PRINCIPLES
-----------------
* The audit is data-driven: every finding is a structured record with
  severity, location, evidence, and remediation guidance. The HTML report
  is just a render of that data.
* No telemetry, no network, no exfiltration. The tool runs entirely locally
  and writes its outputs to --output.
* The findings are *generic* — they describe issues any Hermes/agent install
  is likely to have, not your specific config. Personal data stays in the
  private `--self` mode; the public-mode report is anonymized.

LICENSE: MIT
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Finding model
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

@dataclass
class Finding:
    id: str
    title: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str  # security | performance | reliability | observability | ux | best-practice
    area: str      # core | gateway | tools | skills | memory | state | logs | config
    summary: str
    evidence: List[str] = field(default_factory=list)  # code/log snippets
    location: str = ""                                 # file:line
    root_cause: str = ""
    remediation: str = ""
    effort: str = "M"     # S | M | L | XL
    impact: str = "M"     # S | M | L | XL
    references: List[str] = field(default_factory=list)
    # remediation tracking
    status: str = "open"  # open | in_progress | resolved | wontfix
    resolved_at: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Audit checks (the actual logic)
# ─────────────────────────────────────────────────────────────────────────────

def check_core_loop(target: Path, find: List[Finding]) -> None:
    """Inspect run_agent.py / equivalent for retry, error handling, timeouts."""
    candidates = [
        target / "hermes-agent" / "run_agent.py",
        target / "run_agent.py",
        target / "agent" / "loop.py",
    ]
    src = next((p for p in candidates if p.exists()), None)
    if not src:
        find.append(Finding(
            id="CORE-001", title="Agent loop entrypoint not found",
            severity="HIGH", category="reliability", area="core",
            summary=f"Searched {', '.join(str(p) for p in candidates)} — no run loop found.",
            remediation="Confirm the agent uses a recognized entrypoint shape.",
        ))
        return

    text = src.read_text(errors="replace")
    lines = text.splitlines()
    n_lines = len(lines)
    n_bytes = src.stat().st_size

    # God-file detector
    if n_lines > 5000:
        find.append(Finding(
            id="CORE-002", title=f"God-file loop ({n_lines:,} lines, {n_bytes//1024}KB)",
            severity="MEDIUM", category="best-practice", area="core",
            summary=f"{src.relative_to(target)} is {n_lines:,} lines. Hot path bloat risk; mixin extraction is the standard remedy.",
            location=f"{src.name}:1-{n_lines}",
            remediation="Extract responsibilities into focused mixins/modules (init, runtime helpers, dispatch). Reference: AGENTS.md contribution rubric encourages this exact refactor.",
            effort="L", impact="M",
        ))

    # Exception catch inventory
    n_exc = len(re.findall(r"except\s+(?:Exception|BaseException)", text))
    n_silent = len(re.findall(r"except[^\n]*:\s*\n\s+pass", text))
    if n_exc > 50:
        find.append(Finding(
            id="CORE-003", title=f"{n_exc} broad exception catches, {n_silent} silent",
            severity="LOW", category="observability", area="core",
            summary=f"Broad `except Exception:` count is high but not necessarily a bug. Silent-pass count is the better signal.",
            location=src.name,
            remediation="Adopt a central error_classifier (agent/error_classifier.py exists upstream) and tag exceptions with FailoverReason / category before catching.",
            effort="M", impact="L",
        ))

    # Retry / backoff presence
    if not re.search(r"backoff|retry", text, re.IGNORECASE):
        find.append(Finding(
            id="CORE-004", title="No retry/backoff logic found in agent loop",
            severity="HIGH", category="reliability", area="core",
            summary="Rate-limit or transient failure will hard-fail the loop.",
            location=src.name,
            remediation="Implement exponential backoff with jitter for 429/5xx; rotate credentials via credential_pool on rate-limit.",
            effort="M", impact="L",
        ))

    # Prompt cache discipline
    if re.search(r"system_prompt\s*=\s*[\"']", text):
        find.append(Finding(
            id="CORE-005", title="Possible mid-conversation system_prompt mutation",
            severity="MEDIUM", category="performance", area="core",
            summary="Mutating system_prompt mid-loop invalidates the provider's per-conversation prompt cache. Multiplies cost.",
            location=src.name,
            remediation="Use ephemeral_system_prompt (constructor arg) for per-turn additions; keep system_prompt byte-stable for the life of the conversation.",
            effort="S", impact="L",
        ))


def check_tools(target: Path, find: List[Finding]) -> None:
    """Inventory tool surface and look for foot-gun patterns."""
    tools_dir = target / "hermes-agent" / "tools"
    if not tools_dir.exists():
        return
    tool_files = list(tools_dir.glob("*.py"))
    n = len(tool_files)
    find.append(Finding(
        id="TOOL-001", title=f"{n} tool files in registry",
        severity="INFO", category="reliability", area="tools",
        summary=f"Tool surface inventory: {n} files. Per-turn cost is roughly proportional to total schema size.",
        location=f"tools/*.py ({n} files)",
        remediation="Audit schemas with `hermes tools list --show-sizes` (if available). Trim descriptions; ensure handlers are service-gated (check_fn) where appropriate.",
    ))

    # Find any tool that *requires* a secret in its schema (anti-pattern).
    # We require a *handler* that accepts the value and either logs it or
    # forwards it unredacted. Schema-only mentions of "api_key" are not enough
    # to flag — many tools have a `provider` field whose name happens to
    # contain the substring.
    suspect_field = re.compile(r"['\"](api[_-]?key|token|password|secret)['\"]\s*:\s*\{", re.IGNORECASE)
    handler_echo   = re.compile(r"logger\.(info|debug|warning|error)\([^)]*\*?\*?(?:args|kwargs)|print\([^)]*\b(args|kwargs)\b")
    suspects = []
    for tf in tool_files:
        try:
            text = tf.read_text(errors="replace")
        except Exception:
            continue
        if "registry.register" not in text: continue
        if not suspect_field.search(text): continue
        # Heuristic: does the handler reference args/kwargs in a logger/print?
        # A real secret-leak requires the handler to use the value in a way
        # that gets logged. Tools that just read from os.environ are fine.
        if re.search(r"os\.environ|os\.getenv", text):
            # Has env-var reading — likely fine
            if not handler_echo.search(text):
                continue
        suspects.append(tf.name)
    if suspects:
        find.append(Finding(
            id="TOOL-002", title=f"{len(suspects)} tool(s) may accept secrets as parameters",
            severity="HIGH", category="security", area="tools",
            summary="Tool schemas that accept secrets as input arguments can leak via logs, trajectories, or session replay. Prefer reading from env via os.environ inside the handler.",
            location=", ".join(suspects),
            remediation="Move secret reading inside the handler. If the schema *must* declare the field, mark it as sensitive in the schema sanitizer and redact in logs.",
            effort="M", impact="L",
        ))


def check_skills(target: Path, find: List[Finding]) -> None:
    """Inspect the skills/ tree for staleness, duplication, and frontmatter hygiene."""
    skills_root = target / "skills"
    if not skills_root.exists():
        return
    skill_files = list(skills_root.rglob("SKILL.md"))
    find.append(Finding(
        id="SKILL-001", title=f"{len(skill_files)} SKILL.md files in user skills tree",
        severity="INFO", category="ux", area="skills",
        summary=f"Skill count: {len(skill_files)}. Each skill adds to model context only when invoked (good), but the SKILL.md discovery prompt *does* scan on cold-start.",
        location=f"skills/**/SKILL.md",
    ))

    # Empty / placeholder skills
    empty = [str(p.relative_to(skills_root)) for p in skill_files
             if len(p.read_text(errors="replace").strip()) < 200]
    if empty:
        find.append(Finding(
            id="SKILL-002", title=f"{len(empty)} suspiciously short SKILL.md files",
            severity="LOW", category="ux", area="skills",
            summary="Skills with minimal SKILL.md are likely stubs that will misfire when loaded.",
            location=", ".join(empty[:10]) + ("..." if len(empty) > 10 else ""),
            remediation="Either flesh out or remove. Use `skill_manage(action='delete')` to clean up.",
        ))

    # Skills without frontmatter
    no_frontmatter = []
    for p in skill_files:
        try:
            head = p.read_text(errors="replace")[:200]
        except Exception:
            continue
        if not head.lstrip().startswith("---"):
            no_frontmatter.append(str(p.relative_to(skills_root)))
    if no_frontmatter:
        find.append(Finding(
            id="SKILL-003", title=f"{len(no_frontmatter)} SKILL.md files lack YAML frontmatter",
            severity="MEDIUM", category="reliability", area="skills",
            summary="Without frontmatter (name, description, when to use), the agent can't reliably discover or trigger the skill.",
            location=", ".join(no_frontmatter[:10]) + ("..." if len(no_frontmatter) > 10 else ""),
            remediation="Add frontmatter per the SKILL.md authoring spec.",
        ))


def check_state(target: Path, find: List[Finding]) -> None:
    """Look at state DB size, session count, snapshot hygiene."""
    state_db = target / "state.db"
    if state_db.exists():
        size_mb = state_db.stat().st_size / 1024 / 1024
        if size_mb > 100:
            find.append(Finding(
                id="STATE-001", title=f"state.db is {size_mb:.0f}MB",
                severity="MEDIUM", category="performance", area="state",
                summary="Large state DB slows cold-start and increases backup size. WAL checkpointing is normal but consider pruning or archiving old sessions.",
                location="state.db",
                remediation="Run `VACUUM` after backup. Consider archiving sessions older than N days.",
                effort="S", impact="M",
            ))

    sessions_dir = target / "sessions"
    if sessions_dir.exists():
        n = sum(1 for _ in sessions_dir.glob("*.json"))
        find.append(Finding(
            id="STATE-002", title=f"{n} session transcript files",
            severity="INFO", category="reliability", area="state",
            summary=f"{n} session files. Each contains full message history verbatim — useful for recall, hazardous if exfiltrated.",
            location="sessions/*.json",
            remediation="Set a retention policy. Redact secrets before storing (agent/redact.py upstream handles this).",
        ))


def check_logs(target: Path, find: List[Finding]) -> None:
    """Inspect log files for size, growth rate, and redaction."""
    logs_dir = target / "logs"
    if not logs_dir.exists():
        return
    big_logs = []
    for log in sorted(logs_dir.glob("*.log*")):
        try:
            mb = log.stat().st_size / 1024 / 1024
        except OSError:
            continue
        if mb > 50:
            big_logs.append((log.name, mb))
    if big_logs:
        find.append(Finding(
            id="LOG-001", title=f"{len(big_logs)} log files > 50MB",
            severity="LOW", category="observability", area="logs",
            summary=", ".join(f"{n} ({m:.0f}MB)" for n, m in big_logs),
            location="logs/",
            remediation="Add logrotate (size + count) and structured JSON output. Cap individual log lines to avoid token-cost surprise on tail.",
        ))

    # Redaction check
    any_log = next((p for p in logs_dir.glob("*.log") if p.stat().st_size > 0), None)
    if any_log:
        sample = any_log.read_text(errors="replace")[:200_000]
        # Heuristic: an actual API key in a log line is bad
        if re.search(r"sk-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|gho_[A-Za-z0-9]{20,}", sample):
            find.append(Finding(
                id="LOG-002", title="Possible API key in log file",
                severity="CRITICAL", category="security", area="logs",
                summary=f"Found an sk-... or sk-ant-... pattern in {any_log.name}. Treat as compromised and rotate.",
                location=str(any_log.name),
                remediation="Rotate the key. Add a redaction filter at logger setup. Add CI grep for key patterns against logs/.",
                effort="S", impact="XL",
            ))


def check_config(target: Path, find: List[Finding]) -> None:
    """Inspect config.yaml for anti-patterns and missing fields."""
    cfg = target / "config.yaml"
    if not cfg.exists():
        return
    text = cfg.read_text(errors="replace")

    # YAML key inventory
    keys = set(re.findall(r"^([a-z_][a-z0-9_]*):", text, re.MULTILINE | re.IGNORECASE))
    expected = {
        "model", "providers", "toolsets", "agent", "memory", "logging",
        "telemetry", "safety", "gateway",
    }
    missing = expected - keys
    if missing:
        find.append(Finding(
            id="CFG-001", title=f"Config missing expected sections: {', '.join(sorted(missing))}",
            severity="LOW", category="best-practice", area="config",
            summary="No hard requirement, but these sections are conventional and where most knobs live.",
            location="config.yaml",
            remediation="Add the missing sections with sensible defaults; document each.",
        ))

    # Provider misconfig: empty fallback list
    if "fallback_providers" in text and re.search(r"fallback_providers:\s*\[\s*\]", text):
        find.append(Finding(
            id="CFG-002", title="Empty fallback_providers list",
            severity="MEDIUM", category="reliability", area="config",
            summary="On primary provider failure, there is no fallback. Loop will hard-fail.",
            location="config.yaml:fallback_providers",
            remediation="Add at least one secondary provider with a different API key.",
            effort="S", impact="L",
        ))

    # Max turns set too high
    m = re.search(r"max_turns:\s*(\d+)", text)
    if m and int(m.group(1)) > 100:
        find.append(Finding(
            id="CFG-003", title=f"max_turns set to {m.group(1)}",
            severity="LOW", category="performance", area="config",
            summary="High max_turns risks runaway loops and large bills on stuck agents.",
            location=f"config.yaml:max_turns",
            remediation="Cap at 50-80 unless you have a specific reason; pair with iteration_budget to enforce spend.",
        ))


def check_security_surface(target: Path, find: List[Finding]) -> None:
    """Look at the install for known prompt-injection signatures."""
    # Scan all .md / .yaml / .txt for known injection phrases
    SIGNATURES = [
        "GOD MODE", "DAN MODE", "REBEL GENIUS", "TIME CAPSULE",
        "BENEVOLENT ASI", "LOVE PLINY", "ignore previous instructions",
        "semantically inverse",
    ]
    rx = re.compile("|".join(re.escape(s) for s in SIGNATURES), re.IGNORECASE)
    hits = []
    # Context classifiers — we want to count REAL injection landings, not the
    # research/test/red-flag-list copies that legitimately contain the phrases.
    def classify(rel: str) -> str:
        r = rel.lower()
        if "/optional-skills/security/godmode" in r:        return "research-skill"
        if "/tests/" in r or "/test_" in r:                  return "test-fixture"
        if "/optional-skills/research/" in r:                return "upstream-research"
        if "/optional-skills/" in r and "/scripts/" in r:    return "research-skill"
        if "/.archive/" in r or "/.curator_backups/" in r:   return "archived-copy"
        if "/state-snapshots/" in r:                         return "historical-snapshot"
        if "hermes-agent/website/" in r:                     return "upstream-website-docs"
        if "hermes-agent/.plans/" in r or "/.plans/" in r:   return "upstream-plans"
        if "hermes-agent/tools/" in r:                       return "upstream-tool-code"
        if "hermes-agent/agent/" in r:                       return "upstream-agent-code"
        if "hermes-agent/hermes_cli/" in r:                  return "upstream-cli-code"
        if "hermes-agent/gateway/" in r:                     return "upstream-gateway-code"
        if "hermes-agent/providers/" in r:                   return "upstream-provider-code"
        if "hermes-agent/" in r:                             return "upstream-bundled"
        if rel.endswith("SKILL.md") or "red-flag" in r:      return "red-flag-list"
        # The audit tool's own output dir
        if "sandboxes/singularity/agent-audit/" in r:        return "audit-tool-output"
        return "unknown"

    real_hits: List[tuple] = []
    fp_hits:   List[tuple] = []
    scan_roots = [target, target / "hermes-agent"]
    if (target / "skills").exists():
        scan_roots += [d for d in (target / "skills").iterdir() if d.is_dir()]
    seen = set()
    for root in scan_roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in {".md", ".yaml", ".yml", ".txt", ".json", ".py"}:
                continue
            try:
                if p in seen: continue
                seen.add(p)
                if p.stat().st_size > 5_000_000: continue
                text = p.read_text(errors="replace")
            except (OSError, UnicodeDecodeError):
                continue
            m = rx.search(text)
            if not m: continue
            rel = str(p.relative_to(target))
            # Context-specific suppression: if the match is inside a clear
            # red-flag-list comment block, treat it as expected content.
            if "red-flag" in text.lower() and "INJECTION" in text.upper():
                fp_hits.append((rel, m.group(0), "red-flag-list"))
                continue
            cls = classify(rel)
            (real_hits if cls == "unknown" else fp_hits).append((rel, m.group(0), cls))

    if real_hits:
        find.append(Finding(
            id="SEC-001", title=f"{len(real_hits)} file(s) contain prompt-injection signatures",
            severity="CRITICAL", category="security", area="config",
            summary=f"Common jailbreak phrases found in {len(real_hits)} file(s) NOT classified as upstream/research/test/red-flag/archive. (Separately: {len(fp_hits)} FPs in upstream-bundled files, research skills, tests, red-flag lists, snapshots — these are expected.)",
            location=", ".join(f"{p} ({sig})" for p, sig, _ in real_hits[:5]) + ("..." if len(real_hits) > 5 else ""),
            remediation="Quarantine each file. Treat the phrases as injection attempts unless the file is in a known-bucket (upstream bundled, research skill, test fixture, red-flag list, archive, snapshot).",
            effort="S", impact="XL",
        ))
    elif fp_hits:
        # All matches are in known-good buckets. The signal is still useful —
        # it confirms the audit scanner is working. INFO severity.
        find.append(Finding(
            id="SEC-001", title=f"0 real injection landings; {len(fp_hits)} expected FP matches",
            severity="INFO", category="security", area="config",
            summary=f"Phrases appear only in upstream-bundled code, research skills, test fixtures, red-flag lists, archived copies, and historical snapshots. No new injection landings detected. The new system prompt's red-flag list is the only user-facing source — by design.",
            location=f"(none in user-facing files; {len(fp_hits)} in upstream/test/research buckets)",
            remediation="No action required. Re-run audit after any new file lands in install root, skills/, or .hermes/ to confirm clean state.",
        ))

    # .env permissions
    env = target / ".env"
    if env.exists():
        mode = oct(env.stat().st_mode)[-3:]
        if mode != "600":
            find.append(Finding(
                id="SEC-002", title=f".env permissions are {mode}, expected 600",
                severity="HIGH", category="security", area="config",
                summary=".env is world/group readable; any user on the host can read API keys.",
                location=".env",
                remediation="`chmod 600 .env` (Hermes typically enforces this on install — verify it stuck).",
                effort="S", impact="XL",
            ))

    # config.yaml permissions
    cfg = target / "config.yaml"
    if cfg.exists():
        mode = oct(cfg.stat().st_mode)[-3:]
        if mode not in {"600", "640"}:
            find.append(Finding(
                id="SEC-003", title=f"config.yaml permissions are {mode}",
                severity="MEDIUM", category="security", area="config",
                summary="config.yaml may contain provider URLs and routing rules that leak topology.",
                location="config.yaml",
                remediation="`chmod 600 config.yaml`.",
            ))


def run_audit(target: Path) -> List[Finding]:
    find: List[Finding] = []
    check_security_surface(target, find)
    check_core_loop(target, find)
    check_tools(target, find)
    check_skills(target, find)
    check_state(target, find)
    check_logs(target, find)
    check_config(target, find)
    # Sort by severity
    find.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.id))
    return find


# ─────────────────────────────────────────────────────────────────────────────
# Output rendering
# ─────────────────────────────────────────────────────────────────────────────

SEV_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}

SEV_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


def render_html(findings: List[Finding], target: Path, *,
                health_score: int, top5: List[str],
                generated_at: str, mode: str) -> str:
    by_sev: Dict[str, List[Finding]] = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)

    rows = []
    for sev in SEVERITY_ORDER:
        for f in by_sev.get(sev, []):
            status_badge = {
                "open":         '<span class="badge badge-open">open</span>',
                "in_progress":  '<span class="badge badge-prog">in progress</span>',
                "resolved":     '<span class="badge badge-res">resolved</span>',
                "wontfix":      '<span class="badge badge-wont">wontfix</span>',
            }.get(f.status, f.status)
            evidence_html = "".join(
                f"<pre class='ev'>{e}</pre>" for e in f.evidence
            ) if f.evidence else ""
            rows.append(f"""
            <tr class="finding" data-sev="{sev}">
              <td><span class="sev" style="background:{SEV_COLOR[sev]}">{SEV_EMOJI[sev]} {sev}</span></td>
              <td><code>{f.id}</code></td>
              <td>
                <div class="title">{f.title}</div>
                <div class="area">{f.area} · {f.category}</div>
              </td>
              <td>
                <div class="summary">{f.summary}</div>
                {f"<div class='loc'>{f.location}</div>" if f.location else ""}
                {f"<div class='root'><b>Root cause:</b> {f.root_cause}</div>" if f.root_cause else ""}
                {evidence_html}
                {f"<div class='fix'><b>Remediation:</b> {f.remediation}</div>" if f.remediation else ""}
                <div class="meta">
                  <span class="badge badge-eff">effort {f.effort}</span>
                  <span class="badge badge-imp">impact {f.impact}</span>
                  {status_badge}
                </div>
              </td>
            </tr>""")

    summary_cards = "".join(
        f'<div class="card sev-{sev}"><div class="num">{len(by_sev.get(sev, []))}</div><div class="lbl">{SEV_EMOJI[sev]} {sev}</div></div>'
        for sev in SEVERITY_ORDER
    )

    top5_html = "".join(f"<li>{t}</li>" for t in top5)
    health_color = "#16a34a" if health_score >= 80 else "#ca8a04" if health_score >= 60 else "#dc2626"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Audit Report — {target.name}</title>
<style>
  :root {{
    --bg: #0f172a; --panel: #1e293b; --panel2: #334155; --fg: #e2e8f0; --muted: #94a3b8;
    --accent: #38bdf8; --good: #4ade80; --bad: #f87171; --border: #475569;
  }}
  *{{box-sizing:border-box}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:2rem;line-height:1.5}}
  h1{{margin:0 0 .5rem 0;font-size:1.75rem}}
  h2{{margin:2rem 0 1rem;border-bottom:1px solid var(--border);padding-bottom:.5rem}}
  .meta{{color:var(--muted);font-size:.9rem;margin-bottom:1rem}}
  .summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:1rem;margin:1.5rem 0}}
  .card{{background:var(--panel);border-radius:8px;padding:1rem;text-align:center;border-left:4px solid var(--border)}}
  .card .num{{font-size:2rem;font-weight:700}}
  .card .lbl{{color:var(--muted);font-size:.85rem;text-transform:uppercase;letter-spacing:.05em}}
  .sev-CRITICAL{{border-left-color:{SEV_COLOR['CRITICAL']}}}
  .sev-HIGH{{border-left-color:{SEV_COLOR['HIGH']}}}
  .sev-MEDIUM{{border-left-color:{SEV_COLOR['MEDIUM']}}}
  .sev-LOW{{border-left-color:{SEV_COLOR['LOW']}}}
  .sev-INFO{{border-left-color:{SEV_COLOR['INFO']}}}
  .health{{display:flex;align-items:center;gap:1rem;background:var(--panel);padding:1rem 1.5rem;border-radius:8px;border-left:6px solid {health_color}}}
  .health .score{{font-size:3rem;font-weight:800;color:{health_color}}}
  table{{width:100%;border-collapse:collapse;background:var(--panel);border-radius:8px;overflow:hidden}}
  th,td{{padding:.75rem 1rem;text-align:left;vertical-align:top;border-bottom:1px solid var(--border)}}
  th{{background:var(--panel2);text-transform:uppercase;font-size:.75rem;letter-spacing:.05em;color:var(--muted)}}
  tr.finding:hover{{background:rgba(56,189,248,0.05)}}
  .sev{{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.75rem;font-weight:700;color:#0f172a}}
  code{{background:var(--panel2);padding:.1rem .35rem;border-radius:3px;font-size:.85em}}
  .title{{font-weight:600;margin-bottom:.25rem}}
  .area{{color:var(--muted);font-size:.8rem}}
  .summary{{font-size:.92rem}}
  .loc{{color:var(--muted);font-size:.8rem;font-family:ui-monospace,monospace;margin-top:.35rem}}
  .root,.fix{{margin-top:.5rem;font-size:.9rem}}
  .ev{{background:#020617;border:1px solid var(--border);padding:.5rem;border-radius:4px;overflow-x:auto;font-size:.8rem;margin-top:.5rem}}
  .meta{{margin-top:.5rem;display:flex;gap:.35rem;flex-wrap:wrap}}
  .badge{{font-size:.7rem;padding:.15rem .5rem;border-radius:99px;background:var(--panel2);color:var(--muted)}}
  .badge-eff{{border:1px solid var(--border)}}
  .badge-imp{{border:1px solid var(--border)}}
  .badge-open{{background:#7f1d1d;color:#fecaca}}
  .badge-prog{{background:#78350f;color:#fed7aa}}
  .badge-res{{background:#14532d;color:#bbf7d0}}
  .badge-wont{{background:#374151;color:#9ca3af}}
  .top5{{background:var(--panel);padding:1rem 1.5rem;border-radius:8px}}
  .top5 ol{{margin:.5rem 0;padding-left:1.5rem}}
  .top5 li{{margin:.35rem 0}}
  footer{{margin-top:3rem;color:var(--muted);font-size:.8rem;text-align:center}}
  .mode-tag{{display:inline-block;background:var(--accent);color:#0f172a;padding:.15rem .5rem;border-radius:4px;font-size:.75rem;font-weight:700}}
</style>
</head>
<body>
  <h1>Agent Audit Report</h1>
  <div class="meta">
    <span class="mode-tag">{mode}</span>
    Target: <code>{target}</code> · Generated: {generated_at}
  </div>

  <h2>Overall Health</h2>
  <div class="health">
    <div class="score">{health_score}</div>
    <div>
      <div style="font-size:1.1rem;font-weight:600">System health score (out of 100)</div>
      <div class="meta">Calculated from severity-weighted findings: 100 − 10·CRIT − 5·HIGH − 2·MED − 0.5·LOW (floored at 0)</div>
    </div>
  </div>

  <h2>Findings by severity</h2>
  <div class="summary">{summary_cards}</div>

  <h2>Top 5 most important recommendations</h2>
  <div class="top5"><ol>{top5_html}</ol></div>

  <h2>All findings ({len(findings)})</h2>
  <table>
    <thead><tr><th>Severity</th><th>ID</th><th>Title</th><th>Detail</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>

  <footer>
    Generated by agent-audit · MIT License · Re-run anytime:<br>
    <code>python3 audit_framework.py --self --output ./report</code>
  </footer>
</body>
</html>
"""


def compute_health(findings: List[Finding]) -> int:
    score = 100
    for f in findings:
        if f.status in ("resolved", "wontfix", "applied"):
            continue  # fully addressed
        if f.status == "partially_resolved":
            score -= 0.5 * {
                "CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0,
            }.get(f.severity, 0)
            continue
        score -= {
            "CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0,
        }.get(f.severity, 0)
    return max(0, int(score))


def top5_recommendations(findings: List[Finding]) -> List[str]:
    # Take the top-5 by impact descending, then severity
    impact_rank = {"XL": 4, "L": 3, "M": 2, "S": 1}
    sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sorted_f = sorted(findings, key=lambda f: (
        -impact_rank.get(f.impact, 0),
        sev_rank.get(f.severity, 99),
    ))
    out = []
    for f in sorted_f[:5]:
        out.append(f"<b>{f.title}</b> — {f.remediation[:200]}{'...' if len(f.remediation) > 200 else ''}")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="AI agent install audit")
    ap.add_argument("--target", type=Path, help="Path to agent install root")
    ap.add_argument("--self", action="store_true", help="Audit the local ~/.hermes install")
    ap.add_argument("--output", type=Path, default=Path("./report"),
                    help="Output directory (default: ./report)")
    ap.add_argument("--fix-track", type=Path, help="Path to JSON file tracking remediation status")
    ap.add_argument("--anonymize", action="store_true",
                    help="Strip file paths and identifiers from the report (public-safe mode)")
    args = ap.parse_args()

    if args.self:
        target = Path.home() / ".hermes"
    elif args.target:
        target = args.target
    else:
        ap.error("Pass --self or --target <path>")

    if not target.exists():
        print(f"Target does not exist: {target}", file=sys.stderr)
        return 2

    args.output.mkdir(parents=True, exist_ok=True)

    # Load fix tracking
    fix_state: Dict[str, Dict[str, Any]] = {}
    if args.fix_track and args.fix_track.exists():
        raw = json.loads(args.fix_track.read_text())
        # Accept either a flat {id: {...}} or a wrapped {"fixes": [{id, status, ...}]}
        if isinstance(raw, dict) and "fixes" in raw and isinstance(raw["fixes"], list):
            for entry in raw["fixes"]:
                if "id" in entry:
                    fix_state[entry["id"]] = entry
        elif isinstance(raw, dict):
            fix_state = raw

    # Run audit
    findings = run_audit(target)

    # Apply fix tracking
    for f in findings:
        if f.id in fix_state:
            f.status = fix_state[f.id].get("status", f.status)
            f.resolved_at = fix_state[f.id].get("resolved_at")
            f.notes = fix_state[f.id].get("notes", "")

    # Anonymize if requested
    if args.anonymize:
        for f in findings:
            f.location = re.sub(r"/home/[^/\s]+", "/home/<user>", f.location)
            f.location = re.sub(r"/Users/[^/\s]+", "/Users/<user>", f.location)
            f.evidence = [re.sub(r"/home/[^/\s]+", "/home/<user>", e) for e in f.evidence]

    health = compute_health(findings)
    top5 = top5_recommendations(findings)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    mode = "ANONYMIZED (public-safe)" if args.anonymize else "PRIVATE — local only"

    # Write outputs
    findings_json = args.output / "audit_findings.json"
    findings_json.write_text(json.dumps(
        [f.to_dict() for f in findings], indent=2
    ))

    html_path = args.output / "audit_report.html"
    html_path.write_text(render_html(
        findings, target, health_score=health, top5=top5,
        generated_at=generated, mode=mode,
    ))

    # Markdown summary
    md_lines = [
        f"# Agent Audit Summary",
        f"",
        f"- **Target:** `{target}`",
        f"- **Health score:** {health}/100",
        f"- **Findings:** {len(findings)}",
        f"- **Generated:** {generated}",
        f"",
        f"## Severity breakdown",
        f"",
    ]
    by_sev: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    for sev in SEVERITY_ORDER:
        md_lines.append(f"- **{sev}:** {by_sev[sev]}")
    md_lines += ["", "## Top 5 recommendations", ""]
    for i, t in enumerate(top5, 1):
        md_lines.append(f"{i}. {t.replace('<b>', '**').replace('</b>', '**')}")
    md_lines += [
        "",
        "## Open findings",
        "",
        "| Sev | ID | Title | Area |",
        "|-----|-----|-------|------|",
    ]
    for f in findings:
        if f.status == "resolved":
            continue
        md_lines.append(f"| {f.severity} | `{f.id}` | {f.title} | {f.area} |")
    (args.output / "AUDIT_SUMMARY.md").write_text("\n".join(md_lines) + "\n")

    print(f"Audit complete. {len(findings)} findings. Health: {health}/100.")
    print(f"  HTML: {html_path}")
    print(f"  JSON: {findings_json}")
    print(f"  MD:   {args.output / 'AUDIT_SUMMARY.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
