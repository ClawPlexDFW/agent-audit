#!/usr/bin/env python3
"""
build_before_after.py — Generate a single-page before/after HTML report from
two `audit_findings.json` files produced by audit_framework.py.

USAGE
-----
    python3 build_before_after.py --before before.json --after after.json \
        --output before-after.html [--target-name "My Agent"]

The output is fully self-contained (inline CSS) and is what you link to from
the public repo's README.
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COLOR = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
    "LOW": "#2563eb", "INFO": "#6b7280",
}
SEV_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪",
}


def load(p: Path) -> List[Dict[str, Any]]:
    return json.loads(p.read_text())


def index_by_id(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {f["id"]: f for f in findings}


def compute_health(findings: List[Dict[str, Any]]) -> int:
    score = 100
    for f in findings:
        score -= {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "INFO": 0}.get(f["severity"], 0)
    return max(0, int(score))


def severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    out = {s: 0 for s in SEV_ORDER}
    for f in findings:
        out[f["severity"]] = out.get(f["severity"], 0) + 1
    return out


def render(before: List[Dict[str, Any]], after: List[Dict[str, Any]],
           target_name: str, generated: str) -> str:
    bi, ai = index_by_id(before), index_by_id(after)
    bh, ah = compute_health(before), compute_health(after)
    bc, ac = severity_counts(before), severity_counts(after)

    all_ids = sorted(
        set(bi) | set(ai),
        key=lambda i: (
            SEV_ORDER.index((bi.get(i) or ai.get(i) or {"severity": "INFO"})["severity"]),
            i,
        ),
    )

    # Per-finding status
    rows = []
    new_resolved = 0
    new_persisted = 0
    new_introduced = 0
    for fid in all_ids:
        b = bi.get(fid)
        a = ai.get(fid)
        if b and a:
            sev = a["severity"]
            status = "🟢 resolved" if a.get("status") == "resolved" else "—"
            if a.get("status") == "resolved":
                new_resolved += 1
            else:
                new_persisted += 1
        elif b and not a:
            sev = b["severity"]
            status = "🟢 resolved"
            new_resolved += 1
        else:  # a only
            sev = a["severity"]
            status = "🔴 new"
            new_introduced += 1
        title = (a or b)["title"]
        rows.append(f"""
        <tr>
          <td><code>{fid}</code></td>
          <td><span class="sev" style="background:{SEV_COLOR[sev]}">{SEV_EMOJI[sev]} {sev}</span></td>
          <td>{title}</td>
          <td>{status}</td>
        </tr>""")

    delta = ah - bh
    delta_color = "#16a34a" if delta > 0 else "#dc2626" if delta < 0 else "#6b7280"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Audit Before/After — {html.escape(target_name)}</title>
<style>
  :root {{
    --bg:#0f172a;--panel:#1e293b;--panel2:#334155;--fg:#e2e8f0;--muted:#94a3b8;
    --border:#475569;--good:#4ade80;--bad:#f87171;
  }}
  *{{box-sizing:border-box}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:2rem;line-height:1.5}}
  h1{{margin:0 0 .5rem 0;font-size:1.75rem}}
  h2{{margin:2rem 0 1rem;border-bottom:1px solid var(--border);padding-bottom:.5rem}}
  .meta{{color:var(--muted);font-size:.9rem;margin-bottom:1rem}}
  .row{{display:grid;grid-template-columns:1fr auto 1fr;gap:1rem;align-items:center;margin:1.5rem 0}}
  .panel{{background:var(--panel);padding:1.25rem 1.5rem;border-radius:8px;border-left:4px solid var(--border)}}
  .panel.before{{border-left-color:#f87171}}
  .panel.after{{border-left-color:var(--good)}}
  .panel h3{{margin:0 0 .5rem 0;font-size:.85rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}}
  .panel .score{{font-size:2.5rem;font-weight:800}}
  .arrow{{font-size:1.5rem;text-align:center;color:var(--muted)}}
  .delta{{display:inline-block;padding:.15rem .6rem;border-radius:4px;font-weight:700;color:#0f172a;background:{delta_color}}}
  .summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:1rem;margin:1.5rem 0}}
  .card{{background:var(--panel);border-radius:8px;padding:1rem;text-align:center;border-left:4px solid var(--border)}}
  .card .num{{font-size:1.75rem;font-weight:700}}
  .card .lbl{{color:var(--muted);font-size:.75rem;text-transform:uppercase}}
  table{{width:100%;border-collapse:collapse;background:var(--panel);border-radius:8px;overflow:hidden}}
  th,td{{padding:.6rem 1rem;text-align:left;border-bottom:1px solid var(--border)}}
  th{{background:var(--panel2);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}}
  .sev{{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.7rem;font-weight:700;color:#0f172a}}
  code{{background:var(--panel2);padding:.1rem .35rem;border-radius:3px;font-size:.85em}}
  footer{{margin-top:3rem;color:var(--muted);font-size:.8rem;text-align:center}}
</style>
</head>
<body>
  <h1>Audit Before/After</h1>
  <div class="meta">Target: <b>{html.escape(target_name)}</b> · Generated: {generated}</div>

  <h2>Health score</h2>
  <div class="row">
    <div class="panel before">
      <h3>Before</h3>
      <div class="score">{bh}</div>
      <div class="meta">{len(before)} findings</div>
    </div>
    <div class="arrow">
      <div class="delta">{('+' if delta > 0 else '')}{delta} pts</div>
    </div>
    <div class="panel after">
      <h3>After</h3>
      <div class="score">{ah}</div>
      <div class="meta">{len(after)} findings ({sum(1 for f in after if f.get('status')=='resolved')} resolved)</div>
    </div>
  </div>

  <h2>Severity delta</h2>
  <div class="summary">
    {"".join(
        f'<div class="card"><div class="num">{bc[s]} → {ac[s]}</div><div class="lbl">{SEV_EMOJI[s]} {s}</div></div>'
        for s in SEV_ORDER
    )}
  </div>

  <h2>Remediation outcomes</h2>
  <div class="summary">
    <div class="card"><div class="num">{new_resolved}</div><div class="lbl">🟢 resolved</div></div>
    <div class="card"><div class="num">{new_persisted}</div><div class="lbl">⏳ persisted (open)</div></div>
    <div class="card"><div class="num">{new_introduced}</div><div class="lbl">🔴 introduced</div></div>
  </div>

  <h2>Per-finding detail</h2>
  <table>
    <thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Status</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>

  <footer>
    Generated by build_before_after.py · Pair with <code>audit_framework.py</code>
  </footer>
</body>
</html>"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--before", type=Path, required=True)
    ap.add_argument("--after", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--target-name", type=str, default="Agent Install")
    args = ap.parse_args()

    if not args.before.exists() or not args.after.exists():
        print("Both --before and --after JSON files must exist", file=sys.stderr)
        return 2

    before = load(args.before)
    after = load(args.after)

    from datetime import datetime, timezone
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    args.output.write_text(render(before, after, args.target_name, generated))
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
