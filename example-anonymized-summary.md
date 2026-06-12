# Agent Audit Summary

- **Target:** `/home/<user>/.hermes`
- **Health score:** 94/100
- **Findings:** 9
- **Generated:** 2026-06-12 19:11 UTC

## Severity breakdown

- **CRITICAL:** 1
- **HIGH:** 0
- **MEDIUM:** 3
- **LOW:** 2
- **INFO:** 3

## Top 5 recommendations

1. **35 file(s) contain prompt-injection signatures** — Quarantine each file. Treat the phrases as injection attempts unless the file is in a known-bucket (upstream bundled, research skill, test fixture, red-flag list, archive, snapshot).
2. **Empty fallback_providers list** — Add at least one secondary provider with a different API key.
3. **88 broad exception catches, 45 silent** — Adopt a central error_classifier (agent/error_classifier.py exists upstream) and tag exceptions with FailoverReason / category before catching.
4. **God-file loop (5,368 lines, 231KB)** — Extract responsibilities into focused mixins/modules (init, runtime helpers, dispatch). Reference: AGENTS.md contribution rubric encourages this exact refactor.
5. **state.db is 339MB** — Run `VACUUM` after backup. Consider archiving sessions older than N days.

## Open findings

| Sev | ID | Title | Area |
|-----|-----|-------|------|
| CRITICAL | `SEC-001` | 35 file(s) contain prompt-injection signatures | config |
| MEDIUM | `CFG-002` | Empty fallback_providers list | config |
| MEDIUM | `CORE-002` | God-file loop (5,368 lines, 231KB) | core |
| MEDIUM | `STATE-001` | state.db is 339MB | state |
| LOW | `CORE-003` | 88 broad exception catches, 45 silent | core |
| INFO | `SKILL-001` | 162 SKILL.md files in user skills tree | skills |
| INFO | `STATE-002` | 488 session transcript files | state |
| INFO | `TOOL-001` | 85 tool files in registry | tools |
