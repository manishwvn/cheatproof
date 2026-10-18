# Status

**2026-10-18: project decided: Cheatproof** (Coding & Agentic track). Read `docs/HANDOFF.md` first.

- The repo still carries the old R1 name `twin-diff`; the new planner session renames it and rewrites the docs.
- Built so far: the spend cap (`twindiff/budget.py`, `twindiff/llm.py`, 16 tests), CI and security workflows
  (green), autopilot scripts, guards. No product code yet. The scheduled routine is not created yet.
- Owner blockers: U1 (Nebius key), U3 (Sandboxes access; Docker is the fallback).
- Open audit fixes: single-lock sandbox reservation; one cap number everywhere.
