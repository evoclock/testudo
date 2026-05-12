# CLAUDE.md (Testudo)

Project-specific guidance for Claude Code or other agent tooling working in this repo. Inherits the broader project conventions documented at `~/project-planning/conventions/` (`code-style.md`, `writing-style.md`, `markdown-style.md`, `operations.md`).

## What this project is

Testudo is a dockerised agent runtime: a hardened container that runs an entire agent workflow end-to-end with declarative permissioning, audit logging, rollback semantics, and an embedded lightweight orchestrator. Designed to slot into Hillstar Orchestrator as a hardened execution backend, and to ship its own minimal Electron UI for the demo path.

## Hard rules

- Apache 2.0; sole author Julen Gamboa; no co-author bylines on commits.
- Python project, uv-managed.
- All committed Python passes `ruff check`, `ruff format`, and `mypy` (strict).
- Inventory before authoring: grep `pipeline_output/codebase_inventory.jsonl` for prior art before writing a new module or script.
- Confidentiality: nothing from `~/agentic-orchestrator/` (the private fork) is permitted in this repo. Testudo is OSS only.
- No `/tmp/`. Working dirs go inside the repo (`runs/`, `scratch/`, `pipeline_output/`).
- Never push to remote without explicit authorisation.

## Style

- Follow `~/project-planning/conventions/code-style.md` (eleven-field docstring for scripts; pure functions in modules; thin CLI wrappers).
- Follow `~/project-planning/conventions/writing-style.md` in prose (no emojis, no em-dash clause separators, no ALL-CAPS for emphasis).
- Markdown docs follow `~/project-planning/conventions/markdown-style.md`. MD025 in particular: do not add a body H1 if the file has frontmatter with a `title` field.

## Roadmap

See `~/project-planning/strands/public-oss-push.md` Sub-strand 1 for the broader plan and the two-day v0.1 sprint commitment.
