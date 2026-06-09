# Domain Documentation Strategy

This project uses a multi-context monorepo structure. Documentation is layered so that Claude and human readers can orient quickly within a single package without loading the full repo context.

## File hierarchy

| File | Scope | Audience |
|------|-------|---------|
| `CLAUDE.md` (root) | Whole repo — architecture, ports, auth model, workflow rules | Always loaded by Claude Code |
| `CONTEXT-MAP.md` (root) | Map of all packages, their roles, and interaction boundaries | Loaded when cross-service context is needed |
| `<package>/CONTEXT.md` | Deep dive for one service — module map, data flow, config, gotchas | Loaded when working inside that package |
| `<package>/docs/config.md` | Config field reference for one service | Operator reference |
| `<package>/docs/api.md` | HTTP API surface for one service | Integration reference |
| `docs/adr/` | Architecture Decision Records (system-wide decisions) | Historical context |

## CONTEXT.md structure

Each per-package `CONTEXT.md` should cover, in order:

1. **Role** — one paragraph: what this service does and why it exists
2. **Module map** — table of key source files and their responsibilities
3. **Data flow** — step-by-step description of the primary request lifecycle
4. **Config schema** — key fields, their types, defaults, and effect
5. **Error handling** — how errors propagate, what is logged, what is returned to callers
6. **Known gotchas** — non-obvious constraints, ordering requirements, footguns
7. **Dev commands** — build, test, run, debug for this package specifically
8. **Integration points** — what this service calls, what calls it, how they are wired

## ADR format

Each ADR lives at `docs/adr/NNNN-<slug>.md` and follows this template:

```markdown
# NNNN: <Title>

**Date:** YYYY-MM-DD
**Status:** proposed | accepted | superseded

## Context

Why did this decision need to be made?

## Decision

What was decided?

## Consequences

What are the trade-offs and implications?
```

## CONTEXT-MAP.md

`CONTEXT-MAP.md` at the repo root provides a one-page overview of all packages and their interaction boundaries. It should be updated whenever a new service is added or a major inter-service API changes.
