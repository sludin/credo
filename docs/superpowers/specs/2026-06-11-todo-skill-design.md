---
date: 2026-06-11
topic: todo-skill
status: approved
---

# Design: Global TODO Skill

## Context

Managing a `TODO.md` file at the project root by hand is friction. The goal is a Claude Code skill that lets you add, list, prioritize, and complete todo items through natural language or a `/todo` slash command — globally, across any project.

No external tooling is needed. Claude already has file read/write tools; the skill just teaches it the format and trigger patterns.

## What We Built

A single file at `~/.claude/skills/todo/SKILL.md`. It is a global skill — available in any project conversation.

## TODO.md Format

Open items:

```markdown
- [ ] **Fix the routing table**
  The routing table doesn't handle edge cases when a corgi node rejoins
  after a network partition. Shepherd may assign stale routes.
  Files: `shepherd/src/routing.rs:142`, `credo-lib/src/types.rs:87`
```

Simple items (no context available):

```markdown
- [ ] **Fix the routing table**
```

Completed items at the bottom:

```markdown
## Completed

- [x] **Token refresh cleanup**
  Re-auth prompt when Shepherd rejects a refresh token.
```

Description and Files lines are optional — only added when there's meaningful context to save.

## Trigger Patterns

**Natural language:**
- `todo: <text>` — add simple item
- "add a todo for...", "create a todo around..." — add with discussion context
- "save this as a todo", "make note of this" — capture current discussion
- "show my todos", "what are my open todos" — list open items
- "what should I work on first", "what's most important" — prioritize
- "mark X as done", "X is complete", "close X" — complete an item

**Slash command:**
- `/todo add <title>` — quick add, title only
- `/todo list` — show open items
- `/todo done <title>` — complete an item
- `/todo prioritize` — Claude reasons through list and recommends

## Operations

| Operation | Trigger | Behavior |
|-----------|---------|----------|
| Add simple | `todo: <text>`, `/todo add` | Append unchecked block, title only |
| Add from discussion | "create a todo around this", etc. | Title + synthesized description + relevant files |
| List | "show my todos", `/todo list` | Show open items only |
| Prioritize | "what should I work on first", `/todo prioritize` | Reasoned ranking, no file writes |
| Complete | "mark X as done", `/todo done` | Move block to `## Completed`, change `[ ]` to `[x]` |

**Discovery:** git root → CWD → create new `TODO.md` if adding and none exists.

## Decisions

- **Skill not plugin:** No external server needed. Claude's file tools handle everything; the skill provides the format contract and trigger patterns.
- **No priority tags:** Prioritization is Claude's judgment on demand. Writing tags to the file would add friction and drift out of sync with reality.
- **Completed section (not deletion):** Keeps history visible without cluttering the open list.
- **Optional rich fields:** Simple items stay simple. Description and files only appear when the conversation provides meaningful context to save.
