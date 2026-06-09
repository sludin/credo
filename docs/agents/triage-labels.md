# Triage Labels

These are the canonical status labels used in `.scratch/<feature-slug>/issue.md` files.

| Label | Meaning |
|-------|---------|
| `needs-triage` | Newly created; not yet assessed for priority or approach. |
| `needs-info` | Blocked waiting for more information (from user, logs, external system). |
| `ready-for-agent` | Fully specified and ready for Claude to work on autonomously. |
| `ready-for-human` | Requires a human decision, access, or action that Claude cannot perform. |
| `wontfix` | Acknowledged but will not be addressed. Include a brief reason in the issue. |

## Transition rules

- Only move an issue to `ready-for-agent` when acceptance criteria are defined and unambiguous.
- Move back to `needs-info` if new blockers are discovered during work.
- `wontfix` is terminal — add a **Reason** line before closing.
