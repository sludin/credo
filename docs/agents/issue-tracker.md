# Issue Tracker

Issues in this project are tracked as local markdown files under `.scratch/<feature-slug>/`.

## Directory layout

```
.scratch/
  <feature-slug>/
    issue.md          # issue description, status, and context
    notes.md          # (optional) research notes, links, findings
    plan.md           # (optional) implementation plan
```

`<feature-slug>` is a short kebab-case string describing the feature or bug (e.g., `config-audit`, `cert-renewal-race`).

## issue.md format

```markdown
# <Title>

**Status:** needs-triage | needs-info | ready-for-agent | ready-for-human | wontfix
**Created:** YYYY-MM-DD
**Updated:** YYYY-MM-DD

## Description

What is the problem or feature request?

## Acceptance criteria

- [ ] ...

## Notes

Anything relevant that doesn't fit above.
```

## Lifecycle

1. Create the directory and `issue.md` when work starts or a problem is found.
2. Set **Status** to `needs-triage` initially.
3. Move through the label flow as the issue progresses (see `triage-labels.md`).
4. When resolved, set status to the terminal label (`wontfix` or delete the directory after merging).

## Conventions

- One issue per directory; do not combine unrelated issues.
- Keep `issue.md` short — move research into `notes.md`.
- The `.scratch/` directory is git-ignored; these files are local only.
