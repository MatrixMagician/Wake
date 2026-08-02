# Issue tracker

Issues for this repository live in **GitHub Issues** on `MatrixMagician/Wake`,
accessed with the `gh` CLI.

```bash
gh issue list --label needs-triage
gh issue create --title "..." --body-file <file> --label needs-triage
gh issue view <n> --comments
gh issue edit <n> --add-label ready-for-agent --remove-label needs-triage
```

Conventions:
- One issue per tracer-bullet ticket. Blocking edges are stated in the body as
  `Blocked by: #12, #13` and mirrored with GitHub's native relationships where available.
- Reference the milestone from SPEC.md §7 (`M1`…`M7`) in the issue title prefix, e.g.
  `M3: openat tracepoint decode`.
- Skills may read and comment freely; **closing** an issue is a human action unless the
  user has asked for it explicitly.

## PRs as a request surface

**Off.** External pull requests are not part of the triage queue. Flip this to on here
if that changes.
