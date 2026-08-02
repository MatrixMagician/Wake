# Triage labels

The five canonical triage roles, using the default vocabulary (label string == role name):

| Role | Label | Meaning |
|---|---|---|
| Needs triage | `needs-triage` | Newly filed, not yet categorised. Entry state. |
| Needs info | `needs-info` | Blocked on a reply from the reporter. |
| Ready for agent | `ready-for-agent` | Understood, scoped, and safe for an agent to implement. |
| Ready for human | `ready-for-human` | Needs a human decision, judgement, or privileged action. |
| Won't fix | `wontfix` | Deliberately not doing this; the reason is recorded on the issue. |

Create any missing labels with `gh label create <name>` before first use.
