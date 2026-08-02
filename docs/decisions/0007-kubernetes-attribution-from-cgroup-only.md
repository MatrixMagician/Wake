# 0007. Container attribution is parsed from the cgroup path only

## Status

Accepted. Resolves SPEC.md §9 open question 5.

## Context

Open question 5 asked how deep Kubernetes attribution should go: pod UID plus
container ID parsed from the cgroup path, or full kubelet parsing. The SPEC
leaned towards path parsing only.

## Decision

Cgroup path parsing only. Wake never calls a kubelet, a container runtime, or
any API.

The layouts recognised are:

- raw systemd — `/system.slice/foo.service`, `/user.slice/user-1000.slice/...`
- Podman — `.../libpod-<64hex>.scope`
- Docker — `.../docker-<64hex>.scope`, `/docker/<64hex>`
- Kubernetes — `/kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<uid>.slice/cri-containerd-<64hex>.scope`, and the `crio-` and `docker-` variants

Anything unrecognised leaves the container field empty rather than guessing.

## Decision rationale

Three reasons, in order of weight:

1. **No network egress.** Wake makes no outbound calls at all. Adding a kubelet
   client would put a network dependency on the incident path, which is
   precisely when networks are unreliable.
2. **No credentials.** Kubelet access needs a token, which needs configuration,
   rotation, and a threat model. A support tool that copies a snapshot off a
   customer's box should not also hold cluster credentials.
3. **It works when the cluster does not.** Cgroup paths are readable from
   `/proc` when the API server is unreachable, which is a common incident
   shape.

## Consequences

- A snapshot carries a container ID and pod UID, not a pod *name* or namespace.
  The consumer (Sift, or a human) resolves those from the cluster later, at
  their leisure, from a machine that has credentials.
- New runtime layouts are a table addition in `internal/enrich` with a fixture,
  not an architectural change.
