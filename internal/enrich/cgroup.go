package enrich

import (
	"regexp"
	"strings"
)

// hex64 matches a 64-character lowercase hex string: the canonical length of
// a full container ID (SHA-256-derived) as used by Podman, Docker and the
// CRI runtimes. Anything shorter or non-hex is never treated as a container
// ID — a truncated or malformed ID is worse than none, because a wrong
// attribution actively misleads an incident investigation.
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Runtime-managed cgroup scope names. Each embeds the full container ID as
// systemd sees it: the runtime asks systemd (or writes cgroupfs directly) to
// create a scope named after the container, so the ID is recoverable from
// the path alone with no kubelet/podman/docker API call — required by
// SPEC.md §10 q5.
var (
	libpodScope        = regexp.MustCompile(`^libpod-([0-9a-f]{64})\.scope$`)
	dockerScope        = regexp.MustCompile(`^docker-([0-9a-f]{64})\.scope$`)
	criContainerdScope = regexp.MustCompile(`^cri-containerd-([0-9a-f]{64})\.scope$`)
	crioScope          = regexp.MustCompile(`^crio-([0-9a-f]{64})\.scope$`)
)

// ParseCgroup derives a systemd unit name and, where the path encodes one, a
// container ID from a cgroup path. It recognises raw systemd
// (/system.slice/foo.service, nested user scopes), Podman
// (libpod-<64hex>.scope), Docker under both the systemd cgroup driver
// (docker-<64hex>.scope) and the cgroupfs driver (/docker/<64hex>), and
// Kubernetes pods running containerd or CRI-O
// (kubepods*.slice/.../cri-containerd-<64hex>.scope or crio-<64hex>.scope).
//
// It never guesses: unrecognised or malformed input degrades to two empty
// strings rather than a best-effort partial match. This is a hard rule, not
// a convenience — a support engineer trusting a wrong attribution is worse
// off than one told plainly "unknown" (SPEC.md §10 q5: parse IDs from the
// cgroup path only, never call a kubelet/runtime API to compensate for a
// path this function cannot read).
func ParseCgroup(path string) (unit, container string) {
	segs := splitCgroupPath(path)
	if len(segs) == 0 {
		return "", ""
	}

	// Runtime-managed scopes carry both the container ID and, as the scope
	// name itself, the unit systemd created to hold it. Checked leaf inward:
	// the runtime always names the *innermost* scope, and an outer segment
	// could coincidentally look similar in a deeply nested hierarchy.
	for i := len(segs) - 1; i >= 0; i-- {
		s := segs[i]
		switch {
		case libpodScope.MatchString(s):
			return s, libpodScope.FindStringSubmatch(s)[1]
		case dockerScope.MatchString(s):
			return s, dockerScope.FindStringSubmatch(s)[1]
		case criContainerdScope.MatchString(s):
			return s, criContainerdScope.FindStringSubmatch(s)[1]
		case crioScope.MatchString(s):
			return s, crioScope.FindStringSubmatch(s)[1]
		}
	}

	// Docker's cgroupfs driver (no systemd involvement) names the container
	// cgroup after its ID directly, under a literal "docker" parent segment:
	// /docker/<64hex>. There is no systemd unit in this layout, so unit is
	// left empty rather than reusing the bare hex as a fake unit name.
	for i := len(segs) - 1; i >= 1; i-- {
		if segs[i-1] == "docker" && hex64.MatchString(segs[i]) {
			return "", segs[i]
		}
	}

	// Plain systemd: the deepest segment that is itself a unit (.service or
	// .scope) rather than a purely organisational .slice. This also covers
	// runtime scopes with a non-64-hex name (e.g. hand-rolled or truncated)
	// that the stricter patterns above declined to treat as a container ID.
	for i := len(segs) - 1; i >= 0; i-- {
		if strings.HasSuffix(segs[i], ".service") || strings.HasSuffix(segs[i], ".scope") {
			return segs[i], ""
		}
	}

	return "", ""
}

// splitCgroupPath splits a cgroup path on '/', dropping empty segments so
// that leading, trailing or doubled slashes never produce spurious ""
// entries that could confuse the "docker" parent-segment check above.
func splitCgroupPath(path string) []string {
	parts := strings.Split(path, "/")
	out := parts[:0] // filter in place: write index never outruns read index
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
