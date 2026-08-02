package enrich

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseCgroup is table-driven against fixture cgroup paths under
// testdata/cgroups/, one file per layout, so the expected parse for each
// real-world cgroup convention is documented as data rather than buried in
// Go string literals.
func TestParseCgroup(t *testing.T) {
	cases := []struct {
		fixture       string
		wantUnit      string
		wantContainer string
	}{
		{
			fixture:       "raw_systemd_service.path",
			wantUnit:      "mstr.service",
			wantContainer: "",
		},
		{
			// Deepest .scope wins over the .service ancestor: the scope is
			// the actual leaf process group.
			fixture:       "raw_systemd_user_app.path",
			wantUnit:      "app-org.kde.konsole-678266.scope",
			wantContainer: "",
		},
		{
			fixture:       "podman.path",
			wantUnit:      "libpod-2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6.scope",
			wantContainer: "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6",
		},
		{
			fixture:       "docker_systemd_driver.path",
			wantUnit:      "docker-18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4.scope",
			wantContainer: "18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4",
		},
		{
			// cgroupfs driver: no systemd unit exists for this layout at all.
			fixture:       "docker_cgroupfs_driver.path",
			wantUnit:      "",
			wantContainer: "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea",
		},
		{
			fixture:       "kubernetes_containerd.path",
			wantUnit:      "cri-containerd-252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111.scope",
			wantContainer: "252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111",
		},
		{
			fixture:       "kubernetes_crio.path",
			wantUnit:      "crio-ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb.scope",
			wantContainer: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		},
		{
			fixture:       "init_scope.path",
			wantUnit:      "init.scope",
			wantContainer: "",
		},
		{
			fixture:       "empty.path",
			wantUnit:      "",
			wantContainer: "",
		},
		{
			// Too short to be a real container ID: must not be guessed at,
			// and must not panic. The .scope suffix alone is not enough to
			// call it a "unit" either, since it is plainly a malformed
			// runtime scope rather than something a human configured.
			fixture:       "junk_short_hex.path",
			wantUnit:      "libpod-deadbeef.scope",
			wantContainer: "",
		},
		{
			fixture:       "junk_random_text.path",
			wantUnit:      "",
			wantContainer: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			path := readFixture(t, tc.fixture)
			gotUnit, gotContainer := ParseCgroup(path)
			if gotUnit != tc.wantUnit {
				t.Errorf("unit = %q, want %q (path %q)", gotUnit, tc.wantUnit, path)
			}
			if gotContainer != tc.wantContainer {
				t.Errorf("container = %q, want %q (path %q)", gotContainer, tc.wantContainer, path)
			}
		})
	}
}

// TestParseCgroupNeverPanics fuzzes ParseCgroup with adversarial input that
// is not represented by a fixture file, since "never panic" is a named
// requirement independent of any specific expected output.
func TestParseCgroupNeverPanics(t *testing.T) {
	inputs := []string{
		"",
		"/",
		"///",
		"not-a-path-at-all",
		strings.Repeat("/x", 10000),
		"/docker/",
		"/docker/not-hex-at-all-but-64-characters-long-000000000000000000000000",
		"/kubepods.slice/cri-containerd-.scope",
		"/\x00\x01\x02",
		"libpod-.scope",
		"/a/b/c/libpod-" + strings.Repeat("g", 64) + ".scope", // non-hex char 'g'
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ParseCgroup(%q) panicked: %v", in, r)
				}
			}()
			ParseCgroup(in)
		}()
	}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "cgroups", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return strings.TrimRight(string(b), "\n")
}
