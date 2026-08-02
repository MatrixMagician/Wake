package decode

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/MatrixMagician/wake/internal/event"
)

// fixedClock makes decoding deterministic so that assertions can name exact
// timestamps rather than tolerating whatever the host booted at.
type fixedClock struct{ boot time.Time }

func (c fixedClock) BootTimeToWall(ns uint64) time.Time {
	return c.boot.Add(time.Duration(ns)) //nolint:gosec
}

var testBoot = time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)

func newTestDecoder() *Decoder { return New(fixedClock{boot: testBoot}) }

// TestWireSizes pins the Go decoder's idea of each record's size to the sizes
// the C compiler produces for bpf/wake_event.h. These numbers were obtained by
// compiling a sizeof() probe against the header; if the header changes without
// this test being updated, the decoder is silently misreading the kernel.
func TestWireSizes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"header", headerSize, 56},
		{"exec", execSize, 840},
		{"exit", exitSize, 72},
		{"signal", signalSize, 72},
		{"oom", oomSize, 96},
		{"open", openSize, 328},
		{"connect", connectSize, 104},
	} {
		if tc.got != tc.want {
			t.Errorf("%s size = %d, want %d (C sizeof)", tc.name, tc.got, tc.want)
		}
	}
}

// recBuilder assembles a wire record the way the BPF side would.
type recBuilder struct{ b []byte }

func newRec(size int, kind uint32) *recBuilder {
	r := &recBuilder{b: make([]byte, size)}
	r.u64(0, 1_500_000_000) // 1.5s after boot
	r.u32(8, kind)
	r.u32(12, WireVersion)
	r.u32(16, 4321) // pid
	r.u32(20, 4321) // tid
	r.u32(24, 987)  // uid
	r.u64(32, 42)   // cgroup id
	copy(r.b[40:56], "smtpd\x00")
	return r
}

func (r *recBuilder) u16(off int, v uint16) { binary.LittleEndian.PutUint16(r.b[off:], v) }
func (r *recBuilder) u32(off int, v uint32) { binary.LittleEndian.PutUint32(r.b[off:], v) }
func (r *recBuilder) u64(off int, v uint64) { binary.LittleEndian.PutUint64(r.b[off:], v) }
func (r *recBuilder) str(off int, s string) { copy(r.b[off:], s) }

func TestDecodeHeaderCommonFields(t *testing.T) {
	t.Parallel()
	ev := newTestDecoder().Decode(newRec(exitSize, KindExit).b)

	if got, want := ev.Timestamp, testBoot.Add(1500*time.Millisecond); !got.Equal(want) {
		t.Errorf("ts = %v, want %v", got, want)
	}
	if ev.PID != 4321 || ev.TID != 4321 || ev.UID != 987 || ev.CgroupID != 42 {
		t.Errorf("header fields wrong: %+v", ev)
	}
	if ev.Comm != "smtpd" {
		t.Errorf("comm = %q, want smtpd", ev.Comm)
	}
}

func TestDecodeExec(t *testing.T) {
	t.Parallel()
	r := newRec(execSize, KindExec)
	r.u32(56, 4300) // ppid
	argv := "smtpd\x00-d\x00--config=/etc/x\x00"
	r.u32(60, uint32(len(argv)))
	r.b[64] = 0
	r.str(68, "/usr/sbin/smtpd")
	r.str(324, argv)

	ev := newTestDecoder().Decode(r.b)

	if ev.Class != event.ClassExec {
		t.Fatalf("class = %q", ev.Class)
	}
	if ev.Ppid != 4300 {
		t.Errorf("ppid = %d", ev.Ppid)
	}
	if ev.Filename != "/usr/sbin/smtpd" {
		t.Errorf("filename = %q", ev.Filename)
	}
	want := []string{"smtpd", "-d", "--config=/etc/x"}
	if len(ev.Argv) != len(want) {
		t.Fatalf("argv = %q, want %q", ev.Argv, want)
	}
	for i := range want {
		if ev.Argv[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, ev.Argv[i], want[i])
		}
	}
	if ev.ArgvTrunc {
		t.Error("argv unexpectedly marked truncated")
	}
}

// TestDecodeExecTruncatedArgv covers the case the SPEC calls out explicitly:
// a long command line must be reported as truncated, with the partial final
// argument kept, because half an argument is still evidence.
func TestDecodeExecTruncatedArgv(t *testing.T) {
	t.Parallel()
	r := newRec(execSize, KindExec)
	long := strings.Repeat("a", argvLen-6) // no trailing NUL: cut mid-argument
	argv := "prog\x00" + long
	r.u32(60, uint32(argvLen))
	r.b[64] = 1
	r.str(324, argv)

	ev := newTestDecoder().Decode(r.b)

	if !ev.ArgvTrunc {
		t.Error("truncation flag lost")
	}
	if len(ev.Argv) != 2 || ev.Argv[0] != "prog" {
		t.Fatalf("argv = %q", ev.Argv)
	}
	if len(ev.Argv[1]) == 0 {
		t.Error("partial final argument discarded; it is still evidence")
	}
}

// TestDecodeExecBogusArgvLen proves a corrupt length field cannot cause an
// out-of-range read, and that the record survives rather than being dropped.
func TestDecodeExecBogusArgvLen(t *testing.T) {
	t.Parallel()
	r := newRec(execSize, KindExec)
	r.u32(60, 1<<30)
	r.str(324, "prog\x00")

	ev := newTestDecoder().Decode(r.b)

	if ev.Class != event.ClassExec {
		t.Fatalf("class = %q, want exec", ev.Class)
	}
	if !ev.ArgvTrunc {
		t.Error("an over-long argv_len should be reported as truncation")
	}
}

func TestDecodeExit(t *testing.T) {
	t.Parallel()
	t.Run("clean exit", func(t *testing.T) {
		r := newRec(exitSize, KindExit)
		r.u32(56, 0)
		ev := newTestDecoder().Decode(r.b)
		if ev.ExitCode == nil || *ev.ExitCode != 0 {
			t.Fatalf("exit code = %v", ev.ExitCode)
		}
		if ev.ExitSignal != nil {
			t.Errorf("exit signal set on a clean exit: %v", *ev.ExitSignal)
		}
	})
	t.Run("killed", func(t *testing.T) {
		r := newRec(exitSize, KindExit)
		r.u32(56, 0)
		r.u32(60, 9)
		ev := newTestDecoder().Decode(r.b)
		if ev.ExitSignal == nil || *ev.ExitSignal != 9 {
			t.Fatalf("exit signal = %v", ev.ExitSignal)
		}
		if ev.SignalName != "SIGKILL" {
			t.Errorf("signal name = %q", ev.SignalName)
		}
	})
}

func TestDecodeSignal(t *testing.T) {
	t.Parallel()
	r := newRec(signalSize, KindSignal)
	r.u32(56, 11)   // SIGSEGV
	r.u32(64, 1234) // sender
	ev := newTestDecoder().Decode(r.b)

	if ev.Class != event.ClassSignal || ev.SignalName != "SIGSEGV" {
		t.Fatalf("got %q/%q", ev.Class, ev.SignalName)
	}
	if ev.SenderPID == nil || *ev.SenderPID != 1234 {
		t.Errorf("sender = %v", ev.SenderPID)
	}
}

func TestDecodeOOM(t *testing.T) {
	t.Parallel()
	r := newRec(oomSize, KindOOM)
	r.u64(56, 4096)
	r.u64(64, 2048)
	r.u64(72, 512)
	adj := int16(-500)
	r.u16(88, uint16(adj)) //nolint:gosec
	ev := newTestDecoder().Decode(r.b)

	if ev.Class != event.ClassOOM {
		t.Fatalf("class = %q", ev.Class)
	}
	if ev.TotalVM != 4096 || ev.AnonRSS != 2048 || ev.FileRSS != 512 {
		t.Errorf("memory fields wrong: %+v", ev)
	}
	if ev.OOMScoreAdj == nil || *ev.OOMScoreAdj != -500 {
		t.Errorf("oom_score_adj = %v, want -500 (sign must survive)", ev.OOMScoreAdj)
	}
}

func TestDecodeOpen(t *testing.T) {
	t.Parallel()
	t.Run("failure keeps its errno", func(t *testing.T) {
		r := newRec(openSize, KindOpen)
		eacces := int64(-13)
		r.u64(56, uint64(eacces)) //nolint:gosec
		r.u32(64, 0)              // O_RDONLY
		r.str(72, "/etc/ssl/private/key.pem")
		ev := newTestDecoder().Decode(r.b)

		if ev.Path != "/etc/ssl/private/key.pem" {
			t.Errorf("path = %q", ev.Path)
		}
		if ev.Errno != "EACCES" {
			t.Errorf("errno = %q, want EACCES", ev.Errno)
		}
		if ev.Flags != "O_RDONLY" {
			t.Errorf("flags = %q", ev.Flags)
		}
	})
	t.Run("success has no errno", func(t *testing.T) {
		r := newRec(openSize, KindOpen)
		r.u64(56, 7)
		r.u32(64, 0o2101) // O_WRONLY|O_CREAT|O_APPEND
		r.str(72, "/var/log/app.log")
		ev := newTestDecoder().Decode(r.b)

		if ev.Errno != "" {
			t.Errorf("errno = %q on a successful open", ev.Errno)
		}
		for _, want := range []string{"O_WRONLY", "O_CREAT", "O_APPEND"} {
			if !strings.Contains(ev.Flags, want) {
				t.Errorf("flags %q missing %s", ev.Flags, want)
			}
		}
	})
}

func TestDecodeConnect(t *testing.T) {
	t.Parallel()
	t.Run("ipv4 failed attempt", func(t *testing.T) {
		r := newRec(connectSize, KindConnect)
		r.u32(56, uint32(tcpSynSent)) //nolint:gosec
		r.u32(60, uint32(tcpClose))   //nolint:gosec
		r.u16(64, 54321)
		r.u16(66, 587)
		r.u16(68, afInet)
		r.u16(70, 6)
		copy(r.b[72:], []byte{10, 0, 4, 1})
		copy(r.b[88:], []byte{10, 0, 4, 7})
		ev := newTestDecoder().Decode(r.b)

		if ev.DAddr != "10.0.4.7" || ev.SAddr != "10.0.4.1" {
			t.Errorf("addrs = %q -> %q", ev.SAddr, ev.DAddr)
		}
		if ev.DPort != 587 || ev.Proto != "tcp" {
			t.Errorf("dport/proto = %d/%q", ev.DPort, ev.Proto)
		}
		if ev.OldState != "TCP_SYN_SENT" || ev.NewState != "TCP_CLOSE" {
			t.Errorf("states = %q -> %q", ev.OldState, ev.NewState)
		}
		if ev.Errno == "" {
			t.Error("SYN_SENT->CLOSE must be reported as a failed attempt")
		}
	})
	t.Run("ipv6 success", func(t *testing.T) {
		r := newRec(connectSize, KindConnect)
		r.u32(56, uint32(tcpSynSent))     //nolint:gosec
		r.u32(60, uint32(tcpEstablished)) //nolint:gosec
		r.u16(68, afInet6)
		r.u16(70, 6)
		copy(r.b[88:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		ev := newTestDecoder().Decode(r.b)

		if ev.DAddr != "2001:db8::1" {
			t.Errorf("daddr = %q", ev.DAddr)
		}
		if ev.Errno != "" {
			t.Errorf("errno = %q on a successful connect", ev.Errno)
		}
	})
	t.Run("unknown family yields no address rather than a wrong one", func(t *testing.T) {
		r := newRec(connectSize, KindConnect)
		r.u16(68, 99)
		r.u16(70, 6)
		copy(r.b[88:], []byte{1, 2, 3, 4})
		ev := newTestDecoder().Decode(r.b)
		if ev.DAddr != "" {
			t.Errorf("daddr = %q; a guessed address costs hours in an incident", ev.DAddr)
		}
	})
}

// The tests below are the point of the package: decode is total.

func TestDecodeIsTotal(t *testing.T) {
	t.Parallel()
	d := newTestDecoder()

	t.Run("unknown kind", func(t *testing.T) {
		r := newRec(headerSize+8, 0xDEAD)
		ev := d.Decode(r.b)
		if ev.Class != event.ClassGeneric {
			t.Fatalf("class = %q, want generic", ev.Class)
		}
		if ev.RawKind != 0xDEAD || len(ev.Raw) != len(r.b) {
			t.Errorf("raw payload not retained: kind=%d len=%d", ev.RawKind, len(ev.Raw))
		}
		if ev.DecodeError == "" {
			t.Error("generic event must explain itself")
		}
		if ev.PID != 4321 {
			t.Error("header fields should still be decoded for an unknown kind")
		}
	})

	t.Run("future wire version", func(t *testing.T) {
		r := newRec(exitSize, KindExit)
		r.u32(12, WireVersion+1)
		ev := d.Decode(r.b)
		if ev.Class != event.ClassGeneric {
			t.Fatalf("class = %q, want generic", ev.Class)
		}
		if !strings.Contains(ev.DecodeError, "wire version") {
			t.Errorf("decode error = %q", ev.DecodeError)
		}
	})

	t.Run("truncated record of a known kind", func(t *testing.T) {
		r := newRec(exitSize, KindExit)
		ev := d.Decode(r.b[:headerSize+2])
		if ev.Class != event.ClassGeneric {
			t.Fatalf("class = %q, want generic", ev.Class)
		}
		if len(ev.Raw) == 0 {
			t.Error("raw payload discarded")
		}
	})

	t.Run("record shorter than a header", func(t *testing.T) {
		ev := d.Decode([]byte{1, 2, 3})
		if ev.Class != event.ClassGeneric || ev.DecodeError != ErrShortRecord.Error() {
			t.Fatalf("got %q / %q", ev.Class, ev.DecodeError)
		}
		if len(ev.Raw) != 3 {
			t.Error("the three bytes we did get should still be kept")
		}
	})

	t.Run("empty record", func(t *testing.T) {
		ev := d.Decode(nil)
		if ev.Class != event.ClassGeneric {
			t.Fatalf("class = %q", ev.Class)
		}
	})
}

// FuzzDecodeNeverPanics is the strongest statement of the totality rule: no
// byte sequence the kernel could hand us may take the daemon down.
func FuzzDecodeNeverPanics(f *testing.F) {
	f.Add(newRec(execSize, KindExec).b)
	f.Add(newRec(exitSize, KindExit).b)
	f.Add(newRec(openSize, KindOpen).b)
	f.Add(newRec(connectSize, KindConnect).b)
	f.Add([]byte{})
	f.Add([]byte{0xff})

	d := newTestDecoder()
	f.Fuzz(func(t *testing.T, b []byte) {
		ev := d.Decode(b)
		if ev.Class == "" {
			t.Fatal("decode produced an event with no class")
		}
		if _, err := ev.MarshalJSONLine(); err != nil {
			t.Fatalf("decoded event is not serialisable: %v", err)
		}
	})
}
