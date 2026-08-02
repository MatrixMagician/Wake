package daemon

import (
	"log/slog"
	"net"
	"os"
)

// notifyReady tells systemd the daemon is up, which is what makes
// Type=notify work in the shipped unit. It is implemented here rather than
// pulled in as a dependency because the protocol is one datagram: adding a
// library for it would be more code than the code.
//
// A missing NOTIFY_SOCKET simply means we are not running under systemd, which
// is a normal way to run Wake and not worth a warning.
func notifyReady(log *slog.Logger) {
	sendNotify(log, "READY=1\nSTATUS=Recording\n")
}

// notifyStopping tells systemd a clean shutdown is underway, so that a slow
// final snapshot is not mistaken for a hang.
func notifyStopping(log *slog.Logger) {
	sendNotify(log, "STOPPING=1\nSTATUS=Writing the shutdown snapshot\n")
}

func sendNotify(log *slog.Logger, msg string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	// An address beginning with '@' denotes the abstract namespace, which Go
	// expresses with a leading NUL.
	if addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}

	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		log.Debug("could not notify systemd", "err", err)
		return
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(msg)); err != nil {
		log.Debug("could not notify systemd", "err", err)
	}
}
