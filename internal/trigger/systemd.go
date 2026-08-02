package trigger

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/godbus/dbus/v5"
)

// UnitWatcher subscribes to systemd's manager signals and reports units that
// enter the failed state.
//
// It lives apart from the engine so that the engine's tests need no bus: the
// engine exposes UnitFailed, and this type is simply one caller of it.
type UnitWatcher struct {
	conn *dbus.Conn
	log  *slog.Logger
}

// NewUnitWatcher connects to the system bus and asks systemd to emit the
// PropertiesChanged signals we need. It returns a descriptive error when the
// bus is unavailable, because "no systemd" is a legitimate environment (a
// container, a minimal image) rather than a fatal condition for the daemon.
func NewUnitWatcher(log *slog.Logger) (*UnitWatcher, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("connecting to the system bus (unit triggers need systemd): %w", err)
	}

	obj := conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
	if call := obj.Call("org.freedesktop.systemd1.Manager.Subscribe", 0); call.Err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("subscribing to systemd manager signals: %w", call.Err)
	}

	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.DBus.Properties"),
		dbus.WithMatchMember("PropertiesChanged"),
		dbus.WithMatchPathNamespace("/org/freedesktop/systemd1/unit"),
	); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("adding a signal match for unit property changes: %w", err)
	}

	return &UnitWatcher{conn: conn, log: log}, nil
}

// Run forwards failed units to the engine until the context is cancelled.
func (w *UnitWatcher) Run(ctx context.Context, e *Engine) {
	ch := make(chan *dbus.Signal, 64)
	w.conn.Signal(ch)

	for {
		select {
		case <-ctx.Done():
			return
		case sig, ok := <-ch:
			if !ok {
				return
			}
			unit, state := parseUnitState(sig)
			if state != "failed" || unit == "" {
				continue
			}
			w.log.Info("unit entered the failed state", "unit", unit)
			e.UnitFailed(unit)
		}
	}
}

// Close releases the bus connection.
func (w *UnitWatcher) Close() error {
	if w.conn == nil {
		return nil
	}
	return w.conn.Close()
}

// parseUnitState pulls the unit name and ActiveState out of a
// PropertiesChanged signal. Anything unexpected yields empty strings rather
// than an error: a bus is a firehose of signals we do not care about, and
// logging each one would be its own denial of service.
func parseUnitState(sig *dbus.Signal) (unit, state string) {
	if len(sig.Body) < 2 {
		return "", ""
	}
	iface, _ := sig.Body[0].(string)
	if iface != "org.freedesktop.systemd1.Unit" {
		return "", ""
	}
	props, ok := sig.Body[1].(map[string]dbus.Variant)
	if !ok {
		return "", ""
	}
	v, ok := props["ActiveState"]
	if !ok {
		return "", ""
	}
	if err := v.Store(&state); err != nil {
		return "", ""
	}
	return unitFromPath(string(sig.Path)), state
}

// unitFromPath decodes systemd's object-path escaping ("_2d" for '-', and so
// on) back into a unit name.
func unitFromPath(p string) string {
	const prefix = "/org/freedesktop/systemd1/unit/"
	if !strings.HasPrefix(p, prefix) {
		return ""
	}
	esc := strings.TrimPrefix(p, prefix)

	var b strings.Builder
	for i := 0; i < len(esc); i++ {
		if esc[i] == '_' && i+2 < len(esc) {
			var v int
			if _, err := fmt.Sscanf(esc[i+1:i+3], "%02x", &v); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(esc[i])
	}
	return b.String()
}
