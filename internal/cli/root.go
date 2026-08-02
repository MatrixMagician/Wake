// Package cli defines Wake's command surface (SPEC.md §5).
//
// Every subcommand that talks to the daemon does so over the control socket
// rather than by poking at shared state, so that `wake status` on a host where
// the daemon is not running says exactly that rather than printing zeroes.
package cli

import (
	"github.com/spf13/cobra"

	"github.com/MatrixMagician/wake/internal/ctl"
	"github.com/MatrixMagician/wake/internal/version"
)

// Flags shared across subcommands.
var (
	configPath string
	socketPath string
	jsonOutput bool
)

// Root builds the command tree.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:     "wake",
		Short:   "eBPF incident flight recorder",
		Version: version.Version,
		Long: "Wake records process, file, network, signal and OOM events to a bounded\n" +
			"in-memory ring and writes nothing during normal operation. When a trigger\n" +
			"fires it persists the last N minutes of kernel-level truth surrounding the\n" +
			"incident as a self-contained snapshot.",
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(&socketPath, "socket", ctl.SocketPath,
		"path to the daemon's control socket")
	root.PersistentFlags().BoolVar(&jsonOutput, "json", false,
		"emit JSON rather than human-readable output")

	root.AddCommand(
		runCmd(),
		statusCmd(),
		triggerCmd(),
		watchCmd(),
		snapshotsCmd(),
		doctorCmd(),
		verifyConfigCmd(),
	)
	return root
}
