// Command wake is an eBPF incident flight recorder: it records kernel-level
// events to memory continuously and writes a snapshot only when something
// goes wrong.
package main

import (
	"fmt"
	"os"

	"github.com/MatrixMagician/wake/internal/cli"
)

func main() {
	if err := cli.Root().Execute(); err != nil {
		// Cobra has already printed the error; exit non-zero so that scripts
		// and systemd can tell.
		fmt.Fprintln(os.Stderr)
		os.Exit(1)
	}
}
