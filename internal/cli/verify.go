package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/MatrixMagician/wake/internal/config"
)

func verifyConfigCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "verify-config <file>",
		Short: "Parse and semantically check a configuration file",
		Long: "Exits non-zero when the configuration is invalid, so that it can be gated\n" +
			"in provisioning and in CI. A configuration that only fails at daemon\n" +
			"start-up fails during someone's incident.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]

			// config.Load treats a missing file as "use the defaults", which is
			// right for `wake run` (a zero-config daemon must work) and wrong
			// here: being told a file you mistyped is valid is worse than being
			// told nothing. So verify-config checks existence itself.
			if _, err := os.Stat(path); err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("%s does not exist", path)
				}
				return fmt.Errorf("cannot read %s: %w", path, err)
			}

			cfg, err := config.Load(path)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}

			// Load deliberately does not validate, so that `wake run` and this
			// command share one path from raw bytes to a verdict. Validating
			// here is what makes that verdict mean anything.
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}

			if opts.jsonOutput {
				return writeJSON(cmd.OutOrStdout(), cfg)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s is valid.\nConfig hash: %s\n",
				path, cfg.Hash())
			return nil
		},
	}
}
