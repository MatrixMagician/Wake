package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MatrixMagician/wake/internal/config"
)

func verifyConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify-config <file>",
		Short: "Parse and semantically check a configuration file",
		Long: "Exits non-zero when the configuration is invalid, so that it can be gated\n" +
			"in provisioning and in CI. A configuration that only fails at daemon\n" +
			"start-up fails during someone's incident.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(args[0])
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "%s: %v\n", args[0], err)
				os.Exit(1)
			}
			if jsonOutput {
				return writeJSON(cmd.OutOrStdout(), cfg)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s is valid.\nConfig hash: %s\n",
				args[0], cfg.Hash())
			return nil
		},
	}
}
