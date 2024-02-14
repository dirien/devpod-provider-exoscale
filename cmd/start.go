package cmd

import (
	"context"
	"github.com/dirien/devpod-provider-exoscale/pkg/exoscale"

	"github.com/loft-sh/log"
	"github.com/spf13/cobra"
)

// StartCmd holds the cmd flags
type StartCmd struct{}

// NewStartCmd defines a command
func NewStartCmd() *cobra.Command {
	cmd := &StartCmd{}
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start an instance",
		RunE: func(_ *cobra.Command, args []string) error {
			exoscaleProvider, err := exoscale.NewProvider(log.Default, false)
			if err != nil {
				return err
			}

			return cmd.Run(
				context.Background(),
				exoscaleProvider,
				log.Default,
			)
		},
	}

	return startCmd
}

// Run runs the command logic
func (cmd *StartCmd) Run(
	ctx context.Context,
	providerExoscale *exoscale.ExoscaleProvider,
	logs log.Logger,
) error {
	return exoscale.Start(ctx, providerExoscale)
}
