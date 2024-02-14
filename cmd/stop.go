package cmd

import (
	"context"
	"github.com/dirien/devpod-provider-exoscale/pkg/exoscale"

	"github.com/loft-sh/log"
	"github.com/spf13/cobra"
)

// StopCmd holds the cmd flags
type StopCmd struct{}

// NewStopCmd defines a command
func NewStopCmd() *cobra.Command {
	cmd := &StopCmd{}
	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop an instance",
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

	return stopCmd
}

// Run runs the command logic
func (cmd *StopCmd) Run(
	ctx context.Context,
	exoscaleProvider *exoscale.ExoscaleProvider,
	logs log.Logger,
) error {
	return exoscale.Stop(ctx, exoscaleProvider)
}
