package cmd

import (
	"context"
	"github.com/dirien/devpod-provider-exoscale/pkg/exoscale"

	"github.com/loft-sh/log"
	"github.com/spf13/cobra"
)

// DeleteCmd holds the cmd flags
type DeleteCmd struct{}

// NewDeleteCmd defines a command
func NewDeleteCmd() *cobra.Command {
	cmd := &DeleteCmd{}
	deleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete an instance",
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

	return deleteCmd
}

// Run runs the command logic
func (cmd *DeleteCmd) Run(
	ctx context.Context,
	providerExoscale *exoscale.ExoscaleProvider,
	logs log.Logger,
) error {
	return exoscale.Delete(ctx, providerExoscale)
}
