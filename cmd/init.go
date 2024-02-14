package cmd

import (
	"context"
	"github.com/dirien/devpod-provider-exoscale/pkg/exoscale"

	"github.com/loft-sh/log"
	"github.com/spf13/cobra"
)

// InitCmd holds the cmd flags
type InitCmd struct{}

// NewInitCmd defines a init
func NewInitCmd() *cobra.Command {
	cmd := &InitCmd{}
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Init account",
		RunE: func(_ *cobra.Command, args []string) error {
			exoscaleProvider, err := exoscale.NewProvider(log.Default, true)
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

	return initCmd
}

// Run runs the init logic
func (cmd *InitCmd) Run(
	ctx context.Context,
	exoscaleProvider *exoscale.ExoscaleProvider,
	logs log.Logger,
) error {
	return exoscale.Init(ctx, exoscaleProvider)
}
