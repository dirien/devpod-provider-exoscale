package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/dirien/devpod-provider-exoscale/pkg/exoscale"
	"github.com/loft-sh/devpod/pkg/ssh"
	"github.com/loft-sh/log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// CommandCmd holds the cmd flags
type CommandCmd struct{}

// NewCommandCmd defines a command
func NewCommandCmd() *cobra.Command {
	cmd := &CommandCmd{}
	commandCmd := &cobra.Command{
		Use:   "command",
		Short: "Command an instance",
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

	return commandCmd
}

// Run runs the command logic
func (cmd *CommandCmd) Run(
	ctx context.Context,
	exoscaleProvider *exoscale.ExoscaleProvider,
	logs log.Logger,
) error {
	command := os.Getenv("COMMAND")

	if command == "" {
		return fmt.Errorf("command environment variable is missing")
	}

	privateKey, err := ssh.GetPrivateKeyRawBase(exoscaleProvider.Config.MachineFolder)
	if err != nil {
		return fmt.Errorf("load private key: %w", err)
	}

	// get instance
	instance, err := exoscale.GetDevpodInstance(ctx, exoscaleProvider)
	if err != nil {
		return err
	}
	sshClient, err := ssh.NewSSHClient("devpod", instance.PublicIP.String()+":22", privateKey)

	if err != nil {
		return errors.Wrap(err, "create ssh client")
	}

	defer sshClient.Close()

	// run command
	return ssh.Run(ctx, sshClient, command, os.Stdin, os.Stdout, os.Stderr, nil)
}
