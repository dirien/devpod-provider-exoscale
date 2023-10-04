package options

import (
	"fmt"
	"os"
	"strings"
)

var (
	EXOSCALE_ZONE              = "EXOSCALE_ZONE"
	EXOSCALE_INSTANCE_TYPE     = "EXOSCALE_INSTANCE_TYPE"
	EXOSCALE_INSTANCE_TEMPLATE = "EXOSCALE_INSTANCE_TEMPLATE"
	EXOSCALE_DISK_SIZE_GB      = "EXOSCALE_DISK_SIZE_GB"
	MACHINE_ID                 = "MACHINE_ID"
	MACHINE_FOLDER             = "MACHINE_FOLDER"
)

type Options struct {
	Zone             string
	InstanceType     string
	InstanceTemplate string
	DiskSizeGB       string

	MachineID     string
	MachineFolder string
}

func ConfigFromEnv() (Options, error) {
	return Options{
		Zone: os.Getenv(EXOSCALE_ZONE),
	}, nil
}

func FromEnv(init bool) (*Options, error) {
	retOptions := &Options{}

	var err error

	retOptions.Zone, err = fromEnvOrError(EXOSCALE_ZONE)
	if err != nil {
		return nil, err
	}
	retOptions.Zone = strings.ToLower(retOptions.Zone)

	retOptions.InstanceType, err = fromEnvOrError(EXOSCALE_INSTANCE_TYPE)
	if err != nil {
		return nil, err
	}
	retOptions.InstanceTemplate, err = fromEnvOrError(EXOSCALE_INSTANCE_TEMPLATE)
	if err != nil {
		return nil, err
	}
	retOptions.DiskSizeGB, err = fromEnvOrError(EXOSCALE_DISK_SIZE_GB)
	if err != nil {
		return nil, err
	}

	// Return eraly if we're just doing init
	if init {
		return retOptions, nil
	}

	retOptions.MachineID, err = fromEnvOrError(MACHINE_ID)
	if err != nil {
		return nil, err
	}
	// prefix with devpod-
	retOptions.MachineID = "devpod-" + retOptions.MachineID

	retOptions.MachineFolder, err = fromEnvOrError(MACHINE_FOLDER)
	if err != nil {
		return nil, err
	}
	return retOptions, nil
}

func fromEnvOrError(name string) (string, error) {
	val := os.Getenv(name)
	if val == "" {
		return "", fmt.Errorf(
			"couldn't find option %s in environment, please make sure %s is defined",
			name,
			name,
		)
	}

	return val, nil
}
