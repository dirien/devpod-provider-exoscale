package exoscale

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/dirien/devpod-provider-exoscale/pkg/options"
	v2 "github.com/exoscale/egoscale/v2"
	exoapi "github.com/exoscale/egoscale/v2/api"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/loft-sh/devpod/pkg/client"
	"github.com/loft-sh/devpod/pkg/ssh"
	"github.com/loft-sh/log"
	"github.com/pkg/errors"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type ExoscaleProvider struct {
	Config   *options.Options
	ClientV2 *v2.Client
	//Client           *egoscale.Client
	Log              log.Logger
	WorkingDirectory string
}

func StringPtr(v string) *string {
	return &v
}

type defaultTransport struct {
	next http.RoundTripper
}

var userAgent string

func (t *defaultTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", userAgent)

	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func NewProvider(logs log.Logger, init bool) (*ExoscaleProvider, error) {
	config, err := options.FromEnv(init)

	if err != nil {
		return nil, err
	}

	httpClient := cleanhttp.DefaultPooledClient()
	httpClient.Transport = &defaultTransport{next: httpClient.Transport}

	apiKey := os.Getenv("EXOSCALE_API_KEY")
	if apiKey == "" {
		return nil, errors.Errorf("EXOSCALE_API_KEY is not set")
	}

	apiSecret := os.Getenv("EXOSCALE_API_SECRET")
	if apiSecret == "" {
		return nil, errors.Errorf("EXOSCALE_API_SECRET is not set")
	}

	/*
		client := egoscale.NewClient("https://api.exoscale.com/v1", apiKey, apiSecret,
			egoscale.WithHTTPClient(httpClient),
			egoscale.WithoutV2Client())
	*/
	clientv2, err := v2.NewClient(apiKey, apiSecret)
	if err != nil {
		return nil, err
	}
	return &ExoscaleProvider{
		//Client:   client,
		ClientV2: clientv2,
		Log:      logs,
		Config:   config,
	}, nil
}

func GetDevpodInstance(ctx context.Context, exoscaleProvider *ExoscaleProvider) (*v2.Instance, error) {
	instances, err := exoscaleProvider.ClientV2.ListInstances(ctx, exoscaleProvider.Config.Zone)
	if err != nil {
		return nil, err
	}
	var instanceID *string
	for _, instance := range instances {
		if strings.Contains(*instance.Name, exoscaleProvider.Config.MachineID) {
			fmt.Printf("Found instance %v\n", *instance.Name)
			instanceID = instance.ID
			break
		}
	}
	if instanceID == nil {
		return nil, fmt.Errorf("instance not found")
	}

	instance, err := exoscaleProvider.ClientV2.GetInstance(ctx, exoscaleProvider.Config.Zone, *instanceID)
	if err != nil {
		return nil, fmt.Errorf("get instance: %w", err)
	}
	return instance, nil
}

func Init(ctx context.Context, exoscaleProvider *ExoscaleProvider) error {
	_, err := exoscaleProvider.ClientV2.ListZones(ctx)
	if err != nil {
		return err
	}
	return nil
}

func Create(ctx context.Context, exoscaleProvider *ExoscaleProvider) error {
	publicKeyBase, err := ssh.GetPublicKeyBase(exoscaleProvider.Config.MachineFolder)
	if err != nil {
		return err
	}
	publicKey, err := base64.StdEncoding.DecodeString(publicKeyBase)
	if err != nil {
		return err
	}

	userData := fmt.Sprintf(`#cloud-config
users:
- name: devpod
  shell: /bin/bash
  groups: [ sudo, docker ]
  ssh_authorized_keys:
  - %s
  sudo: [ "ALL=(ALL) NOPASSWD:ALL" ]`, publicKey)

	fmt.Println(userData)
	data := base64.StdEncoding.EncodeToString([]byte(userData))
	fmt.Println(data)
	size, _ := strconv.Atoi(exoscaleProvider.Config.DiskSizeGB)
	sizeGB := int64(size)

	instanceTypes, err := exoscaleProvider.ClientV2.ListInstanceTypes(ctx, exoscaleProvider.Config.Zone)
	if err != nil {
		return err
	}
	var instanceTypeID *string
	for _, instanceType := range instanceTypes {
		if strings.Contains(*instanceType.Size, exoscaleProvider.Config.InstanceType) {
			exoscaleProvider.Log.Infof("Found instance type %v", *instanceType.Size)
			instanceTypeID = instanceType.ID
			break
		}
	}

	listTemplates, err := exoscaleProvider.ClientV2.ListTemplates(ctx, exoscaleProvider.Config.Zone)
	if err != nil {
		return err
	}
	var templateID *string
	for _, template := range listTemplates {
		if strings.Contains(*template.Family, exoscaleProvider.Config.InstanceTemplate) {
			exoscaleProvider.Log.Infof("Found template %v", *template.Name)
			templateID = template.ID
			break
		}
	}

	ctx2 := exoapi.WithEndpoint(ctx, exoapi.NewReqEndpoint("", exoscaleProvider.Config.Zone))

	sshPort := uint16(22)
	group, err := exoscaleProvider.ClientV2.CreateSecurityGroup(ctx2, exoscaleProvider.Config.Zone, &v2.SecurityGroup{
		Name:        StringPtr(fmt.Sprintf("%s-sg", exoscaleProvider.Config.MachineID)),
		Description: StringPtr(fmt.Sprintf("Security group for %s", exoscaleProvider.Config.MachineID)),
	})
	if err != nil {
		return err
	}
	err = exoscaleProvider.ClientV2.AddExternalSourceToSecurityGroup(ctx2, exoscaleProvider.Config.Zone, group, "0.0.0.0/0")
	if err != nil {
		return err
	}
	_, err = exoscaleProvider.ClientV2.CreateSecurityGroupRule(ctx2, exoscaleProvider.Config.Zone, group, &v2.SecurityGroupRule{
		FlowDirection:   StringPtr("ingress"),
		Protocol:        StringPtr("tcp"),
		StartPort:       &sshPort,
		EndPort:         &sshPort,
		SecurityGroupID: group.ID,
		Description:     StringPtr("SSH"),
	})
	if err != nil {
		return err
	}

	groupIDs := []string{*group.ID}

	instance := v2.Instance{
		Name:               &exoscaleProvider.Config.MachineID,
		InstanceTypeID:     instanceTypeID,
		TemplateID:         templateID,
		Zone:               &exoscaleProvider.Config.Zone,
		DiskSize:           &sizeGB,
		UserData:           &data,
		PublicIPAssignment: StringPtr("inet4"),
		SecurityGroupIDs:   &groupIDs,
	}

	_, err = exoscaleProvider.ClientV2.CreateInstance(ctx, exoscaleProvider.Config.Zone, &instance)
	if err != nil {
		return err
	}
	return nil
}

func Delete(ctx context.Context, exoscaleProvider *ExoscaleProvider) error {
	devPodInstance, err := GetDevpodInstance(ctx, exoscaleProvider)
	if err != nil {
		return err
	}
	err = exoscaleProvider.ClientV2.DeleteInstance(ctx, exoscaleProvider.Config.Zone, devPodInstance)
	if err != nil {
		return err
	}
	securityGroupId := (*devPodInstance.SecurityGroupIDs)[0]

	err = exoscaleProvider.ClientV2.DeleteSecurityGroup(ctx, exoscaleProvider.Config.Zone, &v2.SecurityGroup{
		ID: &securityGroupId,
	})
	if err != nil {
		return err
	}

	return nil
}

func Start(ctx context.Context, exoscaleProvider *ExoscaleProvider) error {
	devPodInstance, err := GetDevpodInstance(ctx, exoscaleProvider)
	if err != nil {
		return err
	}
	err = exoscaleProvider.ClientV2.StartInstance(ctx, exoscaleProvider.Config.Zone, devPodInstance)
	if err != nil {
		return err
	}

	return nil
}

func Status(ctx context.Context, exoscaleProvider *ExoscaleProvider) (client.Status, error) {
	devPodInstance, err := GetDevpodInstance(ctx, exoscaleProvider)
	if err != nil {
		return client.StatusNotFound, nil
	}
	switch {
	case *devPodInstance.State == "running":
		return client.StatusRunning, nil
	case *devPodInstance.State == "stopped":
		return client.StatusStopped, nil
	default:
		return client.StatusBusy, nil
	}
}

func Stop(ctx context.Context, exoscaleProvider *ExoscaleProvider) error {
	devPodInstance, err := GetDevpodInstance(ctx, exoscaleProvider)
	if err != nil {
		return err
	}

	err = exoscaleProvider.ClientV2.StopInstance(ctx, exoscaleProvider.Config.Zone, devPodInstance)
	if err != nil {
		return err
	}
	return nil
}
