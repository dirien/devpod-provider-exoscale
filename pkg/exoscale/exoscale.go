package exoscale

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/dirien/devpod-provider-exoscale/pkg/options"
	v3 "github.com/exoscale/egoscale/v3"
	"github.com/exoscale/egoscale/v3/credentials"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/loft-sh/devpod/pkg/client"
	"github.com/loft-sh/devpod/pkg/ssh"
	"github.com/loft-sh/log"
	"github.com/pkg/errors"
)

type ExoscaleProvider struct {
	Config           *options.Options
	ClientV3         *v3.Client
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

	clientv3, err := v3.NewClient(credentials.NewStaticCredentials(apiKey, apiSecret))
	if err != nil {
		return nil, err
	}
	return &ExoscaleProvider{
		ClientV3: clientv3,
		Log:      logs,
		Config:   config,
	}, nil
}

func GetDevpodInstance(ctx context.Context, exoscaleProvider *ExoscaleProvider) (*v3.Instance, error) {
	instances, err := exoscaleProvider.ClientV3.ListInstances(ctx)
	if err != nil {
		return nil, err
	}
	var instanceID v3.UUID
	for _, instance := range instances.Instances {
		if strings.Contains(instance.Name, exoscaleProvider.Config.MachineID) {
			exoscaleProvider.Log.Debugf("Found instance %v\n", instance.Name)
			instanceID = instance.ID
			break
		}
	}
	if instanceID == "" {
		return nil, fmt.Errorf("instance not found")
	}

	instance, err := exoscaleProvider.ClientV3.GetInstance(ctx, instanceID)
	if err != nil {
		return nil, fmt.Errorf("get instance: %w", err)
	}
	return instance, nil
}

func Init(ctx context.Context, exoscaleProvider *ExoscaleProvider) error {
	_, err := exoscaleProvider.ClientV3.ListZones(ctx)
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
package_update: true
package_upgrade: true

groups:
  - docker

system_info:
  default_user:
    groups: [ docker ]

packages:
  - apt-transport-https
  - ca-certificates
  - curl
  - gnupg
  - lsb-release
  - unattended-upgrades

runcmd:
  - mkdir -p /etc/apt/keyrings
  - curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  - echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  - apt-get update
  - apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
  - systemctl enable docker
  - systemctl start docker
users:
- name: devpod
  shell: /bin/bash
  groups: [ sudo, docker ]
  ssh_authorized_keys:
  - %s
  sudo: [ "ALL=(ALL) NOPASSWD:ALL" ]`, publicKey)

	data := base64.StdEncoding.EncodeToString([]byte(userData))
	exoscaleProvider.Log.Debugf("User data: %s", userData)
	size, _ := strconv.Atoi(exoscaleProvider.Config.DiskSizeGB)
	sizeGB := int64(size)

	instanceTypes, err := exoscaleProvider.ClientV3.ListInstanceTypes(ctx)
	if err != nil {
		return err
	}
	var instanceTypeID v3.UUID
	for _, instanceType := range instanceTypes.InstanceTypes {
		if strings.Contains(string(instanceType.Size), exoscaleProvider.Config.InstanceType) {
			exoscaleProvider.Log.Infof("Found instance type %v", instanceType.Size)
			instanceTypeID = instanceType.ID
			break
		}
	}

	listTemplates, err := exoscaleProvider.ClientV3.ListTemplates(ctx)
	if err != nil {
		return err
	}
	var templateID v3.UUID
	for _, template := range listTemplates.Templates {
		if strings.Contains(template.Name, exoscaleProvider.Config.InstanceTemplate) {
			exoscaleProvider.Log.Infof("Found template %v", template.Name)
			templateID = template.ID
			break
		}
	}

	sshPort := int64(22)
	groupOperation, err := exoscaleProvider.ClientV3.CreateSecurityGroup(ctx, v3.CreateSecurityGroupRequest{
		Name:        fmt.Sprintf("%s-sg", exoscaleProvider.Config.MachineID),
		Description: fmt.Sprintf("Security group for %s", exoscaleProvider.Config.MachineID),
	})
	if err != nil {
		return err
	}

	securityGroup, err := exoscaleProvider.ClientV3.GetSecurityGroup(ctx, groupOperation.Reference.ID)
	if err != nil {
		return err
	}

	_, err = exoscaleProvider.ClientV3.AddExternalSourceToSecurityGroup(ctx, securityGroup.ID, v3.AddExternalSourceToSecurityGroupRequest{
		Cidr: "0.0.0.0/0",
	})
	if err != nil {
		return err
	}
	_, err = exoscaleProvider.ClientV3.AddRuleToSecurityGroup(ctx, securityGroup.ID, v3.AddRuleToSecurityGroupRequest{
		FlowDirection: "ingress",
		Protocol:      "tcp",
		StartPort:     sshPort,
		EndPort:       sshPort,
		Description:   "SSH",
		SecurityGroup: &v3.SecurityGroupResource{
			ID: securityGroup.ID,
		},
	})
	if err != nil {
		return err
	}

	groupIDs := []v3.SecurityGroup{*securityGroup}

	instance := v3.CreateInstanceRequest{
		Name: exoscaleProvider.Config.MachineID,
		Template: &v3.Template{
			ID: templateID,
		},
		InstanceType: &v3.InstanceType{
			ID: instanceTypeID,
		},
		DiskSize:           sizeGB,
		UserData:           data,
		PublicIPAssignment: "inet4",
		SecurityGroups:     groupIDs,
	}

	_, err = exoscaleProvider.ClientV3.CreateInstance(ctx, instance)
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
	delOperation, err := exoscaleProvider.ClientV3.DeleteInstance(ctx, devPodInstance.ID)
	if err != nil {
		return err
	}
	status := delOperation.State
	for status == "pending" {
		delOperation, err = exoscaleProvider.ClientV3.GetOperation(ctx, delOperation.ID)
		if err != nil {
			return err
		}
		status = delOperation.State
	}

	securityGroupId := (devPodInstance.SecurityGroups)[0]

	_, err = exoscaleProvider.ClientV3.DeleteSecurityGroup(ctx, securityGroupId.ID)
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
	_, err = exoscaleProvider.ClientV3.StartInstance(ctx, devPodInstance.ID, v3.StartInstanceRequest{})
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
	case devPodInstance.State == "running":
		return client.StatusRunning, nil
	case devPodInstance.State == "stopped":
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

	_, err = exoscaleProvider.ClientV3.StopInstance(ctx, devPodInstance.ID)
	if err != nil {
		return err
	}
	return nil
}
