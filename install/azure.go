// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package install

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

type azureVersionValidation struct{}

func (m *azureVersionValidation) Name() string {
	return "az-binary"
}

func (m *azureVersionValidation) Check(ctx context.Context, k *K8sInstaller) error {
	cmd := azCommand("version")
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("unable to execute \"az version\": %w", err)
	}

	k.Log("✅ Detected az binary")

	return nil
}

type accountInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type azurePrincipalOutput struct {
	AppID       string `json:"appId"`
	DisplayName string `json:"displayName"`
	Name        string `json:"name"`
	Password    string `json:"password"`
	Tenant      string `json:"tenant"`
}

type aksClusterInfo struct {
	NodeResourceGroup string `json:"nodeResourceGroup"`
}

func (k *K8sInstaller) aksSetup(ctx context.Context) error {
	if err := k.azureRetrieveSubscriptionID(ctx); err != nil {
		return err
	}

	if err := k.azureRetrieveAKSNodeResourceGroup(ctx); err != nil {
		return err
	}

	return k.azureSetupServicePrincipal(ctx)
}

func (k *K8sInstaller) azureRetrieveSubscriptionID(ctx context.Context) error {
	args := []string{"account", "show"}
	if k.params.Azure.SubscriptionName != "" {
		args = append(args, "--subscription", k.params.Azure.SubscriptionName)
	}
	cmd := azCommand(args...)
	bytes, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("unable to execute \"az %s\": %w", args, err)
	}

	ai := accountInfo{}
	if err := json.Unmarshal(bytes, &ai); err != nil {
		return fmt.Errorf("unable to unmarshal az output: %w", err)
	}

	k.Log("✅ Derived Azure subscription ID %s from subscription %s", ai.ID, ai.Name)
	k.params.Azure.SubscriptionID = ai.ID

	return nil
}

func (k *K8sInstaller) azureRetrieveAKSNodeResourceGroup(ctx context.Context) error {
	/*
		`az aks create` requires an existing resource group in which to create a
		new AKS cluster, but a single resource group may hold multiple AKS clusters.

		Internally, AKS creates an intermediate resource group (named
		`MC_{RG_name}_{cluster_name}_{location}`) to regroup all AKS nodes for
		this cluster.

		The CLI installs itself into this intermediate resource group, and thus
		derives it from the user-given resource group and cluster name using
		`az aks show`.
	*/
	args := []string{"aks", "show", "--subscription", k.params.Azure.SubscriptionID, "--resource-group", k.params.Azure.ResourceGroupName, "--name", k.params.ClusterName}
	cmd := azCommand(args...)
	bytes, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("unable to execute \"az %s\": %w", args, err)
	}

	clusterInfo := aksClusterInfo{}
	if err := json.Unmarshal(bytes, &clusterInfo); err != nil {
		return fmt.Errorf("unable to unmarshal az output: %w", err)
	}

	k.Log("✅ Derived Azure AKS node resource group %s from resource group %s", clusterInfo.NodeResourceGroup, k.params.Azure.ResourceGroupName)
	k.params.Azure.AksNodeResourceGroup = clusterInfo.NodeResourceGroup

	return nil
}

func (k *K8sInstaller) azureSetupServicePrincipal(ctx context.Context) error {
	if k.params.Azure.TenantID == "" && k.params.Azure.ClientID == "" && k.params.Azure.ClientSecret == "" {
		k.Log("🚀 Creating Azure Service Principal for Cilium operator...")
		/*
			Since user did not provide a pre-existing Service Principal, automatically create a new Service Principal
			and restrict its scope to the strict minimum (i.e. the AKS node resource group in which Cilium will be installed).
			We create a new Service Principal for each installation by design:
			- Having dedicated SPs with minimal privileges over their own AKS clusters is more secure.
			- Even if we wanted to re-use pre-existing SPs, it would not be possible:
				- The ClientSecret (password) of an SP is only displayed at creation time, and cannot be
					retrieved at a later time.
				- Specifying a name (--name) when creating a SP creates a new SP on first call, but then
					overwrites the existing SP with a new ClientSecret on subsequent calls, which potentially
					interferes with existing installations.
		*/
		args := []string{"ad", "sp", "create-for-rbac", "--scopes", "/subscriptions/" + k.params.Azure.SubscriptionID + "/resourceGroups/" + k.params.Azure.AksNodeResourceGroup}
		cmd := azCommand(args...)
		bytes, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("unable to execute \"az %s\": %w", args, err)
		}

		p := azurePrincipalOutput{}
		if err := json.Unmarshal(bytes, &p); err != nil {
			return fmt.Errorf("unable to unmarshal az output: %w", err)
		}

		k.Log("✅ Created Azure Service Principal for Cilium operator with App ID %s and Tenant ID %s", p.AppID, p.Tenant)
		k.Log("ℹ️ Its RBAC privileges are restricted to the AKS node resource group %s", k.params.Azure.AksNodeResourceGroup)
		k.params.Azure.TenantID = p.Tenant
		k.params.Azure.ClientID = p.AppID
		k.params.Azure.ClientSecret = p.Password
	} else {
		if k.params.Azure.TenantID == "" || k.params.Azure.ClientID == "" || k.params.Azure.ClientSecret == "" {
			k.Log(`❌ All three parameters are required for using an existing Azure Service Principal:
   - Tenant ID (--azure-tenant-id)
   - Client ID (--azure-client-id)
   - Client Secret (--azure-client-secret)`)
			return fmt.Errorf("missing at least one of Azure Service Principal parameters")
		}

		k.Log("✅ Using manually configured Azure Service Principal for Cilium operator with App ID %s and Tenant ID %s",
			k.params.Azure.ClientID, k.params.Azure.TenantID)
	}

	return nil
}

// azCommand is a wrapper function around running the "az" binary. It forces
// all output to be in JSON.
func azCommand(args ...string) *exec.Cmd {
	all := append([]string{}, args...)
	all = append(all, "--output", "json")
	return exec.Command("az", all...)
}
