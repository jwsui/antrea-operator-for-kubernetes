/* Copyright © 2020 VMware, Inc. All Rights Reserved.
   SPDX-License-Identifier: Apache-2.0 */

package config

import (
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	ocoperv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/cluster-network-operator/pkg/network"
	"github.com/openshift/cluster-network-operator/pkg/render"
	"gopkg.in/yaml.v2"
	ctrl "sigs.k8s.io/controller-runtime"

	operatorv1 "github.com/vmware/antrea-operator-for-kubernetes/api/v1"
	operatortypes "github.com/vmware/antrea-operator-for-kubernetes/controllers/types"
	"github.com/vmware/antrea-operator-for-kubernetes/version"
)

var log = ctrl.Log.WithName("config")

// TODO re-consider the implementation of functions in this package.

type ConfigOc struct{}

type ConfigK8s struct{}

func (c *ConfigOc) FillConfigs(clusterConfig *configv1.Network, operConfig *operatorv1.AntreaInstall) error {
	antreaAgentConfig := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(operConfig.Spec.AntreaAgentConfig), &antreaAgentConfig)
	if err != nil {
		return fmt.Errorf("failed to parse AntreaAgentConfig: %v", err)
	}

	// Set service CIDR.
	if len(clusterConfig.Spec.ServiceNetwork) == 0 {
		return fmt.Errorf("service network can not be empty")
	}
	serviceCIDR, ok := antreaAgentConfig[operatortypes.ServiceCIDROption]
	if ok {
		found := false
		for _, serviceNet := range clusterConfig.Spec.ServiceNetwork {
			if serviceNet == serviceCIDR {
				found = true
				break
			}
		}
		if !found {
			log.Info("WARNING: option: %s is overwritten by cluster config")
			antreaAgentConfig[operatortypes.ServiceCIDROption] = clusterConfig.Spec.ServiceNetwork[0]
		}
	} else {
		antreaAgentConfig[operatortypes.ServiceCIDROption] = clusterConfig.Spec.ServiceNetwork[0]
	}

	// Set default MTU.
	_, ok = antreaAgentConfig[operatortypes.DefaultMTUOption]
	if !ok {
		antreaAgentConfig[operatortypes.DefaultMTUOption] = operatortypes.DefaultMTU
	}

	// Set Antrea image.
	if operConfig.Spec.AntreaImage == "" {
		operConfig.Spec.AntreaImage = operatortypes.DefaultAntreaImage
	}

	updatedAntreaAgentConfig, err := yaml.Marshal(antreaAgentConfig)
	if err != nil {
		return fmt.Errorf("failed to fill configurations in AntreaAgentConfig: %v", err)
	}
	operConfig.Spec.AntreaAgentConfig = string(updatedAntreaAgentConfig)
	return nil
}

func (c *ConfigK8s) FillConfigs(operConfig *operatorv1.AntreaInstall) error {
	antreaAgentConfig := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(operConfig.Spec.AntreaAgentConfig), &antreaAgentConfig)
	if err != nil {
		return fmt.Errorf("failed to parse AntreaAgentConfig: %v", err)
	}

	// TODO get service cidr from k8s. api found?
	// TODO the lack of service cidr will lead to the defeat in validateconfig.

	// // Set service CIDR.
	// if len(clusterConfig.Spec.ServiceNetwork) == 0 {
	// 	return fmt.Errorf("service network can not be empty")
	// }
	// serviceCIDR, ok := antreaAgentConfig[operatortypes.ServiceCIDROption]
	// if ok {
	// 	found := false
	// 	for _, serviceNet := range clusterConfig.Spec.ServiceNetwork {
	// 		if serviceNet == serviceCIDR {
	// 			found = true
	// 			break
	// 		}
	// 	}
	// 	if !found {
	// 		log.Info("WARNING: option: %s is overwritten by cluster config")
	// 		antreaAgentConfig[operatortypes.ServiceCIDROption] = clusterConfig.Spec.ServiceNetwork[0]
	// 	}
	// } else {
	// 	antreaAgentConfig[operatortypes.ServiceCIDROption] = clusterConfig.Spec.ServiceNetwork[0]
	// }

	// Set default MTU.
	_, ok := antreaAgentConfig[operatortypes.DefaultMTUOption]
	if !ok {
		antreaAgentConfig[operatortypes.DefaultMTUOption] = operatortypes.DefaultMTU
	}

	// Set Antrea image.
	if operConfig.Spec.AntreaImage == "" {
		operConfig.Spec.AntreaImage = operatortypes.DefaultAntreaImage
	}

	updatedAntreaAgentConfig, err := yaml.Marshal(antreaAgentConfig)
	if err != nil {
		return fmt.Errorf("failed to fill configurations in AntreaAgentConfig: %v", err)
	}
	operConfig.Spec.AntreaAgentConfig = string(updatedAntreaAgentConfig)
	return nil
}

func (c *ConfigOc) ValidateConfig(clusterConfig *configv1.Network, operConfig *operatorv1.AntreaInstall) error {
	var errs []error

	// Validate antrea config
	antreaAgentConfig := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(operConfig.Spec.AntreaAgentConfig), &antreaAgentConfig)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to parse AntreaAgentConfig: %v", err))
	} else {
		serviceCIDR, ok := antreaAgentConfig[operatortypes.ServiceCIDROption].(string)
		if ok {
			found := false
			for _, serviceNet := range clusterConfig.Spec.ServiceNetwork {
				if serviceNet == serviceCIDR {
					found = true
					break
				}
			}
			if !found {
				errs = append(errs, fmt.Errorf("invalid serviceCIDR option: %s, available values are: %s", serviceCIDR, clusterConfig.Spec.ServiceNetwork))
			}
		} else {
			errs = append(errs, fmt.Errorf("serviceCIDR option can not be empty"))
		}
	}
	if operConfig.Spec.AntreaImage == "" {
		errs = append(errs, fmt.Errorf("antreaImage option can not be empty"))
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalidate configuration: %v", errs)
	}
	return nil
}

func (c *ConfigK8s) ValidateConfig(operConfig *operatorv1.AntreaInstall) error {
	var errs []error

	// Validate antrea config
	antreaAgentConfig := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(operConfig.Spec.AntreaAgentConfig), &antreaAgentConfig)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to parse AntreaAgentConfig: %v", err))
	} else {
		serviceCIDR, ok := antreaAgentConfig[operatortypes.ServiceCIDROption].(string)
		if ok {

			// TODO check the service cidr if necessary
			_ = serviceCIDR

			// found := false
			// for _, serviceNet := range clusterConfig.Spec.ServiceNetwork {
			// 	if serviceNet == serviceCIDR {
			// 		found = true
			// 		break
			// 	}
			// }
			// if !found {
			// 	errs = append(errs, fmt.Errorf("invalid serviceCIDR option: %s, available values are: %s", serviceCIDR, clusterConfig.Spec.ServiceNetwork))
			// }
		} else {
			errs = append(errs, fmt.Errorf("serviceCIDR option can not be empty"))
		}
	}
	if operConfig.Spec.AntreaImage == "" {
		errs = append(errs, fmt.Errorf("antreaImage option can not be empty"))
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalidate configuration: %v", errs)
	}
	return nil
}

func NeedApplyChange(preConfig, curConfig *operatorv1.AntreaInstall) (agentNeedChange, controllerNeedChange, imageChange bool) {
	if preConfig == nil {
		return true, true, false
	}

	if preConfig.Spec.AntreaAgentConfig != curConfig.Spec.AntreaAgentConfig {
		agentNeedChange = true
	}
	if preConfig.Spec.AntreaCNIConfig != curConfig.Spec.AntreaCNIConfig {
		agentNeedChange = true
	}
	if preConfig.Spec.AntreaControllerConfig != curConfig.Spec.AntreaControllerConfig {
		controllerNeedChange = true
	}
	if preConfig.Spec.AntreaImage != curConfig.Spec.AntreaImage {
		agentNeedChange = true
		controllerNeedChange = true
		imageChange = true
	}
	return
}

func HasClusterNetworkConfigChange(preConfig, curConfig *configv1.Network) bool {
	// TODO: We may need to save the applied cluster network config in somewhere else. Thus operator can
	// retrieve the applied config on restart.
	if preConfig == nil {
		return true
	}
	if !stringSliceEqual(preConfig.Spec.ServiceNetwork, curConfig.Spec.ServiceNetwork) {
		return true
	}
	var preCIDRs, curCIDRs []string
	for _, clusterNet := range preConfig.Spec.ClusterNetwork {
		preCIDRs = append(preCIDRs, clusterNet.CIDR)
	}
	for _, clusterNet := range curConfig.Spec.ClusterNetwork {
		curCIDRs = append(curCIDRs, clusterNet.CIDR)
	}
	if !stringSliceEqual(preCIDRs, curCIDRs) {
		return true
	}
	return false
}

func HasDefaultMTUChange(preConfig, curConfig *operatorv1.AntreaInstall) (bool, int, error) {

	curAntreaAgentConfig := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(curConfig.Spec.AntreaAgentConfig), &curAntreaAgentConfig)
	if err != nil {
		return false, operatortypes.DefaultMTU, err
	}
	curDefaultMTU, ok := curAntreaAgentConfig[operatortypes.DefaultMTUOption]
	if !ok {
		return false, operatortypes.DefaultMTU, fmt.Errorf("%s option can not be empty", operatortypes.DefaultMTUOption)
	}

	if preConfig == nil {
		return true, curDefaultMTU.(int), nil
	}

	preAntreaAgentConfig := make(map[string]interface{})
	err = yaml.Unmarshal([]byte(preConfig.Spec.AntreaAgentConfig), &preAntreaAgentConfig)
	if err != nil {
		return false, operatortypes.DefaultMTU, err
	}
	preDefaultMTU, ok := preAntreaAgentConfig[operatortypes.DefaultMTUOption]
	if !ok {
		return false, operatortypes.DefaultMTU, fmt.Errorf("%s option can not be empty", operatortypes.DefaultMTUOption)
	}

	return preDefaultMTU != curDefaultMTU, curDefaultMTU.(int), nil
}

func BuildNetworkStatus(clusterConfig *configv1.Network, defaultMTU int) *configv1.NetworkStatus {
	// Values extracted from spec are serviceNetwork and clusterNetworkCIDR.
	status := configv1.NetworkStatus{}
	for _, snet := range clusterConfig.Spec.ServiceNetwork {
		status.ServiceNetwork = append(status.ServiceNetwork, snet)
	}

	for _, cnet := range clusterConfig.Spec.ClusterNetwork {
		status.ClusterNetwork = append(status.ClusterNetwork,
			configv1.ClusterNetworkEntry{
				CIDR:       cnet.CIDR,
				HostPrefix: cnet.HostPrefix,
			})
	}
	status.NetworkType = clusterConfig.Spec.NetworkType
	status.ClusterNetworkMTU = defaultMTU
	return &status
}

func inSlice(str string, s []string) bool {
	for _, v := range s {
		if str == v {
			return true
		}
	}
	return false
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, v := range a {
		if !inSlice(v, b) {
			return false
		}
	}
	return true
}

// pluginCNIDir is the directory where plugins should install their CNI
// configuration file. By default, it is where multus looks, unless multus
// is disabled
func pluginCNIConfDir(conf *ocoperv1.NetworkSpec) string {
	if conf.DisableMultiNetwork == nil || !*conf.DisableMultiNetwork {
		return network.MultusCNIConfDir
	}
	return network.SystemCNIConfDir
}

func (c *ConfigK8s) GenerateRenderData(operConfig *operatorv1.AntreaInstall) (*render.RenderData, error) {
	renderData := render.MakeRenderData()

	renderData.Data[operatortypes.ReleaseVersion] = version.Version
	renderData.Data[operatortypes.AntreaAgentConfigRenderKey] = operConfig.Spec.AntreaAgentConfig
	renderData.Data[operatortypes.AntreaCNIConfigRenderKey] = operConfig.Spec.AntreaCNIConfig
	renderData.Data[operatortypes.AntreaControllerConfigRenderKey] = operConfig.Spec.AntreaControllerConfig
	renderData.Data[operatortypes.AntreaImageRenderKey] = operConfig.Spec.AntreaImage
	// TODO how to get cni conf dir in k8s?
	// renderData.Data[operatortypes.CNIConfDirRenderKey] = pluginCNIConfDir(&operatorNetwork.Spec)
	renderData.Data[operatortypes.CNIBinDirRenderKey] = network.CNIBinDir

	return &renderData, nil
}

func (c *ConfigOc) GenerateRenderData(operatorNetwork *ocoperv1.Network, operConfig *operatorv1.AntreaInstall) (*render.RenderData, error) {
	renderData := render.MakeRenderData()

	renderData.Data[operatortypes.ReleaseVersion] = version.Version
	renderData.Data[operatortypes.AntreaAgentConfigRenderKey] = operConfig.Spec.AntreaAgentConfig
	renderData.Data[operatortypes.AntreaCNIConfigRenderKey] = operConfig.Spec.AntreaCNIConfig
	renderData.Data[operatortypes.AntreaControllerConfigRenderKey] = operConfig.Spec.AntreaControllerConfig
	renderData.Data[operatortypes.AntreaImageRenderKey] = operConfig.Spec.AntreaImage
	renderData.Data[operatortypes.CNIConfDirRenderKey] = pluginCNIConfDir(&operatorNetwork.Spec)
	renderData.Data[operatortypes.CNIBinDirRenderKey] = network.CNIBinDir

	return &renderData, nil
}
