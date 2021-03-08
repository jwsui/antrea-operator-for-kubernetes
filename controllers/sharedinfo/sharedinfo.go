/* Copyright © 2020 VMware, Inc. All Rights Reserved.
   SPDX-License-Identifier: Apache-2.0 */

package sharedinfo

import (
	"context"
	"sync"

	operatorv1 "github.com/vmware/antrea-operator-for-kubernetes/api/v1"
	operatortypes "github.com/vmware/antrea-operator-for-kubernetes/controllers/types"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var log = logf.Log.WithName("shared_info")

type SharedInfo struct {
	sync.Mutex

	AdaptorName string

	AntreaAgentDaemonSetSpec       *unstructured.Unstructured
	AntreaControllerDeploymentSpec *unstructured.Unstructured
}

func New(mgr manager.Manager) (*SharedInfo, error) {
	reader := mgr.GetAPIReader()
	antreaInstallName := types.NamespacedName{
		Name:      operatortypes.OperatorConfigName,
		Namespace: operatortypes.OperatorNameSpace,
	}
	antreaInstall := &operatorv1.AntreaInstall{}
	err := reader.Get(context.TODO(), antreaInstallName, antreaInstall)
	if err != nil {
		log.Error(err, "Failed to get ncp-install")
		return nil, err
	}
	// TODO just set to kubernetes before antrea platform pr is completed.
	return &SharedInfo{AdaptorName: "kubernetes"}, nil
	// return &SharedInfo{AdaptorName: antreaInstall.Spec.AntreaPlatform}, nil
}
