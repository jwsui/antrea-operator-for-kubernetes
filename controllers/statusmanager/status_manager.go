/* Copyright © 2020 VMware, Inc. All Rights Reserved.
   SPDX-License-Identifier: Apache-2.0 */

package statusmanager

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/config/clusteroperator/v1helpers"
	"github.com/vmware/antrea-operator-for-kubernetes/version"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/vmware/antrea-operator-for-kubernetes/api/v1"
	operatortypes "github.com/vmware/antrea-operator-for-kubernetes/controllers/types"
)

var log = logf.Log.WithName("status_manager")

type StatusLevel int

const (
	ClusterConfig StatusLevel = iota
	OperatorConfig
	PodDeployment
	RolloutHung
	ClusterNode
	maxStatusLevel
)

// TODO check the interfaces commented in Adaptor
type Adaptor interface {
	// getLastPodState(status *StatusManager) (map[types.NamespacedName]daemonsetState, map[types.NamespacedName]deploymentState)
	// setLastPodState(status *StatusManager, dss map[types.NamespacedName]daemonsetState, deps map[types.NamespacedName]deploymentState) error
	set(status *StatusManager, reachedAvailableLevel bool, conditions ...configv1.ClusterOperatorStatusCondition)
}

// Status coordinates changes to AntreaInstall.status and ClusterOperator.Status
type StatusManager struct {
	sync.Mutex

	client  client.Client
	mapper  meta.RESTMapper
	name    string
	version string

	failing [maxStatusLevel]*configv1.ClusterOperatorStatusCondition

	daemonSets  []types.NamespacedName
	deployments []types.NamespacedName

	OperatorNamespace string
	AdaptorName       string
	Adaptor
}

// TODO Why Status needed?
type Status struct{}

type StatusK8s struct {
	Status
}

type StatusOc struct {
	Status
}

// TODO check if this interface necessary
func (status *StatusManager) setConditions(progressing []string, reachedAvailableLevel bool) {
	conditions := make([]configv1.ClusterOperatorStatusCondition, 0, 2)
	if len(progressing) > 0 {
		conditions = append(conditions,
			configv1.ClusterOperatorStatusCondition{
				Type:    configv1.OperatorProgressing,
				Status:  configv1.ConditionTrue,
				Reason:  "Deploying",
				Message: strings.Join(progressing, "\n"),
			},
		)
	} else {
		conditions = append(conditions,
			configv1.ClusterOperatorStatusCondition{
				Type:   configv1.OperatorProgressing,
				Status: configv1.ConditionFalse,
			},
		)
	}
	if reachedAvailableLevel {
		conditions = append(conditions,
			configv1.ClusterOperatorStatusCondition{
				Type:   configv1.OperatorAvailable,
				Status: configv1.ConditionTrue,
			},
		)
	}

	status.set(status, reachedAvailableLevel, conditions...)
}

// Set updates the AntreaInstall.Status with the provided conditions
func (adaptor *StatusK8s) set(status *StatusManager, reachedAvailableLevel bool, conditions ...configv1.ClusterOperatorStatusCondition) {
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// ncpInstall := &operatorv1.NcpInstall{}
		antreaInstall := &operatorv1.AntreaInstall{}
		err := status.client.Get(context.TODO(), types.NamespacedName{Namespace: operatortypes.OperatorNameSpace, Name: operatortypes.OperatorConfigName}, antreaInstall)
		if err != nil {
			log.Error(err, "Failed to get ncpInstall")
			return err
		}
		co := &configv1.ClusterOperator{ObjectMeta: metav1.ObjectMeta{Name: status.name}}

		oldStatus := antreaInstall.Status.DeepCopy()

		if reachedAvailableLevel {
			co.Status.Versions = []configv1.OperandVersion{
				{Name: "operator", Version: version.Version},
			}
		}
		status.CombineConditions(&co.Status.Conditions, &conditions)

		progressingCondition := v1helpers.FindStatusCondition(co.Status.Conditions, configv1.OperatorProgressing)
		availableCondition := v1helpers.FindStatusCondition(co.Status.Conditions, configv1.OperatorAvailable)
		if availableCondition == nil && progressingCondition != nil && progressingCondition.Status == configv1.ConditionTrue {
			v1helpers.SetStatusCondition(&co.Status.Conditions,
				configv1.ClusterOperatorStatusCondition{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionFalse,
					Reason:  "Startup",
					Message: "The network is starting up",
				},
			)
		}

		if reflect.DeepEqual(*oldStatus, co.Status) {
			return nil
		}

		// Set status to ncp-install CRD
		err = status.setAntreaInstallStatus(&co.Status.Conditions)
		return err
	})
	if err != nil {
		log.Error(err, "Failed to set NcpInstall")
	}
}

// Set updates the ClusterOperator.Status with the provided conditions
func (adaptor *StatusOc) set(status *StatusManager, reachedAvailableLevel bool, conditions ...configv1.ClusterOperatorStatusCondition) {
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		co := &configv1.ClusterOperator{ObjectMeta: metav1.ObjectMeta{Name: status.name}}
		err := status.client.Get(context.TODO(), types.NamespacedName{Name: status.name}, co)
		isNotFound := errors.IsNotFound(err)
		if err != nil && !isNotFound {
			return err
		}

		oldStatus := co.Status.DeepCopy()

		if reachedAvailableLevel {
			co.Status.Versions = []configv1.OperandVersion{
				{Name: "operator", Version: version.Version},
			}
		}
		status.CombineConditions(&co.Status.Conditions, &conditions)

		progressingCondition := v1helpers.FindStatusCondition(co.Status.Conditions, configv1.OperatorProgressing)
		availableCondition := v1helpers.FindStatusCondition(co.Status.Conditions, configv1.OperatorAvailable)
		if availableCondition == nil && progressingCondition != nil && progressingCondition.Status == configv1.ConditionTrue {
			v1helpers.SetStatusCondition(&co.Status.Conditions,
				configv1.ClusterOperatorStatusCondition{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionFalse,
					Reason:  "Startup",
					Message: "The network is starting up",
				},
			)
		}

		v1helpers.SetStatusCondition(&co.Status.Conditions,
			configv1.ClusterOperatorStatusCondition{
				Type:   configv1.OperatorUpgradeable,
				Status: configv1.ConditionTrue,
			},
		)

		if reflect.DeepEqual(*oldStatus, co.Status) {
			return nil
		}

		buf, err := yaml.Marshal(co.Status.Conditions)
		if err != nil {
			buf = []byte(fmt.Sprintf("(failed to convert to YAML: %s)", err))
		}
		if isNotFound {
			if err := status.client.Create(context.TODO(), co); err != nil {
				return err
			}
			log.Info(fmt.Sprintf("Created ClusterOperator with conditions:\n%s", string(buf)))
			return nil
		}
		if err := status.client.Status().Update(context.TODO(), co); err != nil {
			return err
		}
		log.Info(fmt.Sprintf("Updated ClusterOperator with conditions:\n%s", string(buf)))
		// Set status to ncp-install CRD
		err = status.setAntreaInstallStatus(&co.Status.Conditions)
		return err
	})
	if err != nil {
		log.Error(err, "Failed to set ClusterOperator")
	}
}

func (status *StatusManager) setAntreaInstallStatus(conditions *[]configv1.ClusterOperatorStatusCondition) error {
	antreaInstall := &operatorv1.AntreaInstall{}
	err := status.client.Get(context.TODO(), types.NamespacedName{Namespace: operatortypes.OperatorNameSpace, Name: operatortypes.OperatorConfigName}, antreaInstall)
	if err != nil {
		log.Error(err, "failed to get AntreaInstall")
		return err
	}
	antreaInstallPatch := client.MergeFrom(antreaInstall.DeepCopy())
	antreaInstall.Status.Conditions = *conditions
	if err := status.client.Status().Patch(context.TODO(), antreaInstall, antreaInstallPatch); err != nil {
		log.Error(err, "failed to set AntreaInstall")
		return err
	}
	return err
}

/** TODO should be removed.
func SetAntreaInstallDegraded(cl client.Client, reason, message string) {
	SetAntreaInstallStatus(cl, configv1.OperatorDegraded, configv1.ConditionTrue, time.Now(), reason, message)
}

func SetAntreaInstallNotDegraded(cl client.Client) {
	SetAntreaInstallStatus(cl, configv1.OperatorDegraded, configv1.ConditionFalse, time.Now(), "", "")
}

// TODO deprecated!
func SetDegraded(cl client.Client, status *statusmanager.StatusManager, statusLevel statusmanager.StatusLevel, reason, message string) {
	// Set clusteroperator/antrea status
	status.SetDegraded(statusLevel, reason, message)
	// Set AntreaInstall CR status
	SetAntreaInstallDegraded(cl, reason, message)
}

// TODO deprecated!
func SetNotDegraded(cl client.Client, status *statusmanager.StatusManager, statusLevel statusmanager.StatusLevel) {
	// Set clusteroperator/antrea status
	status.SetNotDegraded(statusLevel)
	// Set AntreaInstall CR status
	SetAntreaInstallNotDegraded(cl)
}
*/

func (status *StatusManager) CombineConditions(conditions *[]configv1.ClusterOperatorStatusCondition,
	newConditions *[]configv1.ClusterOperatorStatusCondition) (bool, string) {
	messages := ""
	changed := false
	for _, newCondition := range *newConditions {
		existingCondition := v1helpers.FindStatusCondition(*conditions, newCondition.Type)
		if existingCondition == nil {
			v1helpers.SetStatusCondition(conditions, newCondition)
			messages += fmt.Sprintf("%v. ", newCondition)
			changed = true
		} else if existingCondition.Status != newCondition.Status ||
			existingCondition.Reason != newCondition.Reason ||
			existingCondition.Message != newCondition.Message {
			v1helpers.SetStatusCondition(conditions, newCondition)
			messages += fmt.Sprintf("%v. ", newCondition)
			changed = true
		}
	}
	return changed, messages
}

func (status *StatusManager) SetFromPods() {

}
