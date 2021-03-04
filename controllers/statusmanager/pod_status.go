/* Copyright © 2020 VMware, Inc. All Rights Reserved.
   SPDX-License-Identifier: Apache-2.0 */

// code from https://github.com/openshift/cluster-network-operator/blob/bfc8b01b1ec4d7e5b0cd6423fe75daef945c3cbe/pkg/controller/statusmanager/pod_status.go

package statusmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// if a rollout has not made any progress by this time,
	// mark ourselves as Degraded
	ProgressTimeout = 10 * time.Minute

	// lastSeenAnnotation - the annotation where we stash our state
	lastSeenAnnotation = "network.operator.openshift.io/last-seen-state"
)

// podState is a snapshot of the last-seen-state and last-changed-times
// for pod-creating entities, as marshalled to json in an annotation
type podState struct {
	// "public" for marshalling to json, since we can't have complex keys
	DaemonsetStates  []daemonsetState
	DeploymentStates []deploymentState
}

// daemonsetState is the internal state we use to check if a rollout has
// stalled.
type daemonsetState struct {
	types.NamespacedName

	LastSeenStatus appsv1.DaemonSetStatus
	LastChangeTime time.Time
}

// deploymentState is the same as daemonsetState.. but for deployments!
type deploymentState struct {
	types.NamespacedName

	LastSeenStatus appsv1.DeploymentStatus
	LastChangeTime time.Time
}

// SetFromPods sets the operator Degraded/Progressing/Available status, based on
// the current status of the manager's DaemonSets and Deployments.
func (status *StatusManager) SetFromPods() {
	status.Lock()
	defer status.Unlock()

	reachedAvailableLevel := (len(status.daemonSets) + len(status.deployments)) > 0
	progressing := []string{}
	hung := []string{}

	daemonsetStates, deploymentStates := status.getLastPodState(status)

	for _, dsName := range status.daemonSets {
		ds := &appsv1.DaemonSet{}
		if err := status.client.Get(context.TODO(), dsName, ds); err != nil {
			log.Error(err, fmt.Sprintf("Error getting DaemonSet %q", dsName.String()))
			progressing = append(progressing, fmt.Sprintf("Waiting for DaemonSet %q to be created", dsName.String()))
			reachedAvailableLevel = false
			continue
		}

		dsProgressing := false

		if ds.Status.UpdatedNumberScheduled < ds.Status.DesiredNumberScheduled {
			progressing = append(progressing, fmt.Sprintf("DaemonSet %q update is rolling out (%d out of %d updated)", dsName.String(), ds.Status.UpdatedNumberScheduled, ds.Status.DesiredNumberScheduled))
			dsProgressing = true
		} else if ds.Status.NumberUnavailable > 0 {
			progressing = append(progressing, fmt.Sprintf("DaemonSet %q is not available (awaiting %d nodes)", dsName.String(), ds.Status.NumberUnavailable))
			dsProgressing = true
		} else if ds.Status.NumberAvailable == 0 { // NOTE: update this if we ever expect empty (unscheduled) daemonsets ~cdc
			progressing = append(progressing, fmt.Sprintf("DaemonSet %q is not yet scheduled on any nodes", dsName.String()))
			dsProgressing = true
		} else if ds.Generation > ds.Status.ObservedGeneration {
			progressing = append(progressing, fmt.Sprintf("DaemonSet %q update is being processed (generation %d, observed generation %d)", dsName.String(), ds.Generation, ds.Status.ObservedGeneration))
			dsProgressing = true
		}

		if dsProgressing {
			reachedAvailableLevel = false

			dsState, exists := daemonsetStates[dsName]
			if !exists || !reflect.DeepEqual(dsState.LastSeenStatus, ds.Status) {
				dsState.LastChangeTime = time.Now()
				ds.Status.DeepCopyInto(&dsState.LastSeenStatus)
				daemonsetStates[dsName] = dsState
			}

			// Catch hung rollouts
			if exists && (time.Since(dsState.LastChangeTime)) > ProgressTimeout {
				hung = append(hung, fmt.Sprintf("DaemonSet %q rollout is not making progress - last change %s", dsName.String(), dsState.LastChangeTime.Format(time.RFC3339)))
			}
		} else {
			delete(daemonsetStates, dsName)
		}
	}

	for _, depName := range status.deployments {
		dep := &appsv1.Deployment{}
		if err := status.client.Get(context.TODO(), depName, dep); err != nil {
			log.Error(err, fmt.Sprintf("Error getting Deployment %q", depName.String()))
			progressing = append(progressing, fmt.Sprintf("Waiting for Deployment %q to be created", depName.String()))
			reachedAvailableLevel = false
			continue
		}

		depProgressing := false

		if dep.Status.UnavailableReplicas > 0 {
			progressing = append(progressing, fmt.Sprintf("Deployment %q is not available (awaiting %d replicas to be ready)", depName.String(), dep.Status.UnavailableReplicas))
			depProgressing = true
		} else if dep.Status.AvailableReplicas == 0 {
			progressing = append(progressing, fmt.Sprintf("Deployment %q is not yet scheduled on any nodes", depName.String()))
			depProgressing = true
		} else if dep.Status.ObservedGeneration < dep.Generation {
			progressing = append(progressing, fmt.Sprintf("Deployment %q update is being processed (generation %d, observed generation %d)", depName.String(), dep.Generation, dep.Status.ObservedGeneration))
			depProgressing = true
		}

		if depProgressing {
			reachedAvailableLevel = false

			depState, exists := deploymentStates[depName]
			if !exists || !reflect.DeepEqual(depState.LastSeenStatus, dep.Status) {
				depState.LastChangeTime = time.Now()
				dep.Status.DeepCopyInto(&depState.LastSeenStatus)
				deploymentStates[depName] = depState
			}

			// Catch hung rollouts
			if exists && (time.Since(depState.LastChangeTime)) > ProgressTimeout {
				hung = append(hung, fmt.Sprintf("Deployment %q rollout is not making progress - last change %s", depName.String(), depState.LastChangeTime.Format(time.RFC3339)))
			}
		} else {
			delete(deploymentStates, depName)
		}
	}

	status.setNotDegraded(PodDeployment)
	if err := status.setLastPodState(status, daemonsetStates, deploymentStates); err != nil {
		log.Error(err, "Failed to set pod state (continuing)")
	}

	status.setConditions(progressing, reachedAvailableLevel)

	if len(hung) > 0 {
		status.setDegraded(RolloutHung, "RolloutHung", strings.Join(hung, "\n"))
	} else {
		status.setNotDegraded(RolloutHung)
	}
}

// getLastPodState reads the last-seen daemonset + deployment state
// from the clusteroperator annotation and parses it. On error, it returns
// an empty state, since this should not block updating operator status.
func (adaptor *StatusOc) getLastPodState(status *StatusManager) (map[types.NamespacedName]daemonsetState, map[types.NamespacedName]deploymentState) {
	// with maps allocated
	daemonsetStates := map[types.NamespacedName]daemonsetState{}
	deploymentStates := map[types.NamespacedName]deploymentState{}

	// Load the last-seen snapshot from our annotation
	co := &configv1.ClusterOperator{ObjectMeta: metav1.ObjectMeta{Name: status.name}}
	err := status.client.Get(context.TODO(), types.NamespacedName{Name: status.name}, co)
	if err != nil {
		log.Error(err, "Failed to get last-seen snapshot")
		return daemonsetStates, deploymentStates
	}

	lsbytes := co.Annotations[lastSeenAnnotation]
	if lsbytes == "" {
		return daemonsetStates, deploymentStates
	}

	out := podState{}
	err = json.Unmarshal([]byte(lsbytes), &out)
	if err != nil {
		// No need to return error; just move on
		log.Error(err, "failed to unmashal last-seen-status")
		return daemonsetStates, deploymentStates
	}

	for _, ds := range out.DaemonsetStates {
		daemonsetStates[ds.NamespacedName] = ds
	}

	for _, ds := range out.DeploymentStates {
		deploymentStates[ds.NamespacedName] = ds
	}

	return daemonsetStates, deploymentStates
}

func (adaptor *StatusK8s) getLastPodState(status *StatusManager) (map[types.NamespacedName]daemonsetState, map[types.NamespacedName]deploymentState) {
	// with maps allocated
	daemonsetStates := map[types.NamespacedName]daemonsetState{}
	deploymentStates := map[types.NamespacedName]deploymentState{}
	return daemonsetStates, deploymentStates
}

func (adaptor *StatusOc) setLastPodState(status *StatusManager, dss map[types.NamespacedName]daemonsetState, deps map[types.NamespacedName]deploymentState) error {
	ps := podState{
		DaemonsetStates:  make([]daemonsetState, 0, len(dss)),
		DeploymentStates: make([]deploymentState, 0, len(deps)),
	}

	for nsn, ds := range dss {
		ds.NamespacedName = nsn
		ps.DaemonsetStates = append(ps.DaemonsetStates, ds)
	}

	for nsn, ds := range deps {
		ds.NamespacedName = nsn
		ps.DeploymentStates = append(ps.DeploymentStates, ds)
	}

	lsbytes, err := json.Marshal(ps)
	if err != nil {
		return err
	}

	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		oldStatus := &configv1.ClusterOperator{ObjectMeta: metav1.ObjectMeta{Name: status.name}}
		err := status.client.Get(context.TODO(), types.NamespacedName{Name: status.name}, oldStatus)
		isNotFound := errors.IsNotFound(err)
		if err != nil && !isNotFound {
			return err
		}

		newStatus := oldStatus.DeepCopy()
		if newStatus.Annotations == nil {
			newStatus.Annotations = map[string]string{}
		}
		newStatus.Annotations[lastSeenAnnotation] = string(lsbytes)
		return status.client.Patch(context.TODO(), newStatus, client.MergeFrom(oldStatus))
	})
}

func (adaptor *StatusK8s) setLastPodState(status *StatusManager, dss map[types.NamespacedName]daemonsetState, deps map[types.NamespacedName]deploymentState) error {
	return nil
}
