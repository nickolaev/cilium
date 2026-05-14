// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nftables

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/k8s/resource"
	networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

// Cell wires the experimental no-eBPF nftables reconciler into the agent. It is
// intentionally gated by explicit no-eBPF feature flags so the normal eBPF
// datapath never attempts to own nftables state.
var Cell = cell.Module(
	"noebpf-nftables",
	"Experimental nftables backend for linux-route no-eBPF mode",
	cell.Invoke(registerController),
)

type controllerParams struct {
	cell.In

	JobGroup  job.Group
	Log       *slog.Logger
	DB        *statedb.DB
	Frontends statedb.Table[*loadbalancer.Frontend]
	Pods      statedb.Table[k8sTables.LocalPod] `optional:"true"`

	NetworkPolicies resource.Resource[*networkingv1.NetworkPolicy] `optional:"true"`
}

func registerController(p controllerParams) {
	if !option.Config.EnableNoEBPFServices && !option.Config.EnableNoEBPFNetworkPolicy {
		return
	}

	c := &controller{
		log:             p.Log,
		db:              p.DB,
		frontends:       p.Frontends,
		pods:            p.Pods,
		networkPolicies: p.NetworkPolicies,
		runner:          CommandRunner{},
		policyCache:     map[resource.Key]*networkingv1.NetworkPolicy{},
	}
	p.JobGroup.Add(job.OneShot("noebpf-nftables-reconciler", c.run))
}

type controller struct {
	log       *slog.Logger
	db        *statedb.DB
	frontends statedb.Table[*loadbalancer.Frontend]
	pods      statedb.Table[k8sTables.LocalPod]

	networkPolicies resource.Resource[*networkingv1.NetworkPolicy]
	policyCache     map[resource.Key]*networkingv1.NetworkPolicy
	runner          Runner
}

func (c *controller) run(ctx context.Context, health cell.Health) error {
	initialized, watch := c.frontends.Initialized(c.db.ReadTxn())
	for !initialized {
		health.OK("Waiting for load-balancer frontends to initialize")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
			initialized = true
		}
	}

	limiter := rate.NewLimiter(time.Second, 1)
	defer limiter.Stop()

	var policyEvents <-chan resource.Event[*networkingv1.NetworkPolicy]
	if option.Config.EnableNoEBPFNetworkPolicy && c.networkPolicies != nil {
		policyEvents = c.networkPolicies.Events(ctx)
	}

	for {
		nextWatch, err := c.reconcile(ctx)
		if err != nil {
			health.Degraded("Failed to reconcile no-eBPF nftables state", err)
			c.log.Warn("Failed to reconcile no-eBPF nftables state", "error", err)
		} else {
			health.OK("No-eBPF nftables state reconciled")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-nextWatch.frontends:
		case <-nextWatch.pods:
		case ev, ok := <-policyEvents:
			if !ok {
				policyEvents = nil
				continue
			}
			c.handlePolicyEvent(ev)
		}
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

type tableWatches struct {
	frontends <-chan struct{}
	pods      <-chan struct{}
}

func (c *controller) reconcile(ctx context.Context) (tableWatches, error) {
	txn := c.db.ReadTxn()
	var collectedFrontends []*loadbalancer.Frontend
	var frontendWatch <-chan struct{}
	if option.Config.EnableNoEBPFServices {
		frontends, watch := c.frontends.AllWatch(txn)
		collectedFrontends = statedb.Collect(frontends)
		frontendWatch = watch
	}
	var localPods []k8sTables.LocalPod
	var podWatch <-chan struct{}
	if option.Config.EnableNoEBPFNetworkPolicy && c.pods != nil {
		pods, watch := c.pods.AllWatch(txn)
		localPods = statedb.Collect(pods)
		podWatch = watch
	}

	state, err := desiredState(
		collectedFrontends,
		localPods,
		c.cachedNetworkPolicies(),
		option.Config.EnableNoEBPFServices,
		option.Config.EnableNoEBPFNetworkPolicy,
	)
	if err != nil {
		return tableWatches{frontends: frontendWatch, pods: podWatch}, err
	}
	if err := Apply(ctx, c.runner, state); err != nil {
		return tableWatches{frontends: frontendWatch, pods: podWatch}, fmt.Errorf("apply desired state: %w", err)
	}
	return tableWatches{frontends: frontendWatch, pods: podWatch}, nil
}

func (c *controller) handlePolicyEvent(ev resource.Event[*networkingv1.NetworkPolicy]) {
	var err error
	switch ev.Kind {
	case resource.Upsert:
		c.policyCache[ev.Key] = ev.Object
	case resource.Delete:
		delete(c.policyCache, ev.Key)
	case resource.Sync:
	}
	ev.Done(err)
}

func (c *controller) cachedNetworkPolicies() []*networkingv1.NetworkPolicy {
	policies := make([]*networkingv1.NetworkPolicy, 0, len(c.policyCache))
	for _, policy := range c.policyCache {
		policies = append(policies, policy)
	}
	return policies
}

func desiredState(frontends []*loadbalancer.Frontend, localPods []k8sTables.LocalPod, networkPolicies []*networkingv1.NetworkPolicy, enableServices, enableNetworkPolicy bool) (DesiredState, error) {
	var state DesiredState
	if enableServices {
		services, err := ServicesFromFrontends(frontends)
		if err != nil {
			return DesiredState{}, err
		}
		state.Services = services
	}
	if enableNetworkPolicy {
		policies, err := PoliciesFromK8sNetworkPolicies(localPods, networkPolicies)
		if err != nil {
			return DesiredState{}, err
		}
		state.Policies = policies
	}
	return state, nil
}
