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

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
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

	JobGroup   job.Group
	Log        *slog.Logger
	DB         *statedb.DB
	Frontends  statedb.Table[*loadbalancer.Frontend]
	Pods       statedb.Table[k8sTables.LocalPod]  `optional:"true"`
	Namespaces statedb.Table[k8sTables.Namespace] `optional:"true"`

	NetworkPolicies                  resource.Resource[*networkingv1.NetworkPolicy]              `optional:"true"`
	CiliumNetworkPolicies            resource.Resource[*ciliumv2.CiliumNetworkPolicy]            `optional:"true"`
	CiliumClusterwideNetworkPolicies resource.Resource[*ciliumv2.CiliumClusterwideNetworkPolicy] `optional:"true"`
	AllPods                          resource.Resource[*corev1.Pod]                              `optional:"true"`
}

func registerController(p controllerParams) {
	if !option.Config.EnableNoEBPFServices && !option.Config.EnableNoEBPFNetworkPolicy {
		return
	}

	c := &controller{
		log:                              p.Log,
		db:                               p.DB,
		frontends:                        p.Frontends,
		pods:                             p.Pods,
		namespaces:                       p.Namespaces,
		networkPolicies:                  p.NetworkPolicies,
		ciliumNetworkPolicies:            p.CiliumNetworkPolicies,
		ciliumClusterwideNetworkPolicies: p.CiliumClusterwideNetworkPolicies,
		allPods:                          p.AllPods,
		runner:                           CommandRunner{},
		policyCache:                      map[resource.Key]*networkingv1.NetworkPolicy{},
		cnpCache:                         map[resource.Key]*ciliumv2.CiliumNetworkPolicy{},
		ccnpCache:                        map[resource.Key]*ciliumv2.CiliumClusterwideNetworkPolicy{},
		podCache:                         map[resource.Key]*corev1.Pod{},
	}
	p.JobGroup.Add(job.OneShot("noebpf-nftables-reconciler", c.run))
}

type controller struct {
	log        *slog.Logger
	db         *statedb.DB
	frontends  statedb.Table[*loadbalancer.Frontend]
	pods       statedb.Table[k8sTables.LocalPod]
	namespaces statedb.Table[k8sTables.Namespace]

	networkPolicies                  resource.Resource[*networkingv1.NetworkPolicy]
	ciliumNetworkPolicies            resource.Resource[*ciliumv2.CiliumNetworkPolicy]
	ciliumClusterwideNetworkPolicies resource.Resource[*ciliumv2.CiliumClusterwideNetworkPolicy]
	allPods                          resource.Resource[*corev1.Pod]
	policyCache                      map[resource.Key]*networkingv1.NetworkPolicy
	cnpCache                         map[resource.Key]*ciliumv2.CiliumNetworkPolicy
	ccnpCache                        map[resource.Key]*ciliumv2.CiliumClusterwideNetworkPolicy
	podCache                         map[resource.Key]*corev1.Pod
	runner                           Runner
}

func (c *controller) run(ctx context.Context, health cell.Health) error {
	if option.Config.EnableNoEBPFServices {
		if err := c.waitTableInitialized(ctx, health, c.frontends, "load-balancer frontends"); err != nil {
			return err
		}
	}

	var policyEvents <-chan resource.Event[*networkingv1.NetworkPolicy]
	if option.Config.EnableNoEBPFNetworkPolicy && c.networkPolicies != nil {
		policyEvents = c.networkPolicies.Events(ctx)
	}
	var cnpEvents <-chan resource.Event[*ciliumv2.CiliumNetworkPolicy]
	if option.Config.EnableNoEBPFNetworkPolicy && c.ciliumNetworkPolicies != nil {
		cnpEvents = c.ciliumNetworkPolicies.Events(ctx)
	}
	var ccnpEvents <-chan resource.Event[*ciliumv2.CiliumClusterwideNetworkPolicy]
	if option.Config.EnableNoEBPFNetworkPolicy && c.ciliumClusterwideNetworkPolicies != nil {
		ccnpEvents = c.ciliumClusterwideNetworkPolicies.Events(ctx)
	}
	var podEvents <-chan resource.Event[*corev1.Pod]
	if option.Config.EnableNoEBPFNetworkPolicy && c.allPods != nil {
		podEvents = c.allPods.Events(ctx)
	}
	if option.Config.EnableNoEBPFNetworkPolicy {
		if err := c.waitPolicyInputsInitialized(ctx, health, policyEvents, cnpEvents, ccnpEvents, podEvents); err != nil {
			return err
		}
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
		case <-nextWatch.namespaces:
		case ev, ok := <-podEvents:
			if !ok {
				podEvents = nil
				continue
			}
			c.handlePodEvent(ev)
		case ev, ok := <-policyEvents:
			if !ok {
				policyEvents = nil
				continue
			}
			c.handlePolicyEvent(ev)
		case ev, ok := <-cnpEvents:
			if !ok {
				cnpEvents = nil
				continue
			}
			c.handleCNPEvent(ev)
		case ev, ok := <-ccnpEvents:
			if !ok {
				ccnpEvents = nil
				continue
			}
			c.handleCCNPEvent(ev)
		}
	}
}

func (c *controller) waitTableInitialized(ctx context.Context, health cell.Health, table statedb.TableMeta, name string) error {
	initialized, watch := table.Initialized(c.db.ReadTxn())
	for !initialized {
		health.OK("Waiting for no-eBPF nftables " + name + " to initialize")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-watch:
			initialized, watch = table.Initialized(c.db.ReadTxn())
		}
	}
	return nil
}

func (c *controller) waitPolicyInputsInitialized(ctx context.Context, health cell.Health, policyEvents <-chan resource.Event[*networkingv1.NetworkPolicy], cnpEvents <-chan resource.Event[*ciliumv2.CiliumNetworkPolicy], ccnpEvents <-chan resource.Event[*ciliumv2.CiliumClusterwideNetworkPolicy], podEvents <-chan resource.Event[*corev1.Pod]) error {
	if c.pods == nil || c.namespaces == nil || c.networkPolicies == nil || c.allPods == nil {
		return fmt.Errorf("no-eBPF NetworkPolicy backend requires local pods, namespaces, all pods, and NetworkPolicy resources")
	}
	if err := c.waitTableInitialized(ctx, health, c.pods, "local pods"); err != nil {
		return err
	}
	if err := c.waitTableInitialized(ctx, health, c.namespaces, "namespaces"); err != nil {
		return err
	}

	policiesSynced := false
	cnpSynced := c.ciliumNetworkPolicies == nil
	ccnpSynced := c.ciliumClusterwideNetworkPolicies == nil
	podsSynced := false
	for !policiesSynced || !podsSynced || !cnpSynced || !ccnpSynced {
		health.OK("Waiting for no-eBPF nftables policy resources to synchronize")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-policyEvents:
			if !ok {
				return fmt.Errorf("NetworkPolicy resource closed before synchronization")
			}
			if ev.Kind == resource.Sync {
				policiesSynced = true
			}
			c.handlePolicyEvent(ev)
		case ev, ok := <-cnpEvents:
			if !ok {
				return fmt.Errorf("CiliumNetworkPolicy resource closed before synchronization")
			}
			if ev.Kind == resource.Sync {
				cnpSynced = true
			}
			c.handleCNPEvent(ev)
		case ev, ok := <-ccnpEvents:
			if !ok {
				return fmt.Errorf("CiliumClusterwideNetworkPolicy resource closed before synchronization")
			}
			if ev.Kind == resource.Sync {
				ccnpSynced = true
			}
			c.handleCCNPEvent(ev)
		case ev, ok := <-podEvents:
			if !ok {
				return fmt.Errorf("Pod resource closed before synchronization")
			}
			if ev.Kind == resource.Sync {
				podsSynced = true
			}
			c.handlePodEvent(ev)
		}
	}
	return nil
}

type tableWatches struct {
	frontends  <-chan struct{}
	pods       <-chan struct{}
	namespaces <-chan struct{}
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
	var namespaces []k8sTables.Namespace
	var namespaceWatch <-chan struct{}
	if option.Config.EnableNoEBPFNetworkPolicy && c.pods != nil {
		pods, watch := c.pods.AllWatch(txn)
		localPods = statedb.Collect(pods)
		podWatch = watch
	}
	if option.Config.EnableNoEBPFNetworkPolicy && c.namespaces != nil {
		nss, watch := c.namespaces.AllWatch(txn)
		namespaces = statedb.Collect(nss)
		namespaceWatch = watch
	}

	state, err := desiredState(
		collectedFrontends,
		localPods,
		c.cachedPods(),
		namespaces,
		c.cachedNetworkPolicies(),
		c.cachedCNPs(),
		c.cachedCCNPs(),
		option.Config.EnableNoEBPFServices,
		option.Config.EnableNoEBPFNetworkPolicy,
	)
	if err != nil {
		return tableWatches{frontends: frontendWatch, pods: podWatch, namespaces: namespaceWatch}, err
	}
	if err := Apply(ctx, c.runner, state); err != nil {
		return tableWatches{frontends: frontendWatch, pods: podWatch, namespaces: namespaceWatch}, fmt.Errorf("apply desired state: %w", err)
	}
	return tableWatches{frontends: frontendWatch, pods: podWatch, namespaces: namespaceWatch}, nil
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

func (c *controller) handleCNPEvent(ev resource.Event[*ciliumv2.CiliumNetworkPolicy]) {
	var err error
	switch ev.Kind {
	case resource.Upsert:
		c.cnpCache[ev.Key] = ev.Object
	case resource.Delete:
		delete(c.cnpCache, ev.Key)
	case resource.Sync:
	}
	ev.Done(err)
}

func (c *controller) handleCCNPEvent(ev resource.Event[*ciliumv2.CiliumClusterwideNetworkPolicy]) {
	var err error
	switch ev.Kind {
	case resource.Upsert:
		c.ccnpCache[ev.Key] = ev.Object
	case resource.Delete:
		delete(c.ccnpCache, ev.Key)
	case resource.Sync:
	}
	ev.Done(err)
}

func (c *controller) handlePodEvent(ev resource.Event[*corev1.Pod]) {
	var err error
	switch ev.Kind {
	case resource.Upsert:
		c.podCache[ev.Key] = ev.Object
	case resource.Delete:
		delete(c.podCache, ev.Key)
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

func (c *controller) cachedCNPs() []*ciliumv2.CiliumNetworkPolicy {
	policies := make([]*ciliumv2.CiliumNetworkPolicy, 0, len(c.cnpCache))
	for _, policy := range c.cnpCache {
		policies = append(policies, policy)
	}
	return policies
}

func (c *controller) cachedCCNPs() []*ciliumv2.CiliumClusterwideNetworkPolicy {
	policies := make([]*ciliumv2.CiliumClusterwideNetworkPolicy, 0, len(c.ccnpCache))
	for _, policy := range c.ccnpCache {
		policies = append(policies, policy)
	}
	return policies
}

func (c *controller) cachedPods() []*corev1.Pod {
	pods := make([]*corev1.Pod, 0, len(c.podCache))
	for _, pod := range c.podCache {
		pods = append(pods, pod)
	}
	return pods
}

func desiredState(frontends []*loadbalancer.Frontend, localPods []k8sTables.LocalPod, allPods []*corev1.Pod, namespaces []k8sTables.Namespace, networkPolicies []*networkingv1.NetworkPolicy, cnpPolicies []*ciliumv2.CiliumNetworkPolicy, ccnpPolicies []*ciliumv2.CiliumClusterwideNetworkPolicy, enableServices, enableNetworkPolicy bool) (DesiredState, error) {
	var state DesiredState
	if enableServices {
		services, err := ServicesFromFrontends(frontends)
		if err != nil {
			return DesiredState{}, err
		}
		state.Services = services
	}
	if enableNetworkPolicy {
		policies, err := PoliciesFromK8sNetworkPolicies(localPods, allPods, namespaces, networkPolicies)
		if err != nil {
			return DesiredState{}, err
		}
		state.Policies = policies
		cnpPoliciesOut, err := PoliciesFromCiliumNetworkPolicies(localPods, allPods, namespaces, cnpPolicies)
		if err != nil {
			return DesiredState{}, err
		}
		state.Policies = append(state.Policies, cnpPoliciesOut...)
		ccnpPoliciesOut, err := PoliciesFromCiliumClusterwideNetworkPolicies(localPods, allPods, namespaces, ccnpPolicies)
		if err != nil {
			return DesiredState{}, err
		}
		state.Policies = append(state.Policies, ccnpPoliciesOut...)
	}
	return state, nil
}
