<!-- This file was autogenerated via cilium-operator --cmdref, do not edit manually-->

## cilium-operator-generic hive

Inspect the hive

```
cilium-operator-generic hive [flags]
```

### Options

```
      --enable-k8s-api-discovery              Enable discovery of Kubernetes API groups and resources with the discovery API
      --gops-port uint16                      Port for gops server to listen on (default 9891)
  -h, --help                                  help for hive
      --identity-gc-interval duration         GC interval for security identities (default 15m0s)
      --identity-gc-rate-interval duration    Interval used for rate limiting the GC of security identities (default 1m0s)
      --identity-gc-rate-limit int            Maximum number of security identities that will be deleted within the identity-gc-rate-interval (default 2500)
      --identity-heartbeat-timeout duration   Timeout after which identity expires on lack of heartbeat (default 30m0s)
      --k8s-api-server string                 Kubernetes API server URL
      --k8s-client-burst int                  Burst value allowed for the K8s client
      --k8s-client-qps float32                Queries per second limit for the K8s client
      --k8s-heartbeat-timeout duration        Configures the timeout for api-server heartbeat, set to 0 to disable (default 30s)
      --k8s-kubeconfig-path string            Absolute path of the kubernetes kubeconfig file
      --operator-pprof                        Enable serving pprof debugging API
      --operator-pprof-address string         Address that pprof listens on (default "localhost")
      --operator-pprof-port uint16            Port that pprof listens on (default 6061)
```

### SEE ALSO

* [cilium-operator-generic](cilium-operator-generic.md)	 - Run cilium-operator-generic
* [cilium-operator-generic hive dot-graph](cilium-operator-generic_hive_dot-graph.md)	 - Output the dependencies graph in graphviz dot format
