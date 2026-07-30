# OK-128 controlled provisioning benchmark

This runbook compares one Flatcar and one Talos warm cluster provision on the
same `ok-infra` management cluster. It wraps the supported lifecycle commands;
the observer has no apply, install, or cleanup implementation of its own.
Results are single-run observations and must not be presented as an SLO.

## Fixed envelope

- KubeVirt, `amd64`, Kubernetes `v1.34.1`
- one control-plane and one worker VM
- 2 vCPU, 4 GiB RAM, and 20 GiB disk per VM
- scheduling node `ok-infra`; the shared Golden PVCs are on
  `ok-storage-block`. Each OS retains its validated clone-target semantics:
  Flatcar `local-path`, Talos `ok-storage-block`
- Cilium chart `1.19.6`, SHA-256
  `21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179`
- sequential order: Flatcar first, complete cleanup, then Talos
- no other intentional management-cluster workload during either run

The benchmark records the exact repository revisions, input file digests,
Golden-Image identity, node versions, management load before/after, command
exit status, full sanitized command output, POSIX `real/user/sys`, and all nine
ticket milestones at one-second resolution. POSIX time and
`lifecycle_command_completed` describe the wrapped Make lifecycle. The ninth
ticket milestone, `command_completed`, is the common wrapper completion after
all asynchronous Kubernetes milestones have been observed.

## Offline preparation

Prerequisites are Python 3 with PyYAML, GNU/BSD Make, `kubectl`, `clusterctl`,
Helm, `/usr/bin/time`, both `ok-cluster` and `ok-linux` checkouts, and explicit
management/workload kubeconfig paths. Both repositories must be clean.

Acquire the chart before starting either timer:

```sh
make prepare-cilium-chart
make verify-cilium-chart
make ok128-benchmark-test
```

An offline operator can place a pre-downloaded chart through the same
digest-verifying atomic workflow:

```sh
make prepare-cilium-chart CILIUM_CHART_SOURCE=/media/cilium-1.19.6.tgz
```

Create and render disposable clusters with the fixed envelope. Use distinct
unused endpoints/CIDRs appropriate for the approved runtime:

```sh
make new CLUSTER=ok128-flatcar TYPE=flatcar WORKERS=1 \
  K8S_VERSION=v1.34.1 PROVIDER=kubevirt ARCHITECTURE=amd64 \
  NODE_SELECTOR=ok-infra START_IP=<approved-ip>
make render CLUSTER=ok128-flatcar

make new CLUSTER=ok128-talos TYPE=talos WORKERS=1 \
  K8S_VERSION=v1.34.1 TALOS_VERSION=v1.9.5 \
  PROVIDER=kubevirt ARCHITECTURE=amd64 \
  NODE_SELECTOR=ok-infra START_IP=<approved-ip>
make render CLUSTER=ok128-talos
```

Inspect the rendered configs, commit and push the exact benchmark inputs, and
verify that both repositories are clean. The Flatcar lifecycle and common
observer deliberately refuse unpushed source. Store run output outside the
checkout so that the first result does not make the repository dirty before
the second:

```sh
mkdir -p /private/tmp/ok128-benchmark
```

After the branch is pushed, run the common read-only management preflight for
each OS. It checks the controlled envelope, exact source revisions, chart
digest, absent namespace/workload kubeconfig, Bound Golden PVC, and current
management load:

```sh
make ok128-benchmark-preflight CLUSTER=ok128-flatcar OK128_OS=flatcar \
  CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz" \
  OK128_MANAGEMENT_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  OK128_WORKLOAD_KUBECONFIG="$HOME/.kube/ok128-flatcar.yaml"
```

Repeat with `CLUSTER=ok128-talos`, `OK128_OS=talos`, and its workload
kubeconfig path immediately before the Talos run.

## Guarded runtime

These commands mutate `ok-infra` and require a separate explicit Runtime GO.
The explicit confirmation applies only to the one command invocation.

Run Flatcar first:

```sh
OK128_BENCHMARK_APPLY=yes make ok128-benchmark-flatcar \
  CLUSTER=ok128-flatcar \
  CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz" \
  OK128_MANAGEMENT_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  OK128_WORKLOAD_KUBECONFIG="$HOME/.kube/ok128-flatcar.yaml" \
  OK128_OUTPUT_DIR=/private/tmp/ok128-benchmark \
  OK128_RUN_ID=flatcar-1 OK128_TEST_ORDER=1
```

After review, clean up only through the supported Flatcar lifecycle. Then run
the read-only cleanup verification with the recorded Flatcar Golden PVC name
and UID:

```sh
FLATCAR_TEARDOWN=yes make teardown-flatcar CLUSTER=ok128-flatcar \
  FLATCAR_INFRA_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  FLATCAR_WORKLOAD_KUBECONFIG="$HOME/.kube/ok128-flatcar.yaml"

make ok128-benchmark-cleanup-verify CLUSTER=ok128-flatcar \
  OK128_MANAGEMENT_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  OK128_OUTPUT_DIR=/private/tmp/ok128-benchmark \
  OK128_RUN_ID=flatcar-1 \
  OK128_GOLDEN_CLAIM=<recorded-claim> \
  OK128_GOLDEN_UID=<recorded-uid>
```

Only after Flatcar cleanup is verified, run Talos:

```sh
OK128_BENCHMARK_APPLY=yes make ok128-benchmark-talos \
  CLUSTER=ok128-talos \
  CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz" \
  OK128_MANAGEMENT_KUBECONFIG="$HOME/.kube/ok-infra.yaml" \
  OK128_WORKLOAD_KUBECONFIG="$HOME/.kube/ok128-talos.yaml" \
  OK128_OUTPUT_DIR=/private/tmp/ok128-benchmark \
  OK128_RUN_ID=talos-1 OK128_TEST_ORDER=2
```

Use the existing Talos `make teardown CLUSTER=ok128-talos CONFIRM=yes` flow
only after explicit cleanup approval, then run the same read-only cleanup
verification using the Talos Golden PVC identity.

## Comparison and publication

```sh
make ok128-benchmark-compare \
  OK128_FLATCAR_EVIDENCE=/private/tmp/ok128-benchmark/flatcar-1.json \
  OK128_TALOS_EVIDENCE=/private/tmp/ok128-benchmark/talos-1.json \
  OK128_OUTPUT_DIR=/private/tmp/ok128-benchmark
```

The comparison refuses incomplete, overlapping, failed, or differently shaped
runs. Review all JSON/log/Markdown/CSV files, run a second independent secret
scan, and only then copy the sanitized bundle into
`docs/adoption/OK-128/evidence/` for review. Cold Golden-Image publication
measurements remain separate; they are never included in these warm lifecycle
timers.
