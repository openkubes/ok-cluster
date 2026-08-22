# OK-147 bounded stage-authority v7 rebind closure

This redacted DEV checkpoint records the single approved rebind of the
existing bounded stage authority on `ok-mgmt` to the fresh-run-v7 Plan and the
runner published from `ok-cluster` source `4a9a650c4270b2a572e7de4a7d3f3b45b2837330`.
It contains no credential, Secret payload, raw Kubernetes object, endpoint,
UID, resourceVersion, token, key, certificate payload or kubeconfig.

## Bound identities

```text
runner source:       4a9a650c4270b2a572e7de4a7d3f3b45b2837330
runner image:        sha256:86b5b1175944785d787fcc1b408114d31341c67be90841f896aedc43389f5af2
fresh-run plan:      sha256:4f61e81b3f3dba5a2819e5be93764486d5a936f3fb2ba153a80d5866801af19c
authority policy:    sha256:631cf3a6cea8c120218fae9060195b796668b58db51c7bfa6e281147d963e598
rebind candidate:    sha256:1f8876413595a82aa0253c87ae2ef2c56fa672a66ddc6b7709ccc9b09b64b1f7
private evidence:    sha256:ac8003868105c2ec4a409cac75224c69dd878af7dd0f0d18790761cfcff7bf78
```

The private evidence identity above identifies the local redacted execution
record. The file itself remains outside Git together with all source Secret
material.

## Result

The approved create/patch boundary completed once:

1. one new immutable private source Secret was created under the exact v7
   name;
2. the existing StatefulSet was patched with UID and resourceVersion
   preconditions;
3. only the policy digest, source-Secret reference, init image, runner image
   and their expected-policy arguments changed; and
4. bounded observation proved the new generation fully converged.

Direct live verification after the operation established:

```text
StatefulSet generation:       observed == desired
replicas:                     1 desired / 1 updated / 1 ready
init image:                   exact v7 runner digest
runner image:                 exact v7 runner digest
source Secret:                exact immutable v7 Secret
old immutable Secret:        retained
state PVC:                    retained
```

## Boundary

```text
stage-authority v7 rebind:    PASS
stage execution performed:   no
cluster lifecycle mutation:  no
state migration/reset:       no
old Secret cleanup:          no
retry:                       no
failure injection:           no
raw/private publication:     forbidden
```

This checkpoint updates only the authorization service's verified Plan and
runner binding. It does not authorize a stage grant, activation installation
or fresh cluster run. The next activation must bind the fresh-run-v7 Plan and
the exact v7 authority identity before any lifecycle mutation is considered.
