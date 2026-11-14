# CLI v1.0.1 development note — installed binary source binding (OK-228)

**Not released.** This is a narrow, source-verified compatibility step for a downloaded or globally installed `ok` binary. It is **not** a packaged installer and does not remove source/tool prerequisites.

## Why

The original Same-Plane operator `ok up` / `ok destroy` requires the executable at `<ok-cluster>/.tools/bin/ok`. A global executable at `/usr/local/bin/ok` has no reliable way to infer its accompanying Make/Python lifecycle checkout.

The revised runtime accepts an **explicit** `OK_CLUSTER_HOME` pointing to a canonical `ok-cluster` checkout:

```sh
export OK_CLUSTER_HOME=/absolute/path/to/ok-cluster
ok version
ok up -f cluster.yaml --management /absolute/path/to/management.yaml
# later, after independent readiness verification:
ok destroy my-cluster --management /absolute/path/to/management.yaml
```

Only use a binary with an exact, embedded full source commit; the checked-out `OK_CLUSTER_HOME` source must be at **the same commit** and satisfy the existing clean-checkout and pinned `ok-linux` gates. This override does not authorize an arbitrary checkout, does not permit a revision mismatch, and does not infer a source checkout from the current directory.

For development binaries, the existing `<ok-cluster>/.tools/bin/ok` discovery continues to work without `OK_CLUSTER_HOME`. For installed binaries, missing `OK_CLUSTER_HOME` fails with actionable guidance.

## Limitations and release gates

- The prepared lifecycle source and its sibling pinned `ok-linux` still need to be locally available. Do not move or overwrite evidence directories.
- The Cilium cache must pass its exact pinned SHA-256 check; see OK-228 / PR #495 for the separate local acquisition UX.
- The management cluster still requires existing CAPI, KubeVirt, CDI, storage, Golden Image and network prerequisites.
- The two typed provision/bootstrap confirmations and the exact-name destroy confirmation remain compulsory.
- No release is authorized by this design alone: review, CI, macOS/Linux compatibility, artifact integrity/provenance and a fresh live Create → Verify → Destroy acceptance test are outstanding.
- The end-state for v1.0.1 is a revision-bound install layout or verified lifecycle bundle that makes manual `OK_CLUSTER_HOME` setup unnecessary. This is only the minimal first binding step.
