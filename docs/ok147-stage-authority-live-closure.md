# OK-147 bounded stage-authority live closure

This redacted DEV checkpoint records the first complete installation of the
bounded stage authority on `ok-mgmt`. It contains no credential, raw Kubernetes
object, endpoint, UID, resourceVersion, token, key, certificate payload or
kubeconfig.

## Bound identities

```text
runner source:       a963f6bf887871e3653b33e5d17b0c53f5d10248
runner image:        sha256:e0aa65106b4ddf3eb877267de0df4aa7237cddfda242a684a98beb660329243f
fresh-run plan:      sha256:94289e594abee71e8844a0c665620215094f0cd2830fe71b0f38610d643e0949
authority policy:    sha256:1be805c25ccfd341ca9dccbdc0c3e5408d413b42914c7e22234fe9afd1fa9c27
runtime package:     sha256:c0f054d10dee3b60c8a0962dc63a231977c424bbace0d8ea57185412f0ef0529
package receipt:     sha256:6ad238f02a74c6b5eea4caac7adb9b6c46ab3b54fd2261266d381f7fd9e7316c
service identity:    sha256:d464c0a616e2461c1d85ecd1a22b802c48573c8ac3ed1e9917f35308f1d3b7df
recovery candidate:  sha256:c45d80fbdfe1e5eb99587e617cc670bb9fd74cf7f4a6e40d44721804a156f614
cleanup receipt:     sha256:71f9d4a7c3d500c957eaa9e9d48e6af9d564478da07836cabf5721f4c07ab691
```

## Result

The initial single-use launcher created four confirmed objects and stopped
after the API server accepted the NetworkPolicy but omitted its explicitly
empty `spec.egress` field in the response. The launcher preserved the partial
state and performed no retry.

The implementation was then narrowed to recognize only that Kubernetes
serialization equivalence. All tests, vet and bounded race tests passed before
the corrected image was published with pullback and attestation verification.
The corrected execution package was recorded additively as fresh-run v6.

The recovery preflight verified the exact five-object partial prefix and the
existing three-object least-privilege installer bootstrap. It then removed the
five objects in reverse dependency order with UID and resourceVersion API
preconditions. No force deletion or finalizer mutation was used.

After proving all six runtime names absent and the bound Service identity free,
one new maximum-30-minute TokenRequest was used by the single-use launcher. The
fixed create sequence completed:

```text
Secret -> ServiceAccount -> PersistentVolumeClaim
       -> Service -> NetworkPolicy -> StatefulSet
```

Bounded read-only observation then proved:

```text
StatefulSet replicas:       1 desired / 1 current / 1 ready
StatefulSet generation:     observed == desired
authority Pod:              Running / Ready / zero restarts
runtime image:              exact bound digest
state PVC:                  Bound / local-path / 64Mi
Service endpoints:          one ready address / bound HTTPS port
```

## Boundary

```text
stage authority installed:  PASS
stage execution performed:  no
cluster lifecycle mutation: no
retry after corrected run:  no
rollback:                   no
failure injection:          no
raw evidence publication:   forbidden
```

The tokenless installer bootstrap and the stage-authority runtime remain on
`ok-mgmt`. Private signing, TLS, bearer-token and cleanup evidence remain only
under `/private/tmp` with private file permissions. A later stage-run grant
must bind the fresh-run-v6 plan, the installed authority policy/key identity
and a separately prepared runner activation package.
