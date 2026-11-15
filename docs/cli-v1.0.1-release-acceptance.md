# CLI v1.0.1 release acceptance checklist (OK-228)

This checklist applies to acceptance builds (`v1.0.1-rcN`) of the approved merge commit, and then to the official v1.0.1 built from the tag on that same commit (see `docs/release-process.md`). The RC1 (`2a9b805`) and RC2 artifacts are not changed.

The live steps require separately authorized disposable infrastructure and a dedicated, explicitly authorized identity. Run nothing against shared clusters without approval.

## Fresh-user platform validation (after documented release build; record each result separately)

The v1.0.1 target artifact matrix is **darwin-arm64**, **darwin-amd64** and **linux-amd64** (subject to passing native acceptance before publishing). The operator host CPU is distinct from the provisioned **AMD64** Talos/KubeVirt workload-node architecture.

| Tester / environment | Artifact | Minimum evidence | Status |
|---|---|---|---|
| Linux AMD64 / Ubuntu Multipass | `linux-amd64` | Download and independent SHA-256, install in clean user HOME, `ok version`, `ok config init`, `ok config show`, `ok up` plan; live lifecycle only when explicitly authorized | NOT TESTED |
| Daniel / macOS M5 ARM64 | `darwin-arm64` | Clean user installation, unsigned/quarantine handling, PATH, init and interactive `ok up` UX | NOT TESTED |
| Suchit / WSL2 Linux AMD64 | `linux-amd64` | Native Linux installation in WSL, private Linux-path kubeconfig, PATH/runtime dependencies, init and interactive request flow | NOT TESTED |
| Intel Mac AMD64 | `darwin-amd64` | Native Intel-macOS verified installer and fresh-user initialization, plus first-cluster workflow with authorized management | NOT TESTED |

For a fresh-user test, do **not** precreate config/state/requests/logs/kubeconfig directories, export test-specific XDG paths, or manually scaffold a ClusterRequest unless explicitly testing override behavior. The CLI should create private application directories. A prepared management cluster, required runtime tools and a valid, explicitly authorized management kubeconfig **are** prerequisites. Do not overwrite an existing user's local config to simulate a clean install.

`ok config init` only verifies the bundle and saves a kubeconfig path (private regular file); it does not generate credentials, set `current-context`, or contact the Kubernetes API. Check `kubectl --kubeconfig <path> get nodes` read-only before enabling mutation. The CLI must not infer its management target from `KUBECONFIG` or current kubectl context.

Collect platform, OS/architecture, artifact name/SHA-256, CLI commit, tool versions, screenshot/log of non-secret prompts, exit codes, verified directory permissions and any failure mode. Do not publish raw kubeconfigs, secrets or raw Make logs.

**Acceptance gate distinction:** A successful live `ok up` / Ready / `ok destroy` on a shared environment is useful evidence but does not by itself close all independent lifecycle safety, supply-chain, multi-cluster and publish-approval gates specified below. Keep a draft GitHub release until those gates are recorded.

## A. Build (maintainer, clean checkout of the reviewed commit)

- [ ] The **OK CLI build and acceptance** workflow (`release=false`) passes for `v1.0.1-rcN` and the approved commit, natively on `macos-15`, `macos-15-intel` and `ubuntu-24.04`; the artifacts and both acceptance reports are kept as evidence. Local equivalent: `make ok-rc-acceptance RC_VERSION=v1.0.1-rcN RC_COMMIT=<approved commit>` passes. It checks the sources, runs the tests, builds both bundles, verifies the checksums and `release.txt`, smoke-tests the native bundle, and writes `acceptance-*.json` next to the artifacts
- [ ] `make ok-rc-smoke-install …` passes natively on the other platform (macOS ARM64, macOS Intel AMD64 and Linux AMD64/WSL2)
- [ ] Record the Go toolchain, build host and the acceptance reports. Never claim a signature or reproducibility that wasn't established.
- [ ] CI green on the reviewed commit: `test`, `release-bundle` (macOS and Ubuntu, including `install_ok_test.py` and `ok_rc_acceptance_test.py`)

## B. Installation, per platform (macOS ARM64 natively; Linux AMD64 natively, preferably WSL2), as an unprivileged user

- [ ] The archive SHA-256 equals the value received through a separate trusted channel
- [ ] `install-ok.sh --archive … --sha256 … --link` installs to `~/.local/share/ok/<bundle>`, creates `~/.local/bin/ok`, and leaves the archive unchanged
- [ ] Running the installer again refuses (the existing install is unchanged), and an existing `~/.local/bin/ok` is never replaced
- [ ] `--prefix`/`--bin-dir` install into an alternative location
- [ ] Wrong checksum, truncated archive and wrong-platform archive are refused with nothing installed
- [ ] A destination created concurrently (directory, symlink or file) is never replaced, entered or nested into (automated: `test_destination_created_concurrently_is_never_replaced_or_nested`)
- [ ] macOS: a browser download is quarantined; quarantine is handled only after the checksum matched
- [ ] `ok version` through the link prints the bundle version and full commit

## C. First run

- [ ] `ok config init` through `~/.local/bin/ok` reports "release bundle (release.txt matches)" and the bundle paths, and asks for the management kubeconfig and an `ok`/`no` confirmation
- [ ] Without a terminal (`</dev/null`), `ok config init` shows the summary and saves nothing; with `--yes` it saves, but only after the same verification
- [ ] No provider kubeconfig is requested. The management kubeconfig must be 0600, a regular file, and not a symlink. Its contents are not read; no cluster is contacted
- [ ] Missing tools (for example uninstalling or hiding `helm`) are listed and nothing is installed
- [ ] A second `ok config init` refuses (create-only); `ok config show` prints a readable summary (saved settings separate from the live running-bundle check, which reports `verified`, or `NOT VERIFIED` with a reason for a tampered bundle) and never kubeconfig contents; `ok config show -o json` / `--output json` output is identical to RC2
- [ ] The config path is the OS default (macOS `~/Library/Application Support/ok/config.json`) or `--config`; an explicit missing `--config` fails for `ok up` and `ok destroy`
- [ ] Split-plane compatibility: `ok config init --topology split-plane` (or the five path flags) still writes `ok-cli-paths/v1` with both kubeconfigs; legacy `ok cluster destroy` refuses a Same-Plane config

## C2. Upgrade from RC1 with an existing configuration

- [ ] Start from an `ok-cli-paths/v2` file whose `lifecycleRoot`/`okLinuxPath` point at the installed RC1 bundle and whose `managementKubeconfig` is set. RC1 (`2a9b805`) cannot write v2 itself, so create this file by hand (mode 0600 in a 0700 directory) for the test; the same situation arises for any later upgrade (RC2 to RC3)
- [ ] Install RC2 next to RC1: the RC1 installation stays untouched, and `--link` leaves an existing `~/.local/bin/ok` alone (repoint it yourself)
- [ ] `ok config show` from RC2 reports RC2 as verified and notes that the saved sources are RC1's; the file is unchanged, and `ok config init` from RC2 refuses to overwrite it
- [ ] `ok up` / `ok destroy <name>` from RC2 use the saved management reference and RC2's own sources, never the RC1 `lifecycleRoot`; a cluster created by RC1 is destroyed with RC1's `ok` by full path (cross-version destroy is not supported)
- [ ] Automated: `TestUpgradeKeepsConfigButUsesRunningBundleSources` (cmd/ok)

## D. Lifecycle (authorized disposable infrastructure only)

- [ ] `ok up` without `--management`: the banner says "management kubeconfig from saved configuration …". Identity (API, CA, kube-system UID) is shown; both typed confirmations are required
- [ ] Independent verification: nodes Ready, Cilium and CoreDNS Running, CAPI Cluster Available, KubeVirt VMs/VMIs Ready, PVCs Bound; sibling clusters unaffected
- [ ] `ok destroy <name>` without `--management`: same source line, UID and ledger checks, typed cluster name
- [ ] Independent absence checks for namespace, exact PVs, Longhorn volumes and Golden image cloner RBAC; the ledger ConfigMap persists; the Golden image is preserved
- [ ] Two disposable clusters from the same installation (OK-228 gate)

## E. Release gates (v1.0.1 is not stable before A to D and these are complete)

- [ ] Licensing and redistribution decision
- [ ] Provenance/signing decision (or an explicit unsigned Community Preview policy)
- [x] Version semantics decided: SemVer, one version for ok-cluster releases and the `ok` CLI; v1.0.1 is the first `1.x` release, and the next patch release is v1.0.2
- [ ] Approval to tag: `v1.0.1` (free in the tag history as of 2026-11-14) on the approved commit only; then `make ok-release-acceptance RELEASE_VERSION=v1.0.1 RELEASE_COMMIT=<approved commit>`
- [ ] If attesting: environment `ok-cli-release-attestation` exists with required reviewers and a protected/selected-branch policy; the official run (`release=true attest=true`) is approved by a reviewer. Acceptance builds never attest
- [ ] Approval to publish the GitHub release (checklist in `docs/release-process.md`); release notes in `docs/release-notes/v1.0.1.md`
- [ ] Release notes state the limitations: Same-Plane only, prepared management cluster, unsigned, local CIDR inventory, no cross-version destroy, no name reuse
