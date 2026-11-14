# CLI v1.0.1 release acceptance checklist (OK-228)

This checklist applies to a new release candidate built from the merge commit of the first-run PR. The RC1 artifacts (`2a9b805`) are not changed.

The live steps require separately authorized disposable infrastructure and a dedicated, explicitly authorized identity. Run nothing against shared clusters without approval.

## A. Build (maintainer, clean checkout of the reviewed commit)

- [ ] `make ok-release-bundle GOOS=darwin GOARCH=arm64 …` and `GOOS=linux GOARCH=amd64 …` with the pinned `ok-linux` and the pinned Cilium chart
- [ ] Record the Go toolchain, build host, `release.txt` and SHA-256 of both archives. Never claim a signature or reproducibility that wasn't established.
- [ ] CI green on the reviewed commit: `test`, `release-bundle` (macOS and Ubuntu, including `install_ok_test.py`)

## B. Installation, per platform (macOS ARM64 natively; Linux AMD64 natively, preferably WSL2), as an unprivileged user

- [ ] The archive SHA-256 equals the value received through a separate trusted channel
- [ ] `install-ok.sh --archive … --sha256 … --link` installs to `~/.local/share/ok/<bundle>`, creates `~/.local/bin/ok`, and leaves the archive unchanged
- [ ] Running the installer again refuses (the existing install is unchanged), and an existing `~/.local/bin/ok` is never replaced
- [ ] `--prefix`/`--bin-dir` install into an alternative location
- [ ] Wrong checksum, truncated archive and wrong-platform archive are refused with nothing installed
- [ ] macOS: a browser download is quarantined; quarantine is handled only after the checksum matched
- [ ] `ok version` through the link prints the bundle version and full commit

## C. First run

- [ ] `ok config init` through `~/.local/bin/ok` reports "release bundle (release.txt matches)" and the bundle paths, and asks for the management kubeconfig and an `ok`/`no` confirmation
- [ ] No provider kubeconfig is requested. The management kubeconfig must be 0600, a regular file, and not a symlink. Its contents are not read; no cluster is contacted
- [ ] Missing tools (for example uninstalling or hiding `helm`) are listed and nothing is installed
- [ ] A second `ok config init` refuses (create-only); `ok config show` shows the path and settings, never kubeconfig contents
- [ ] The config path is the OS default (macOS `~/Library/Application Support/ok/config.json`) or `--config`; an explicit missing `--config` fails for `ok up` and `ok destroy`
- [ ] Split-plane compatibility: `ok config init --topology split-plane` (or the five path flags) still writes `ok-cli-paths/v1` with both kubeconfigs; legacy `ok cluster destroy` refuses a Same-Plane config

## D. Lifecycle (authorized disposable infrastructure only)

- [ ] `ok up` without `--management`: the banner says "management kubeconfig from saved configuration …". Identity (API, CA, kube-system UID) is shown; both typed confirmations are required
- [ ] Independent verification: nodes Ready, Cilium and CoreDNS Running, CAPI Cluster Available, KubeVirt VMs/VMIs Ready, PVCs Bound; sibling clusters unaffected
- [ ] `ok destroy <name>` without `--management`: same source line, UID and ledger checks, typed cluster name
- [ ] Independent absence checks for namespace, exact PVs, Longhorn volumes and Golden image cloner RBAC; the ledger ConfigMap persists; the Golden image is preserved
- [ ] Two disposable clusters from the same installation (OK-228 gate)

## E. Release gates (unchanged)

- [ ] Licensing and redistribution decision
- [ ] Provenance/signing decision (or an explicit unsigned Community Preview policy)
- [ ] Version and tag semantics decided; a tag only on the reviewed commit, and only with explicit approval
- [ ] Release notes state the limitations: Same-Plane only, prepared management cluster, unsigned, local CIDR inventory, no cross-version destroy, no name reuse
