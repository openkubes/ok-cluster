# OpenKubes release process (ok-cluster and the `ok` CLI)

## Versions

- **Semantic Versioning** (`vMAJOR.MINOR.PATCH`) for every release from v1.0.1 on. The next patch release after v1.0.1 is **v1.0.2**.
- **One version for both.** A GitHub release `vX.Y.Z` of `openkubes/ok-cluster` and the `ok` CLI built from it carry the same version. `ok version` prints `vX.Y.Z <full commit>`.
- **There is no v1.0.0.** The previous repository release is `v0.15.0`, and the first `1.x` release is v1.0.1. Before tagging, the tag history is checked: on 2026-11-14 no `v1.*` tag or GitHub release existed.

## Acceptance builds versus official releases

| | Acceptance build | Official release |
|---|---|---|
| Version | `vX.Y.Z-rcN` (for example `v1.0.1-rc3`) | `vX.Y.Z` |
| Git tag | none: the full commit SHA identifies it | `vX.Y.Z`, created only after explicit approval, pointing at the exact approved commit |
| Command | `make ok-rc-acceptance RC_VERSION=… RC_COMMIT=…` | `make ok-release-acceptance RELEASE_VERSION=… RELEASE_COMMIT=…` |
| Default output | `../rc-artifacts/<version>` | `../release-artifacts/<version>` |
| Published | never | as a GitHub release, after the checklist below |

The two never mix:
- An acceptance build refuses an official version.
- An official build refuses an `-rc` version.
- An official build refuses to run unless the local tag `vX.Y.Z` already points at `--commit`.
- `build_release_bundle.sh` independently refuses an official version whose tag doesn't point at the packaged commit.
- Neither command creates, moves or pushes tags. Neither publishes anything, runs `ok up`/`ok destroy`, contacts a cluster, or changes `PATH`, `~/.local/bin/ok` or the user's configuration.

## What `scripts/ok-rc-acceptance.sh` checks

Both make targets run it. It needs to run as a normal user, with `git`, `go`, `python3`, `tar` and `sha256sum` or `shasum`. It writes `acceptance-<version>-<UTC time>.json` next to the artifacts. **Reporting boundary:** a setup refusal before the output location is accepted (arguments, version format, root, missing tools, `ok-linux`/chart paths, `--out`/`--work` location, an existing report name) exits **2** with no report, and says so on stderr: nothing has been built and there is no accepted place for a report yet. Every failure from step 1 on exits **1** and is recorded in the report as `"result": "FAIL"` with the failed step; a pass exits 0 with `"PASS"`.

1. **source:** `ok-cluster` HEAD equals `--commit` and is clean. Official builds: the tag points at `--commit`. `ok-linux` is at the commit pinned in `cmd/ok/cluster_provision.go` and is clean. The Cilium chart matches the pinned SHA-256.
2. **tests:** `go vet ./cmd/ok`, `go test ./cmd/ok`, `tests/release_bundle_test.py`, `tests/install_ok_test.py`.
3. **build:** darwin/arm64 and linux/amd64 bundles into a new or empty output directory (never overwritten, never inside a checkout).
4. **verify:** each archive against its `.sha256`, and `release.txt` version, platform and both commits.
5. **smoke:** isolated and offline, for the bundle native to the machine running it:
   - `install-ok.sh` into a private prefix, then `ok version`;
   - a second install is refused;
   - `ok config init` without `--yes` is refused; with `--yes` it saves to an isolated file;
   - `ok config show` (text and `-o json`);
   - `ok cluster plan`.
6. **final:** sources unchanged; the user's `~/.local/bin/ok` and default config file unchanged.

A PASS means the artifacts are consistent and install correctly. **It is not a stable-release approval.**

## Running it

Prepare sibling checkouts: `ok-cluster` at the approved commit, clean; `ok-linux` at the pinned commit, clean. Have the pinned chart at `ok-cluster/.tools/cilium-1.19.6.tgz`, from `make prepare-cilium-chart` or the accepted bundle.

```bash
cd ok-cluster
git switch --detach <approved-commit>
make ok-rc-acceptance RC_VERSION=v1.0.1-rc3 RC_COMMIT=<approved-commit>
# Re-check existing artifacts, for example on the other platform after copying them:
make ok-rc-smoke-install RC_VERSION=v1.0.1-rc3 RC_COMMIT=<approved-commit> RC_OUT=<dir with the artifacts>
```

Overrides: `OK_LINUX_PATH=…`, `CILIUM_CHART=…`, `RC_OUT=…`, `RC_WORK=…` (where the isolated smoke installs and logs go; by default a new directory under `$TMPDIR`, kept for inspection).

**Each machine smoke-tests only its native bundle.** Run `ok-rc-smoke-install` on the other platform too, natively: macOS ARM64 on a Mac, Linux AMD64 on Linux or WSL2. Building uses the Go module cache or proxy as configured for `go build`; the smoke test needs no network.

## Official build pipeline: GitHub Actions

**`.github/workflows/ok-cli-build.yaml` ("OK CLI build and acceptance") is the primary build system.** It runs the same `make` targets and script as above, so there is no second copy of the build logic in YAML.

| Property | How |
|---|---|
| Trigger | manual only: **Actions → OK CLI build and acceptance → Run workflow** on `main`. Inputs: `version`, `commit` (full 40-character SHA), `release` (default off) and `attest` (default off). Dispatch needs write access. There is no `pull_request` trigger, so PR code never runs here. |
| Commit identity | a `bind` job validates the inputs (passed via `env`, never interpolated into shell). It checks out exactly `commit` and requires it to be on `main`. For `release=true`, the tag `version` must already point at `commit`, and the script checks that again. |
| Runners and toolchain | `macos-15` builds and accepts `darwin-arm64`, `ubuntu-24.04` builds and accepts `linux-amd64`, each natively (`--targets`). Go **1.24.13** is pinned explicitly, without a dependency cache. |
| Checks | per runner, the full script: source identity (clean commit, pinned `ok-linux`, chart SHA-256), tests, native build, `.sha256`, `release.txt`, isolated install and first-run smoke. |
| Outputs | Actions artifacts `ok-<version>-<target>` (bundle, `.sha256`, acceptance report JSON; kept 30 days), and logs on failure. Nothing is installed outside the runner. |
| Permissions | the workflow default is `{}`. Build jobs get `contents: read` only, with `persist-credentials: false`. Only the opt-in `attest` job gets `id-token: write` / `attestations: write`; it runs no repository code, only downloads the bundles, re-checks their SHA-256 and calls `actions/attest`. |
| Pins | `actions/checkout` v4.4.0, `setup-go` v7.0.0, `upload-artifact` v4.6.2, `download-artifact` v4.3.0, `attest` v4.2.2, all pinned by full commit SHA. |
| Never | creates or pushes tags, creates or publishes a GitHub release, or merges. |

**Attestations (evaluation).** `attest=true` creates a GitHub artifact attestation (signed SLSA build provenance) for each bundle; it can be verified with `gh attestation verify <bundle> --repo openkubes/ok-cluster`.
- This repository is public, so each attestation is also written to **Sigstore's public transparency log**. That is a form of publication, which is why it is opt-in and should be used only for an approved official build.
- Recommended before first use: give the `attest` job a protected GitHub environment with required reviewers.
- Attestations prove which workflow run built a file from which commit. They don't replace the release gates, and the bundles remain unsigned and not notarized for macOS Gatekeeper.

### Promoting an accepted commit to the official v1.0.1

Each arrow is a recorded owner decision; nothing below happens automatically.

1. **Merge** the release PR after review, with all CI checks green. Record the merge commit's full SHA as `C`.
2. **Acceptance build:** run the workflow with `version=v1.0.1-rc3`, `commit=C`, `release=false`, `attest=false`. Both jobs must pass. Download the artifacts; keep the two acceptance reports as evidence.
3. **Lifecycle safety gates** with those artifacts, on separately authorized disposable infrastructure (`docs/cli-v1.0.1-release-acceptance.md`, sections D and E). If anything fails, fix it on a new PR, which gives a new `C` and `-rc4`, and repeat.
4. **Decisions recorded:** licensing/redistribution, provenance/signing policy (including whether to attest), final release notes.
5. → **Approval to tag.** A maintainer runs `git fetch origin && git tag -a v1.0.1 -m "v1.0.1" C && git rev-parse v1.0.1^{commit}` (it must print `C`), then `git push origin refs/tags/v1.0.1`, then `git ls-remote origin refs/tags/v1.0.1^{}` (it must show `C`).
6. **Official build:** run the workflow with `version=v1.0.1`, `commit=C`, `release=true`, and `attest` as decided in step 4. It refuses unless the tag points at `C`. Download both bundles, their `.sha256` and the reports; check `sha256sum -c`, `release.txt` (`version: v1.0.1`, `ok-cluster commit: C`) and, if attested, `gh attestation verify`.
7. → **Approval to publish.** Create a **draft** GitHub release for tag `v1.0.1`. Attach the two official bundles, their `.sha256` files and `scripts/install-ok.sh` from `C`, and the release notes with the SHA-256 values. Re-download the attachments, verify them, then publish. Announce the SHA-256 values through a second channel.
8. The next patch release is **v1.0.2**, through the same steps.

## Release checklist (GitHub release `vX.Y.Z`)

Each step needs a recorded owner decision. Nothing is tagged, published or merged without explicit approval.

1. [ ] The release PR is reviewed and merged; CI is green on the merge commit. Record the full SHA as the approved commit.
2. [ ] An acceptance build of that exact commit (`vX.Y.Z-rcN`) passes in the **OK CLI build and acceptance** workflow, natively on both platforms (local fallback: `make ok-rc-acceptance`, plus `ok-rc-smoke-install` natively on the other platform).
3. [ ] **Lifecycle safety gates** pass with those artifacts on separately authorized disposable infrastructure (see `docs/cli-v1.0.1-release-acceptance.md`, sections D and E): `ok up`, independent verification, `ok destroy`, independent absence checks, two clusters from one installation. **No stable declaration before this.**
4. [ ] Licensing/redistribution and provenance/signing decisions are recorded (or an explicit unsigned-preview policy).
5. [ ] Release notes are final (`docs/release-notes/vX.Y.Z.md`, limitations included).
6. [ ] **Approval to tag.** Then: `git tag -a vX.Y.Z -m "vX.Y.Z" <approved commit>`, and confirm `git rev-parse vX.Y.Z^{commit}` equals the approved commit. Push only that tag, and confirm the remote tag resolves to the same commit.
7. [ ] Official build: the workflow with `release=true` (local fallback: `make ok-release-acceptance RELEASE_VERSION=vX.Y.Z RELEASE_COMMIT=<approved commit>`). Official artifacts are rebuilt from the tag, never renamed acceptance artifacts.
8. [ ] **Approval to publish.** Create a draft GitHub release for the tag. Attach both `.tar.gz`, their `.sha256` and `install-ok.sh`. Paste the notes and the SHA-256 values. Re-download the attachments and check them against the recorded values before publishing.
9. [ ] Announce the SHA-256 values through a second channel. The next development version is `vX.Y.(Z+1)`.
