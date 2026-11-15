# OpenKubes CLI third-party attributions

This collection accompanies `./cmd/ok` for darwin/arm64, darwin/amd64 and
linux/amd64 with CGO disabled. It preserves all 33 LICENSE and NOTICE files
from the pre-generated `third-party-licenses` collection byte for byte,
including OpenKubes' own license and the separately licensed Kubernetes Go
forks. Paths identify the package scopes used by the original collection;
they are not necessarily the upstream file paths.

`manifest.json` records the 27 linked third-party modules and their pinned
versions, each file's upstream module-relative source path and SHA-256, and
a digest of the linked package inventory for each platform. The OpenKubes
entry refers to this repository's `LICENSE`. Requirements in `go.mod` that
are not imported by `./cmd/ok` are deliberately excluded. Standard-library
packages are supplied by the Go toolchain and are outside this collection.

Verify from the repository root:

```sh
python3 -B scripts/verify_third_party_licenses.py
```

Verification uses only the checked-in collection and the local Go module
cache, with GOPROXY and GOSUMDB disabled. Missing cached dependencies fail
instead of downloading. Official bundle builds verify their target before
copying this directory to the archive root; no license service or additional
runtime dependency is required.

When dependencies change, regenerate and review the attribution collection
for all three platforms. Preserve upstream texts, including NOTICE files and
licenses for code copied into dependencies. Compare each collected file to
the `source` in its pinned module cache directory. Update the file digests
and module versions only after reviewing that comparison. Package inventory
digests are SHA-256 of sorted, nonempty lines (each ending in a newline) from:

```sh
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 GOPROXY=off GOSUMDB=off GOWORK=off \
  go list -mod=readonly -deps \
  -f '{{if and .Module (not .Module.Main)}}{{.ImportPath}} {{.Module.Path}} {{.Module.Version}}{{end}}' ./cmd/ok
```

Repeat for darwin/amd64 and linux/amd64. The current inventories are identical;
each platform is checked independently to detect future build-tag differences.
