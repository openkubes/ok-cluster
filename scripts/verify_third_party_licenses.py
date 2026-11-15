#!/usr/bin/env python3
"""Verify the checked-in attribution collection without network access."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = ("darwin/arm64", "darwin/amd64", "linux/amd64")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify(root=ROOT, platforms=PLATFORMS):
    collection = root / "THIRD_PARTY_LICENSES"
    manifest = json.loads((collection / "manifest.json").read_text())
    if manifest["schema"] != 1 or set(manifest["package_inventory_sha256"]) != set(PLATFORMS):
        raise ValueError("unsupported attribution manifest schema or platforms")
    actual = {p.relative_to(collection).as_posix() for p in collection.rglob("*")
              if p.is_file() and p.name not in ("manifest.json", "README.md")}
    if actual != set(manifest["files"]):
        raise ValueError("attribution file inventory mismatch")
    scopes = set()
    for name, record in manifest["files"].items():
        path = collection / name
        if path.is_symlink() or sha256(path.read_bytes()) != record["sha256"]:
            raise ValueError(f"attribution checksum mismatch: {name}")
        if path.name == "LICENSE":
            scopes.add(path.parent.relative_to(collection).as_posix())

    for target in platforms:
        if target not in PLATFORMS:
            raise ValueError(f"unsupported attribution platform: {target}")
        goos, goarch = target.split("/")
        env = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local",
                   GOWORK="off", GOFLAGS="", CGO_ENABLED="0", GOOS=goos, GOARCH=goarch)
        template = ("{{if and .Module (not .Module.Main)}}{{.ImportPath}} "
                    "{{.Module.Path}} {{.Module.Version}}"
                    "{{if .Module.Replace}} REPLACED{{end}}{{end}}")
        result = subprocess.run(["go", "list", "-mod=readonly", "-deps", "-f", template, "./cmd/ok"],
                                cwd=root, env=env, capture_output=True, text=True, check=True)
        lines = sorted(filter(None, result.stdout.splitlines()))
        modules = {}
        for line in lines:
            package, module, version = line.split()  # replacements fail closed
            modules[module] = version
            if not any(package == scope or package.startswith(scope + "/") for scope in scopes):
                raise ValueError(f"missing package attribution: {package} ({target})")
        if modules != manifest["modules"]:
            raise ValueError(f"linked module versions differ from attribution manifest ({target})")
        if sha256(("\n".join(lines) + "\n").encode()) != manifest["package_inventory_sha256"][target]:
            raise ValueError(f"linked packages changed; review attribution coverage ({target})")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=PLATFORMS, help="default: verify all supported platforms")
    args = parser.parse_args()
    verify(platforms=(args.platform,) if args.platform else PLATFORMS)
    print("Third-party LICENSE/NOTICE collection verified (offline)")


if __name__ == "__main__":
    main()
