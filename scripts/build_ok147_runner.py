#!/usr/bin/env python3
"""Plan or explicitly build the bounded OK-147 runner OCI archive."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile


FORMAT = "ok147-runner-image-build-plan/v1"
PLATFORMS = "linux/amd64,linux/arm64"
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--created", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--execute", action="store_true")
    return parser.parse_args()


def validate(args: argparse.Namespace, root: Path) -> tuple[Path, dt.datetime]:
    if not VERSION_RE.fullmatch(args.version):
        raise ValueError("version must be an explicit semantic version")
    if not REVISION_RE.fullmatch(args.revision):
        raise ValueError("revision must be a full lowercase Git commit")
    try:
        created = dt.datetime.fromisoformat(args.created.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("created must be RFC3339") from error
    if created.tzinfo is None:
        raise ValueError("created must include a timezone")
    output = Path(args.output).expanduser().resolve()
    if output.suffix != ".tar":
        raise ValueError("output must be an OCI .tar archive")
    if output.exists() or output.with_suffix(".sbom.spdx.json").exists() or output.with_suffix(".build-record.json").exists():
        raise ValueError("output, SBOM, or build record already exists")
    if not output.parent.is_dir():
        raise ValueError("output parent directory does not exist")
    if not (root / "Containerfile.ok147").is_file():
        raise ValueError("Containerfile.ok147 is missing")
    return output, created


def supply_chain_contract(root: Path) -> tuple[dict[str, object], str]:
    path = root / "build" / "ok147-runner-image.json"
    raw = path.read_bytes()
    document = json.loads(raw)
    if document.get("format") != "ok147-runner-image-build/v1":
        raise ValueError("runner image build contract format is invalid")
    if document.get("platforms") != PLATFORMS.split(","):
        raise ValueError("runner image platforms differ from the build contract")
    if document.get("networkPublication") != "disabled":
        raise ValueError("runner image build contract permits publication")
    containerfile = (root / "Containerfile.ok147").read_text()
    for field in ("dockerfileFrontend", "builderImage", "runtimeImage"):
        identity = document.get(field)
        if not isinstance(identity, str) or not re.search(r"@sha256:[0-9a-f]{64}$", identity):
            raise ValueError(f"{field} is not digest-bound")
        if identity not in containerfile:
            raise ValueError(f"{field} differs from Containerfile.ok147")
    return document, "sha256:" + hashlib.sha256(raw).hexdigest()


def build_command(root: Path, args: argparse.Namespace, output: Path, created: dt.datetime) -> list[str]:
    created_value = created.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    return [
        "docker", "buildx", "build",
        "--file", str(root / "Containerfile.ok147"),
        "--platform", PLATFORMS,
        "--provenance=mode=max",
        "--build-arg", f"VERSION={args.version}",
        "--build-arg", f"REVISION={args.revision}",
        "--build-arg", f"CREATED={created_value}",
        "--output", f"type=oci,dest={output}",
        str(root),
    ]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def inspect_oci_archive(path: Path) -> dict[str, object]:
    with tarfile.open(path, "r") as archive:
        try:
            member = archive.getmember("index.json")
        except KeyError as error:
            raise ValueError("OCI archive has no index.json") from error
        source = archive.extractfile(member)
        if source is None:
            raise ValueError("OCI archive has no readable index.json")
        raw = source.read()
    index = json.loads(raw)
    if index.get("schemaVersion") != 2 or not isinstance(index.get("manifests"), list):
        raise ValueError("OCI archive index is invalid")
    platforms: dict[str, str] = {}
    attestations: list[str] = []
    for descriptor in index["manifests"]:
        digest = descriptor.get("digest", "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("OCI index contains an invalid manifest digest")
        annotations = descriptor.get("annotations") or {}
        if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
            attestations.append(digest)
            continue
        platform = descriptor.get("platform") or {}
        identity = f"{platform.get('os')}/{platform.get('architecture')}"
        if identity not in PLATFORMS.split(","):
            raise ValueError(f"OCI archive contains unexpected platform {identity}")
        if identity in platforms:
            raise ValueError(f"OCI archive contains duplicate platform {identity}")
        platforms[identity] = digest
    if sorted(platforms) != sorted(PLATFORMS.split(",")):
        raise ValueError("OCI archive lacks an exact platform manifest set")
    if len(attestations) < 2:
        raise ValueError("OCI archive lacks per-platform provenance attestations")
    return {
        "ociIndexDigest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "platformManifestDigests": dict(sorted(platforms.items())),
        "provenanceManifestDigests": sorted(attestations),
    }


def write_exclusive(path: Path, value: object) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        output, created = validate(args, root)
        supply_chain, supply_chain_digest = supply_chain_contract(root)
        command = build_command(root, args, output, created)
        plan = {
            "format": FORMAT,
            "version": args.version,
            "revision": args.revision,
            "created": created.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "platforms": PLATFORMS.split(","),
            "output": str(output),
            "publish": False,
            "execute": args.execute,
            "supplyChainContractDigest": supply_chain_digest,
            "builderImage": supply_chain["builderImage"],
            "runtimeImage": supply_chain["runtimeImage"],
            "command": command,
        }
        if not args.execute:
            print(json.dumps(plan, sort_keys=True, indent=2))
            return 0
        if os.environ.get("OK147_IMAGE_BUILD") != "yes":
            raise ValueError("execution requires OK147_IMAGE_BUILD=yes")
        status = subprocess.run(["git", "status", "--porcelain"], cwd=root, check=True, capture_output=True, text=True)
        if status.stdout:
            raise ValueError("image build requires a clean worktree")
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
        if head != args.revision:
            raise ValueError("revision differs from the checked-out commit")
        subprocess.run(command, cwd=root, check=True)
        oci_identity = inspect_oci_archive(output)
        sbom = output.with_suffix(".sbom.spdx.json")
        subprocess.run(["syft", "scan", f"oci-archive:{output}", "--output", f"spdx-json={sbom}"], cwd=root, check=True)
        record = {
            **{key: value for key, value in plan.items() if key != "command"},
            "format": "ok147-runner-image-build-record/v1",
            "ociArchiveDigest": sha256(output),
            "sbomDigest": sha256(sbom),
            **oci_identity,
        }
        write_exclusive(output.with_suffix(".build-record.json"), record)
        print(json.dumps(record, sort_keys=True, indent=2))
        return 0
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
