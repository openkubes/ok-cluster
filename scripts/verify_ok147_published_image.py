#!/usr/bin/env python3
"""Fail-closed verifier for the bounded OK-147 GHCR publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys


FORMAT = "ok147-runner-publication-receipt/v1"
IMAGE = "ghcr.io/openkubes/ok-cluster-runner"
PLATFORMS = ("linux/amd64", "linux/arm64")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
RUN_URL_RE = re.compile(r"^https://github\.com/openkubes/ok-cluster/actions/runs/[1-9][0-9]*$")
PREDICATES = {
    "https://spdx.dev/Document",
    "https://slsa.dev/provenance/v1",
}


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def read_json(path: Path) -> tuple[bytes, object]:
    raw = path.read_bytes()
    return raw, json.loads(raw)


def verify_index(path: Path, expected_digest: str) -> tuple[dict[str, str], dict[str, str]]:
    if not DIGEST_RE.fullmatch(expected_digest):
        raise ValueError("expected digest is invalid")
    raw, document = read_json(path)
    if sha256_bytes(raw) != expected_digest:
        raise ValueError("pulled index differs from the published digest")
    if not isinstance(document, dict):
        raise ValueError("pulled index is not a JSON object")
    if document.get("schemaVersion") != 2:
        raise ValueError("pulled index has an invalid schema version")
    if document.get("mediaType") != "application/vnd.oci.image.index.v1+json":
        raise ValueError("published subject is not an OCI image index")
    descriptors = document.get("manifests")
    if not isinstance(descriptors, list):
        raise ValueError("published index has no manifest list")

    platforms: dict[str, str] = {}
    attestations: dict[str, str] = {}
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            raise ValueError("published index contains a non-object descriptor")
        digest = descriptor.get("digest", "")
        if not DIGEST_RE.fullmatch(digest):
            raise ValueError("published index contains an invalid descriptor digest")
        annotations = descriptor.get("annotations") or {}
        if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
            subject = annotations.get("vnd.docker.reference.digest", "")
            if not DIGEST_RE.fullmatch(subject) or subject in attestations:
                raise ValueError("published index contains invalid or duplicate attestation subjects")
            attestations[subject] = digest
            continue
        platform = descriptor.get("platform") or {}
        identity = f"{platform.get('os')}/{platform.get('architecture')}"
        if identity not in PLATFORMS or identity in platforms:
            raise ValueError(f"published index contains unexpected or duplicate platform {identity}")
        platforms[identity] = digest

    if tuple(sorted(platforms)) != tuple(sorted(PLATFORMS)):
        raise ValueError("published index lacks the exact platform set")
    if tuple(sorted(attestations)) != tuple(sorted(platforms.values())):
        raise ValueError("published index lacks one attestation manifest per platform")
    return dict(sorted(platforms.items())), dict(sorted(attestations.items()))


def verify_attestations(directory: Path, attestations: dict[str, str]) -> dict[str, object]:
    result: dict[str, object] = {}
    for subject, digest in attestations.items():
        path = directory / f"{digest.removeprefix('sha256:')}.json"
        raw, document = read_json(path)
        if sha256_bytes(raw) != digest:
            raise ValueError("pulled attestation manifest differs from its descriptor")
        if not isinstance(document, dict):
            raise ValueError("attestation manifest is not a JSON object")
        if document.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
            raise ValueError("attestation descriptor is not an OCI image manifest")
        layers = document.get("layers")
        if not isinstance(layers, list):
            raise ValueError("attestation manifest has no layers")
        predicates: set[str] = set()
        for layer in layers:
            if not isinstance(layer, dict) or layer.get("mediaType") != "application/vnd.in-toto+json":
                raise ValueError("attestation manifest contains a non-in-toto layer")
            predicate = (layer.get("annotations") or {}).get("in-toto.io/predicate-type")
            if not isinstance(predicate, str):
                raise ValueError("attestation layer has no predicate type")
            predicates.add(predicate)
        if predicates != PREDICATES:
            raise ValueError("attestation manifest lacks the exact SPDX and SLSA predicates")
        result[subject] = {
            "manifestDigest": digest,
            "predicateTypes": sorted(predicates),
        }
    return dict(sorted(result.items()))


def write_exclusive(path: Path, value: object) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list-attestations")
    listing.add_argument("--index", type=Path, required=True)
    listing.add_argument("--expected-digest", required=True)

    receipt = commands.add_parser("receipt")
    receipt.add_argument("--index", type=Path, required=True)
    receipt.add_argument("--attestations-dir", type=Path, required=True)
    receipt.add_argument("--github-attestation", type=Path, required=True)
    receipt.add_argument("--expected-digest", required=True)
    receipt.add_argument("--publication-contract-digest", required=True)
    receipt.add_argument("--image", required=True)
    receipt.add_argument("--source-sha", required=True)
    receipt.add_argument("--version", required=True)
    receipt.add_argument("--workflow-run-url", required=True)
    receipt.add_argument("--output", type=Path, required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        platforms, attestations = verify_index(args.index, args.expected_digest)
        if args.command == "list-attestations":
            for digest in sorted(attestations.values()):
                print(digest)
            return 0

        if args.image != IMAGE:
            raise ValueError("published image identity is not the bounded repository")
        if not REVISION_RE.fullmatch(args.source_sha):
            raise ValueError("source SHA is invalid")
        if not VERSION_RE.fullmatch(args.version):
            raise ValueError("version is invalid")
        if not DIGEST_RE.fullmatch(args.publication_contract_digest):
            raise ValueError("publication contract digest is invalid")
        if not RUN_URL_RE.fullmatch(args.workflow_run_url):
            raise ValueError("workflow run URL is invalid")
        if args.output.exists() or not args.output.parent.is_dir():
            raise ValueError("receipt output must be absent in an existing directory")
        _, github_attestation = read_json(args.github_attestation)
        if not github_attestation:
            raise ValueError("GitHub attestation verification result is empty")
        verified_attestations = verify_attestations(args.attestations_dir, attestations)
        record = {
            "format": FORMAT,
            "image": args.image,
            "digest": args.expected_digest,
            "sourceSha": args.source_sha,
            "version": args.version,
            "publicationContractDigest": args.publication_contract_digest,
            "workflowRunUrl": args.workflow_run_url,
            "platformManifestDigests": platforms,
            "attestations": verified_attestations,
            "githubAttestationVerificationDigest": sha256_file(args.github_attestation),
            "pullbackByDigestVerified": True,
            "networkPublicationPerformed": True,
            "deploymentPerformed": False,
            "clusterContactPerformed": False,
        }
        write_exclusive(args.output, record)
        print(json.dumps(record, sort_keys=True, indent=2))
        return 0
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
