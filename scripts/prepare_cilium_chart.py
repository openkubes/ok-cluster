#!/usr/bin/env python3
"""Acquire or verify the exact Cilium chart used by supported lifecycles."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.19.6"
FILENAME = f"cilium-{VERSION}.tgz"
AUTHORITATIVE_URL = f"https://helm.cilium.io/{FILENAME}"
EXPECTED_SHA256 = (
    "21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179"
)
DEFAULT_CACHE = ROOT / ".tools" / FILENAME


class ChartAcquisitionError(RuntimeError):
    """The requested chart cannot satisfy the pinned artifact contract."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path) -> str:
    if path.is_symlink():
        raise ChartAcquisitionError(f"refusing symlink chart: {path}")
    if not path.is_file():
        raise ChartAcquisitionError(f"Cilium chart is absent: {path}")
    observed = sha256(path)
    if observed != EXPECTED_SHA256:
        raise ChartAcquisitionError(
            f"Cilium chart digest mismatch at {path}: "
            f"observed sha256:{observed}, expected sha256:{EXPECTED_SHA256}"
        )
    return observed


def download(destination: Path) -> None:
    request = urllib.request.Request(
        AUTHORITATIVE_URL,
        headers={"User-Agent": "ok-cluster-cilium-chart-acquisition/1"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        if getattr(response, "status", 200) != 200:
            raise ChartAcquisitionError(
                f"authoritative repository returned HTTP {response.status}"
            )
        with destination.open("wb") as stream:
            shutil.copyfileobj(response, stream)
            stream.flush()
            os.fsync(stream.fileno())


def prepare(
    cache: Path,
    *,
    source: Path | None = None,
    verify_only: bool = False,
) -> str:
    cache = cache.expanduser().resolve()
    if cache.exists() or cache.is_symlink():
        digest = verify(cache)
        return f"REUSED {cache} sha256:{digest}"
    if verify_only:
        raise ChartAcquisitionError(f"Cilium chart is absent: {cache}")

    cache.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{FILENAME}.",
            suffix=".tmp",
            dir=cache.parent,
        )
        os.close(descriptor)
        temporary_path = Path(temporary)
        if source is None:
            download(temporary_path)
        else:
            resolved_source = source.expanduser().resolve()
            if not resolved_source.is_file() or resolved_source.is_symlink():
                raise ChartAcquisitionError(
                    f"offline chart source is not a regular file: "
                    f"{resolved_source}"
                )
            with resolved_source.open("rb") as incoming:
                with temporary_path.open("wb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
        digest = verify(temporary_path)
        temporary_path.chmod(0o644)
        os.replace(temporary_path, cache)
        temporary_path = None
        return f"READY {cache} sha256:{digest}"
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", default=str(DEFAULT_CACHE))
    parser.add_argument("--source")
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = Path(args.source) if args.source else None
    print(
        prepare(
            Path(args.cache),
            source=source,
            verify_only=args.verify_only,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ChartAcquisitionError, OSError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
