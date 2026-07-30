#!/usr/bin/env python3
"""Offline tests for the pinned Cilium chart acquisition workflow."""

from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scripts.prepare_cilium_chart as acquisition  # noqa: E402


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS {message}")


def main() -> int:
    check(
        acquisition.VERSION == "1.19.6"
        and acquisition.AUTHORITATIVE_URL
        == "https://helm.cilium.io/cilium-1.19.6.tgz"
        and acquisition.EXPECTED_SHA256
        == "21c43cf53841f9ab0375047d95aa4c64051ea52bbd2c679416e6408f5f1c9179",
        "version, authoritative source, and digest are exact pins",
    )
    original_digest = acquisition.EXPECTED_SHA256
    try:
        payload = b"offline pinned chart fixture\n"
        acquisition.EXPECTED_SHA256 = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory(
            prefix=".cilium-tool-test-", dir=ROOT
        ) as temporary:
            directory = Path(temporary)
            source = directory / "predownloaded.tgz"
            cache = directory / ".tools" / acquisition.FILENAME
            source.write_bytes(payload)
            ready = acquisition.prepare(cache, source=source)
            first_mtime = cache.stat().st_mtime_ns
            source.write_bytes(b"a different source must not replace cache")
            reused = acquisition.prepare(cache, source=source)
            check(
                ready.startswith("READY ")
                and reused.startswith("REUSED ")
                and cache.read_bytes() == payload
                and cache.stat().st_mtime_ns == first_mtime,
                "valid cache is atomically published and idempotently reused",
            )
            cache.write_bytes(b"corrupt")
            try:
                acquisition.prepare(cache, source=source)
            except acquisition.ChartAcquisitionError:
                mismatch_failed = True
            else:
                mismatch_failed = False
            check(
                mismatch_failed and cache.read_bytes() == b"corrupt",
                "invalid cache fails closed without silent replacement",
            )
            absent = directory / "absent" / acquisition.FILENAME
            try:
                acquisition.prepare(absent, verify_only=True)
            except acquisition.ChartAcquisitionError:
                verify_only_failed = True
            else:
                verify_only_failed = False
            check(
                verify_only_failed,
                "verify-only mode never performs an implicit download",
            )
            downloaded = directory / "download" / acquisition.FILENAME
            original_download = acquisition.download
            download_calls = []

            def fake_download(destination: Path) -> None:
                download_calls.append(destination)
                destination.write_bytes(payload)

            acquisition.download = fake_download
            try:
                acquisition.prepare(downloaded)
            finally:
                acquisition.download = original_download
            check(
                download_calls
                and downloaded.read_bytes() == payload,
                "online mode stages the authoritative download before publish",
            )
            check(
                not list(cache.parent.glob("*.tmp")),
                "atomic staging leaves no temporary artifact",
            )
    finally:
        acquisition.EXPECTED_SHA256 = original_digest

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    talos_install = makefile.split(
        'if [ "$$CLUSTER_TYPE" = "talos" ] || '
        '[ "$$CLUSTER_TYPE" = "talos-mgmt" ]; then',
        1,
    )[1].split("\n\telse \\", 1)[0]
    check(
        "prepare-cilium-chart:" in makefile
        and "--verify-only" in makefile
        and 'FLATCAR_CILIUM_CHART="$(pwd)/.tools/cilium-1.19.6.tgz"'
        in readme,
        "supported Make and explicit Flatcar usage are documented",
    )
    check(
        'helm upgrade --install cilium "$(CILIUM_CHART)"' in talos_install
        and "cilium/cilium" not in talos_install,
        "Talos provisioning uses only the pre-verified local chart",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
