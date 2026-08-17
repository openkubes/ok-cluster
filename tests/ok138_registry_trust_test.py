#!/usr/bin/env python3
"""Offline acceptance checks for OK-138 Talos registry trust."""
from __future__ import annotations

import importlib.util
import base64
import ipaddress
import os
from pathlib import Path
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location(
    "talos_registry_trust", ROOT / "scripts/talos_registry_trust.py"
)
assert SPEC and SPEC.loader
trust = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trust)
RENDER_SPEC = importlib.util.spec_from_file_location("render", ROOT / "render.py")
assert RENDER_SPEC and RENDER_SPEC.loader
renderer = importlib.util.module_from_spec(RENDER_SPEC)
RENDER_SPEC.loader.exec_module(renderer)

HOST = "registry.ok-shared.internal"
ADDRESS = "198.51.100.27"
CA = b"""-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIUfEe/v6k2f0HSSgLT7RppPHBXZm4wDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwOT0stMTM4IFRlc3QgQ0EwHhcNMjYwODExMDUwMTI1WhcN
MzYwODA4MDUwMTI1WjAZMRcwFQYDVQQDDA5PSy0xMzggVGVzdCBDQTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAK9EDcgg1mGkQ7M/+n6eM7CkEPBBEKrm
jKgzBelgBMHRUE1JV8XNSgnRJDOkIS9IWW5jLdkQko0v6JuLYb1BaCR5tSmlDyq+
Yykyit4nqJuKPyUpHqCm73ICqD9ZwgLWCJ+0oBuzOzyBzOt2VoBJFLhyccMlg+aw
m87JAVsuuC7GTwqGgVjVcl/ZMvD96/lLg3zCTFM+GQFf34GfwXHD029vzWCxgQur
2ZCAu9yav54WPTT6cVBDisBg+CllliKJfdlK1MUvT1/AK6OxTrUKfHHI9l/JFRKG
2EUaDMWJJIcJSfaYvqtCkc6oS+TfXjFDEjT01bv7+jc7MSgh3gdx0GsCAwEAAaNT
MFEwHQYDVR0OBBYEFHgHRp1y31Yv3tSfAF6WbA4iBsu1MB8GA1UdIwQYMBaAFHgH
Rp1y31Yv3tSfAF6WbA4iBsu1MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAB+GsgezWyKh8cP6k+PBGOKEy4ZifSZr+UOaWCBXSbWd/2z5YCfh9koC
Nw+XAZzcO6kHEw9A99DIcGnKCRyHmbrmi052cDANblvSwcZ19jJJoehSk6b+cThv
23p/vvvYocScehaCo8ydVgu3WWdZg2Rab0AY9i5QiHpCdQM8DJG/fTQO3pfSyOAr
YCsDRWTmZxY0YGNmKcODUY0W/6mgL0xCdllyqxA2bSNVKkGiCYNjHNs3lnOofG1a
tXGR1YHWKK+tzJAfXwpGZlrAbYGR0Z176qaNMD0C8A6/HbwLM2YhxhjXB2OM77FP
kh1bGN4EJWU6UI/A5gk7iaLQ/Bv1uCE=
-----END CERTIFICATE-----
"""


def base_manifest() -> bytes:
    return yaml.safe_dump_all([
        {
            "apiVersion": "controlplane.cluster.x-k8s.io/v1alpha3",
            "kind": "TalosControlPlane",
            "spec": {"controlPlaneConfig": {"controlplane": {"configPatches": []}}},
        },
        {
            "apiVersion": "bootstrap.cluster.x-k8s.io/v1alpha3",
            "kind": "TalosConfigTemplate",
            "spec": {"template": {"spec": {"configPatches": []}}},
        },
    ], sort_keys=False).encode()


class RegistryTrustTest(unittest.TestCase):
    def test_default_off_has_no_rendered_effect(self) -> None:
        for path in ROOT.glob("ok-*/cluster-config.yaml"):
            cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if "registryTrust" not in cfg:
                self.assertNotIn("registry.ok-shared.internal", path.read_text(encoding="utf-8"))
        source = (ROOT / "new-cluster.sh").read_text(encoding="utf-8")
        self.assertIn('REGISTRY_TRUST="${REGISTRY_TRUST:-false}"', source)
        cfg = {"name": "default-off", "type": "talos"}
        before = dict(cfg)
        renderer.validate_registry_trust(cfg)
        self.assertEqual(cfg, before)
        source_cfg = yaml.safe_load(
            (ROOT / "ok-ai" / "cluster-config.yaml").read_text(encoding="utf-8")
        )
        source_cfg.pop("registryTrust", None)
        with tempfile.TemporaryDirectory(
            prefix=".ok138-default-off-", dir=ROOT
        ) as temp:
            output = Path(temp)
            renderer.render_cluster("ok-ai", output, source_cfg)
            rendered = "\n".join(
                path.read_text(encoding="utf-8")
                for path in output.iterdir()
                if path.is_file()
            )
        self.assertNotIn("registryTrust", rendered)
        self.assertNotIn(HOST, rendered)

    def test_opt_in_control_plane_worker_parity(self) -> None:
        docs = list(yaml.safe_load_all(trust.hydrate_manifest(base_manifest(), HOST, ADDRESS, CA)))
        cp = docs[0]["spec"]["controlPlaneConfig"]["controlplane"]["configPatches"]
        worker = docs[1]["spec"]["template"]["spec"]["configPatches"]
        self.assertEqual(cp, worker)
        self.assertEqual(cp, trust.capi_ops(HOST, ADDRESS, CA))
        existing = [
            {"op": "add", "path": "/cluster/proxy", "value": {"disabled": True}},
            {
                "op": "add",
                "path": "/machine/registries",
                "value": {
                    "mirrors": {"docker.io": {"endpoints": ["https://cache.invalid"]}},
                    "config": {HOST: {"auth": {"username": "kept"}}},
                },
            },
            {
                "op": "add",
                "path": "/machine/network/extraHostEntries",
                "value": [
                    {"ip": "198.51.100.9", "aliases": ["kept.invalid", HOST]}
                ],
            },
        ]
        updated = trust.upsert_capi_patches(existing, HOST, ADDRESS, CA)
        self.assertEqual(updated[0], existing[0])
        self.assertIn("docker.io", updated[1]["value"]["mirrors"])
        self.assertEqual(
            updated[1]["value"]["config"][HOST]["auth"]["username"], "kept"
        )
        self.assertEqual(
            updated[2]["value"],
            [
                {"ip": "198.51.100.9", "aliases": ["kept.invalid"]},
                {"ip": ADDRESS, "aliases": [HOST]},
            ],
        )
        self.assertEqual(
            trust.upsert_capi_patches(updated, HOST, ADDRESS, CA), updated
        )
        with self.assertRaises(trust.TrustError):
            trust.upsert_capi_patches(
                [
                    {
                        "op": "add",
                        "path": "/machine/registries/mirrors",
                        "value": {"docker.io": {"endpoints": ["https://cache.invalid"]}},
                    }
                ],
                HOST,
                ADDRESS,
                CA,
            )

    def test_runtime_and_declarative_semantics_are_equivalent(self) -> None:
        runtime = yaml.safe_load(trust.render_patch(HOST, ADDRESS, CA))
        ops = trust.capi_ops(HOST, ADDRESS, CA)
        self.assertEqual(ops[0]["value"], runtime["machine"]["registries"])
        self.assertEqual(
            ops[1]["value"], runtime["machine"]["network"]["extraHostEntries"]
        )
        encoded = runtime["machine"]["registries"]["config"][HOST]["tls"]["ca"]
        self.assertEqual(base64.b64decode(encoded), CA)

    def test_runtime_upsert_preserves_unrelated_config_and_is_idempotent(self) -> None:
        current = {
            "machine": {
                "registries": {
                    "mirrors": {"docker.io": {"endpoints": ["https://cache.invalid"]}},
                    "config": {HOST: {"auth": {"username": "kept"}}},
                },
                "network": {
                    "extraHostEntries": [
                        {"ip": "198.51.100.10", "aliases": ["kept.invalid", HOST]},
                    ]
                },
            }
        }
        first = trust.runtime_ops(current, HOST, ADDRESS, CA)
        registries = first[0]["value"]
        entries = first[1]["value"]
        self.assertIn("docker.io", registries["mirrors"])
        self.assertEqual(registries["config"][HOST]["auth"]["username"], "kept")
        self.assertEqual(entries[0], {"ip": "198.51.100.10", "aliases": ["kept.invalid"]})
        self.assertEqual(entries[1], {"ip": ADDRESS, "aliases": [HOST]})
        reapplied = trust.runtime_ops(
            {"machine": {"registries": registries, "network": {"extraHostEntries": entries}}},
            HOST, ADDRESS, CA,
        )
        self.assertEqual(reapplied, first)

    def test_fragment_and_normal_render_contain_no_hydrated_values(self) -> None:
        fragment = trust.PATCH_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn("${REGISTRY_CA_BASE64}", fragment)
        self.assertIn("${REGISTRY_ADDRESS}", fragment)
        for path in list((ROOT / "templates").rglob("*.tpl")) + list(ROOT.glob("ok-*/*.yaml")):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(ADDRESS, text, str(path))
            self.assertNotIn(CA.decode(), text, str(path))

        capability_files = [
            ROOT / "docs/registry-trust.md",
            ROOT / "scripts/talos_registry_trust.py",
            ROOT / "templates/talos/patches/registry-trust.yaml.tpl",
        ]
        for path in capability_files:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("-----BEGIN CERTIFICATE-----", text, str(path))
            for token in text.replace("'", " ").replace('"', " ").split():
                candidate = token.strip("<>()[]{},:;`$\\")
                try:
                    address = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                self.assertTrue(address.is_reserved, f"estate-like IP in {path}: {address}")

    def test_negative_guards(self) -> None:
        with self.assertRaises(trust.TrustError):
            trust._single_ip([], "test")
        with self.assertRaises(trust.TrustError):
            trust._single_ip([ADDRESS, "198.51.100.28"], "test")
        with self.assertRaises(trust.TrustError):
            trust._single_ip(["registry.invalid"], "test")
        with self.assertRaises(SystemExit):
            renderer.validate_registry_trust(
                {"name": "bad", "type": "talos", "registryTrust": {"enabled": False}}
            )
        source = (ROOT / "scripts/talos_registry_trust.py").read_text(encoding="utf-8")
        self.assertIn('os.environ.get("REGISTRY_TRUST_APPLY") != "yes"', source)
        self.assertIn('"--mode", "no-reboot"', source)
        self.assertIn('argv.append("--dry-run")', source)
        self.assertNotIn("tempfile", source)
        self.assertIn("os.memfd_create", source)

    def test_talosctl_v195_complete_config_validation(self) -> None:
        if not hasattr(os, "memfd_create"):
            self.skipTest("complete Talos validation requires Linux anonymous memfd support")
        try:
            version = trust.run(["talosctl", "version", "--client"])
        except trust.TrustError as exc:
            self.skipTest(str(exc))
        if b"Tag: v1.9.5" not in version:
            self.skipTest("complete Talos validation requires talosctl v1.9.5")
        trust.validate_with_talosctl(trust.render_patch(HOST, ADDRESS, CA))


if __name__ == "__main__":
    unittest.main(verbosity=2)
