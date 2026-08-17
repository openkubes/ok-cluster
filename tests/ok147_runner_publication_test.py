import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_ok147_published_image", ROOT / "scripts" / "verify_ok147_published_image.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class RunnerPublicationTest(unittest.TestCase):
    def fixture(self, temporary):
        root = Path(temporary)
        attestations_dir = root / "attestations"
        attestations_dir.mkdir()
        platform_digests = {
            "linux/amd64": "sha256:" + "a" * 64,
            "linux/arm64": "sha256:" + "b" * 64,
        }
        attestation_descriptors = []
        for platform_digest in platform_digests.values():
            manifest = {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "layers": [
                    {
                        "mediaType": "application/vnd.in-toto+json",
                        "annotations": {"in-toto.io/predicate-type": "https://spdx.dev/Document"},
                    },
                    {
                        "mediaType": "application/vnd.in-toto+json",
                        "annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"},
                    },
                ],
            }
            raw = canonical(manifest)
            digest = MODULE.sha256_bytes(raw)
            (attestations_dir / f"{digest.removeprefix('sha256:')}.json").write_bytes(raw)
            attestation_descriptors.append({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": digest,
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": platform_digest,
                },
                "platform": {"os": "unknown", "architecture": "unknown"},
            })
        index = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": digest,
                    "platform": {"os": platform.split("/")[0], "architecture": platform.split("/")[1]},
                }
                for platform, digest in platform_digests.items()
            ] + attestation_descriptors,
        }
        index_path = root / "index.json"
        index_path.write_bytes(canonical(index))
        return index_path, attestations_dir, MODULE.sha256_file(index_path)

    def test_verifier_accepts_exact_platform_and_attestation_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            index, directory, digest = self.fixture(temporary)
            platforms, attestations = MODULE.verify_index(index, digest)
            self.assertEqual(tuple(platforms), MODULE.PLATFORMS)
            verified = MODULE.verify_attestations(directory, attestations)
            self.assertEqual(len(verified), 2)
            for value in verified.values():
                self.assertEqual(set(value["predicateTypes"]), MODULE.PREDICATES)

    def test_index_digest_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            index, _, _ = self.fixture(temporary)
            with self.assertRaisesRegex(ValueError, "differs from the published digest"):
                MODULE.verify_index(index, "sha256:" + "f" * 64)

    def test_missing_sbom_predicate_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            index, directory, digest = self.fixture(temporary)
            _, attestations = MODULE.verify_index(index, digest)
            first = next(iter(directory.glob("*.json")))
            document = json.loads(first.read_text())
            document["layers"] = document["layers"][1:]
            first.write_bytes(canonical(document))
            with self.assertRaisesRegex(ValueError, "differs from its descriptor"):
                MODULE.verify_attestations(directory, attestations)

    def test_publication_contract_is_dispatch_only_and_digest_bound(self):
        contract = json.loads((ROOT / "build" / "ok147-runner-publication.json").read_text())
        self.assertEqual(contract["networkPublication"], "workflow-dispatch-only")
        self.assertEqual(contract["tagTemplate"], "sha-<12>-run-<run-id>")
        self.assertEqual(contract["platforms"], list(MODULE.PLATFORMS))
        self.assertRegex(contract["sbomGeneratorImage"], r"@sha256:[0-9a-f]{64}$")

    def test_workflow_is_pinned_protected_and_has_no_automatic_trigger(self):
        raw = (ROOT / ".github" / "workflows" / "ok147-runner-publisher.yaml").read_text()
        self.assertIn('"on":\n  workflow_dispatch:', raw)
        self.assertNotRegex(raw, r"(?m)^  (push|pull_request|schedule):\s*$")
        self.assertIn("environment: ok-147-runner-publish", raw)
        self.assertIn("if: github.ref == 'refs/heads/main'", raw)
        self.assertIn("provenance: mode=max", raw)
        contract = json.loads((ROOT / "build" / "ok147-runner-publication.json").read_text())
        self.assertIn(f"sbom: generator={contract['sbomGeneratorImage']}", raw)
        self.assertIn('docker buildx imagetools inspect "$IMAGE@$DIGEST" --raw', raw)
        self.assertIn("gh attestation verify", raw)
        self.assertIn("sha-${{ steps.bind.outputs.short_sha }}-run-${{ github.run_id }}", raw)
        self.assertNotIn(":latest", raw)
        self.assertEqual(set(re.findall(r"secrets\.([A-Z0-9_]+)", raw)), {"GITHUB_TOKEN"})
        for action_ref in re.findall(r"uses: [^@\s]+@([^\s]+)", raw):
            self.assertRegex(action_ref, r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
