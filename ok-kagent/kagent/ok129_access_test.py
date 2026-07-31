#!/usr/bin/env python3
"""Unit tests for the OK-129 installer-side access guard."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import yaml

import ok129_access as access


def profile(**write_overrides):
    write = {
        "scope": "namespaces",
        "namespaces": ["kagent-lab"],
        "resources": ["configmaps"],
        "requireApproval": True,
    }
    write.update(write_overrides)
    return {
        "kind": "KagentAccessProfile",
        "mode": "read-write",
        "install": {"namespace": "kagent"},
        "write": write,
    }


class ValidationTests(unittest.TestCase):
    def test_evidenced_profile_is_allowed(self):
        access.validate_ok129(profile())

    def test_read_only_may_park_only_the_evidenced_write_profile(self):
        raw = profile()
        raw["mode"] = "read-only"
        access.validate_ok129(raw)

    def test_cluster_scope_is_refused(self):
        with self.assertRaisesRegex(access.AccessError, "cluster scope"):
            access.validate_ok129(profile(scope="cluster", namespaces=[]))

    def test_ungated_write_is_refused(self):
        with self.assertRaisesRegex(access.AccessError, "requireApproval=true"):
            access.validate_ok129(profile(requireApproval=False))

    def test_non_evidenced_resource_is_refused(self):
        with self.assertRaisesRegex(access.AccessError, "exactly: configmaps"):
            access.validate_ok129(profile(resources=["configmaps", "deployments"]))

    def test_non_lab_namespace_is_refused(self):
        with self.assertRaisesRegex(access.AccessError, "exactly: kagent-lab"):
            access.validate_ok129(profile(namespaces=["team-a"]))


class MatrixTests(unittest.TestCase):
    def test_allowed_verbs_come_from_rendered_role(self):
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "custom-tools", "namespace": "kagent-lab"},
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": ["configmaps"],
                    "verbs": ["get", "patch"],
                },
                {
                    "apiGroups": [""],
                    "resources": ["pods"],
                    "verbs": ["get", "list"],
                },
            ],
        }
        binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "custom-tools", "namespace": "kagent-lab"},
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "name": "custom-tools",
                    "namespace": "custom-write-ns",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            rbac = Path(directory) / "rbac.yaml"
            rbac.write_text(yaml.safe_dump_all([role, binding]), encoding="utf-8")
            rows = access.verification_matrix(profile(), rbac)

        allowed = {
            (row[2], row[3]) for row in rows if row[0] == "configured-allow"
        }
        self.assertEqual(allowed, {("get", "configmaps"), ("patch", "configmaps")})
        self.assertIn(
            (
                "nonconfigured-denied",
                "system:serviceaccount:custom-write-ns:custom-tools",
                "patch",
                "deployments",
                "no",
                "namespace",
                "kagent-lab",
            ),
            rows,
        )

    def test_every_configured_namespace_is_tested(self):
        """The matrix must not stop at the first configured namespace."""
        docs = []
        for namespace in ("kagent-lab", "kagent-lab-2"):
            docs.append(
                {
                    "kind": "Role",
                    "metadata": {"name": "tools", "namespace": namespace},
                    "rules": [{"resources": ["configmaps"], "verbs": ["patch"]}],
                }
            )
            docs.append(
                {
                    "kind": "RoleBinding",
                    "metadata": {"name": "tools", "namespace": namespace},
                    "subjects": [
                        {"kind": "ServiceAccount", "name": "tools", "namespace": "write"}
                    ],
                }
            )
        raw = profile(namespaces=["kagent-lab", "kagent-lab-2"])
        original = access.ALLOWED_WRITE_NAMESPACES
        access.ALLOWED_WRITE_NAMESPACES = {"kagent-lab", "kagent-lab-2"}
        try:
            with tempfile.TemporaryDirectory() as directory:
                rbac = Path(directory) / "rbac.yaml"
                rbac.write_text(yaml.safe_dump_all(docs), encoding="utf-8")
                rows = access.verification_matrix(raw, rbac)
        finally:
            access.ALLOWED_WRITE_NAMESPACES = original

        allowed = {row[6] for row in rows if row[0] == "configured-allow"}
        self.assertEqual(allowed, {"kagent-lab", "kagent-lab-2"})
        denied = {row[6] for row in rows if row[0] == "nonconfigured-denied"}
        self.assertEqual(denied, {"kagent-lab", "kagent-lab-2"})

    def test_missing_role_for_a_configured_namespace_is_refused(self):
        docs = [
            {
                "kind": "Role",
                "metadata": {"name": "tools", "namespace": "kagent-lab"},
                "rules": [{"resources": ["configmaps"], "verbs": ["patch"]}],
            },
            {
                "kind": "RoleBinding",
                "metadata": {"name": "tools", "namespace": "kagent-lab"},
                "subjects": [
                    {"kind": "ServiceAccount", "name": "tools", "namespace": "write"}
                ],
            },
        ]
        raw = profile(namespaces=["kagent-lab", "kagent-lab-2"])
        original = access.ALLOWED_WRITE_NAMESPACES
        access.ALLOWED_WRITE_NAMESPACES = {"kagent-lab", "kagent-lab-2"}
        try:
            with tempfile.TemporaryDirectory() as directory:
                rbac = Path(directory) / "rbac.yaml"
                rbac.write_text(yaml.safe_dump_all(docs), encoding="utf-8")
                with self.assertRaisesRegex(access.AccessError, "kagent-lab-2"):
                    access.verification_matrix(raw, rbac)
        finally:
            access.ALLOWED_WRITE_NAMESPACES = original

    def test_unexpected_mutation_is_rejected(self):
        role = {
            "kind": "Role",
            "metadata": {"name": "tools", "namespace": "kagent-lab"},
            "rules": [
                {"resources": ["configmaps"], "verbs": ["get", "patch"]},
                {"resources": ["pods"], "verbs": ["get", "delete"]},
            ],
        }
        binding = {
            "kind": "RoleBinding",
            "metadata": {"name": "tools", "namespace": "kagent-lab"},
            "subjects": [
                {"kind": "ServiceAccount", "name": "tools", "namespace": "write"}
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            rbac = Path(directory) / "rbac.yaml"
            rbac.write_text(yaml.safe_dump_all([role, binding]), encoding="utf-8")
            with self.assertRaisesRegex(access.AccessError, "non-configured"):
                access.verification_matrix(profile(), rbac)


class CleanupDiscoveryTests(unittest.TestCase):
    def test_former_permissions_follow_returned_names_and_subjects(self):
        role = {
            "metadata": {"name": "old-release", "namespace": "old-target"},
            "rules": [
                {"resources": ["configmaps"], "verbs": ["get", "patch", "delete"]}
            ],
        }
        binding = {
            "metadata": {"name": "old-binding", "namespace": "old-target"},
            "roleRef": {"name": "old-release"},
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "namespace": "old-tools-ns",
                    "name": "old-release",
                }
            ],
        }
        checks = access.discover_permission_checks([role], [binding], [], [])
        self.assertEqual(
            checks,
            {
                access.PermissionCheck(
                    "system:serviceaccount:old-tools-ns:old-release",
                    "patch",
                    "configmaps",
                    "old-target",
                ),
                access.PermissionCheck(
                    "system:serviceaccount:old-tools-ns:old-release",
                    "delete",
                    "configmaps",
                    "old-target",
                ),
            },
        )

    def test_cleanup_uses_discovered_object_and_release_names(self):
        class FakeRuntime:
            def __init__(self):
                self.commands = []
                self.cleaned = False
                self.documents = {
                    "agents.kagent.dev": [
                        {"metadata": {"name": "old-agent", "namespace": "kagent"}}
                    ],
                    "remotemcpservers.kagent.dev": [
                        {"metadata": {"name": "old-server", "namespace": "kagent"}}
                    ],
                    "roles.rbac.authorization.k8s.io": [
                        {
                            "metadata": {
                                "name": "old-release",
                                "namespace": "old-target",
                            },
                            "rules": [
                                {
                                    "resources": ["configmaps"],
                                    "verbs": ["get", "patch"],
                                }
                            ],
                        }
                    ],
                    "rolebindings.rbac.authorization.k8s.io": [
                        {
                            "metadata": {
                                "name": "old-binding",
                                "namespace": "old-target",
                            },
                            "roleRef": {"name": "old-release"},
                            "subjects": [
                                {
                                    "kind": "ServiceAccount",
                                    "namespace": "old-tools-ns",
                                    "name": "old-release",
                                }
                            ],
                        }
                    ],
                    "clusterroles.rbac.authorization.k8s.io": [],
                    "clusterrolebindings.rbac.authorization.k8s.io": [],
                    "namespaces": [{"metadata": {"name": "old-tools-ns"}}],
                }

            def get_json(self, resource, **_kwargs):
                return {
                    "items": [] if self.cleaned else self.documents.get(resource, [])
                }

            def kubectl(self, args, *, capture=False):
                self.commands.append(("kubectl", tuple(args)))
                if args[:2] == ["delete", "namespace"]:
                    self.cleaned = True
                if args[:2] == ["auth", "can-i"]:
                    return "no\n"
                return "" if capture else ""

            def helm(self, args, *, capture=False):
                self.commands.append(("helm", tuple(args)))
                if args[0] == "list":
                    return json.dumps(
                        [
                            {"name": "actual-tools", "chart": "kagent-tools-0.2.1"},
                            {"name": "unrelated", "chart": "other-1.0.0"},
                        ]
                    )
                return "" if capture else ""

        runtime = FakeRuntime()
        access.cleanup(runtime)

        self.assertIn(
            (
                "kubectl",
                (
                    "delete",
                    "agents.kagent.dev",
                    "old-agent",
                    "--namespace",
                    "kagent",
                    "--ignore-not-found",
                ),
            ),
            runtime.commands,
        )
        self.assertIn(
            (
                "helm",
                (
                    "uninstall",
                    "actual-tools",
                    "--namespace",
                    "old-tools-ns",
                    "--wait",
                    "--timeout",
                    "5m",
                ),
            ),
            runtime.commands,
        )
        self.assertNotIn(
            (
                "helm",
                (
                    "uninstall",
                    "unrelated",
                    "--namespace",
                    "old-tools-ns",
                    "--wait",
                    "--timeout",
                    "5m",
                ),
            ),
            runtime.commands,
        )
        self.assertIn(
            (
                "kubectl",
                (
                    "auth",
                    "can-i",
                    "patch",
                    "configmaps",
                    "--as=system:serviceaccount:old-tools-ns:old-release",
                    "--namespace",
                    "old-target",
                ),
            ),
            runtime.commands,
        )


if __name__ == "__main__":
    unittest.main()
