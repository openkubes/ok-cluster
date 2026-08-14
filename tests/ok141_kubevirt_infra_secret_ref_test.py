#!/usr/bin/env python3
"""Offline contract tests for the OK-141 external CAPK authority seam."""

from pathlib import Path
from string import Template
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import render  # noqa: E402


def base_config() -> dict:
    return {
        "name": "disposable-ok141",
        "type": "talos",
        "provider": "kubevirt",
        "versions": {"kubernetes": "v1.36.2", "talos": "v1.9.6"},
        "network": {
            "endpoint": "provider-allocated",
            "podCIDR": "10.40.0.0/16",
            "serviceCIDR": "10.100.0.0/20",
        },
    }


def kubevirt_cluster_document(config: dict) -> dict:
    template = Template(
        (ROOT / "templates/talos/providers/kubevirt/cluster-base.yaml.tpl").read_text()
    )
    rendered = template.safe_substitute(render.build_context(config))
    return next(
        document
        for document in yaml.safe_load_all(rendered)
        if document and document.get("kind") == "KubevirtCluster"
    )


def expect_error(config: dict, message: str) -> None:
    try:
        render.render_infra_cluster_secret_ref(config)
    except SystemExit as error:
        assert message in str(error)
    else:
        raise AssertionError("invalid infraClusterSecretRef was accepted")


def main() -> None:
    same_cluster = base_config()
    assert "infraClusterSecretRef" not in kubevirt_cluster_document(same_cluster)["spec"]

    external = base_config()
    external["infraClusterSecretRef"] = {
        "name": "external-infra-kubeconfig-disposable-ok141",
        "namespace": "disposable-ok141",
    }
    document = kubevirt_cluster_document(external)
    assert document["spec"]["infraClusterSecretRef"] == {
        "apiVersion": "v1",
        "kind": "Secret",
        "name": "external-infra-kubeconfig-disposable-ok141",
        "namespace": "disposable-ok141",
    }
    assert document["spec"]["controlPlaneServiceTemplate"]["spec"]["type"] == "LoadBalancer"
    assert document["spec"]["controlPlaneServiceTemplate"]["metadata"] == {
        "namespace": "disposable-ok141"
    }

    same_cluster_document = kubevirt_cluster_document(same_cluster)
    assert same_cluster_document["spec"]["controlPlaneServiceTemplate"]["metadata"] == {
        "namespace": "disposable-ok141"
    }

    incomplete = base_config()
    incomplete["infraClusterSecretRef"] = {"name": "missing-namespace"}
    expect_error(incomplete, "requires exactly name and namespace")

    unsafe = base_config()
    unsafe["infraClusterSecretRef"] = {
        "name": "$(unsafe)",
        "namespace": "disposable-ok141",
    }
    expect_error(unsafe, "not a DNS subdomain")

    wrong_provider = base_config()
    wrong_provider["provider"] = "openstack"
    wrong_provider["infraClusterSecretRef"] = {
        "name": "external-infra-kubeconfig-disposable-ok141",
        "namespace": "disposable-ok141",
    }
    expect_error(wrong_provider, "supported only for Talos on KubeVirt")

    print("OK-141 infraClusterSecretRef tests: PASS")


if __name__ == "__main__":
    main()
