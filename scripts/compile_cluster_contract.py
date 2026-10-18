#!/usr/bin/env python3
"""Compile fresh Contract bytes from reviewed static profiles; no authority."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys


def denied(*args, **kwargs):
    raise RuntimeError('network and child processes forbidden in Contract compilation')


def main():
    args = argparse.ArgumentParser()
    args.add_argument('--ok-linux-path', required=True)
    options = args.parse_args()
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise ValueError('oversized intent')
    intent = json.loads(raw)
    if intent['spec']['profile'] != 'talos-kubevirt-mvp':
        raise ValueError('unsupported Contract recipe')
    socket.socket = denied
    socket.create_connection = denied
    subprocess.Popen = denied
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    from scripts.render_cluster_intent import digest, resolve_intent_config
    config = resolve_intent_config(intent, options.ok_linux_path)
    recipe_path = root / 'profiles/cli/talos-kubevirt-mvp-contract-v1.json'
    runner_path = root / 'profiles/cli/talos-kubevirt-mvp-v1.json'
    recipe = json.loads(recipe_path.read_bytes())
    runner = json.loads(runner_path.read_bytes())
    assert recipe['format'] == 'ok-cli-contract-recipe/v1' and recipe['profile'] == intent['spec']['profile']
    assert set(recipe) == {'format', 'profile', 'apiVersion', 'kind', 'connectivity',
                          'controlPlaneEndpoint', 'enablementProfile', 'platformProfile', 'requiredConditions'}
    name, os_config = config['name'], config['os']
    contract = {'apiVersion': recipe['apiVersion'], 'kind': recipe['kind'],
        'metadata': {'name': name, 'namespace': name}, 'spec': {
        'kubernetesVersion': config['versions']['kubernetes'],
        'infrastructure': {'provider': config['provider'], 'profile': config['providerProfile'],
            'providerAccess': {'mode': 'external-cluster-secret', 'managementPlane': 'ok-mgmt',
                'providerPlane': 'ok-infra', 'secretRef': {'apiVersion': 'v1', 'kind': 'Secret',
                    **config['infraClusterSecretRef']}, 'targetNamespace': name},
            'controlPlaneEndpoint': recipe['controlPlaneEndpoint']},
        'operatingSystem': {'distribution': os_config['distribution'], 'profile': os_config['profile'],
            'version': config['versions']['talos'], 'architecture': os_config['architecture'],
            'schematicID': os_config['schematic_id'], 'imageDigest': os_config['imageDigest'],
            'identity': os_config['identity'],
            'goldenImage': {key: os_config['goldenImage'][key] for key in ('namespace', 'claim', 'storageClass')}},
        'topology': {role: {'replicas': config[role]['replicas'],
            'machine': {key: config[role][key] for key in ('cores', 'memory', 'disk')}}
            for role in ('controlPlane', 'workers')},
        'connectivity': {**recipe['connectivity'], 'podCIDR': config['network']['podCIDR'],
                         'serviceCIDR': config['network']['serviceCIDR']},
        'enablement': {'profile': recipe['enablementProfile'], 'revision': runner['enablementRevision']},
        'platform': {'profile': recipe['platformProfile'], 'revision': runner['platformRevision']},
        'conditions': {'required': recipe['requiredConditions']}}}
    print(json.dumps({'contract': contract, 'sourceDigests': {
        'contractRecipe': digest(recipe_path), 'runnerRecipe': digest(runner_path),
        'compiler': digest(Path(__file__)), 'rendererAdapter': digest(root / 'scripts/render_cluster_intent.py'),
        'resolver': digest(root / 'profile_resolvers/talos.py'),
        'okLinuxProfile': digest(Path(options.ok_linux_path) / 'profiles/kubevirt/profile.yaml')}}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Offline Contract compilation stopped: ' + type(error).__name__ + '; no authority or execution.', file=sys.stderr)
        sys.exit(2)
