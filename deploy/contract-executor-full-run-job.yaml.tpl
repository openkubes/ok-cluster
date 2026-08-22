apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: "${OK147_RUN_ID}"
  namespace: openkubes-execution-system
spec:
  podSelector:
    matchLabels:
      openkubes.io/execution-id: "${OK147_RUN_ID}"
  policyTypes: ["Ingress", "Egress"]
  ingress: []
  egress:
    - to: [{ipBlock: {cidr: "${OK147_INFRASTRUCTURE_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_INFRASTRUCTURE_API_PORT}}]
    - to: [{ipBlock: {cidr: "${OK147_MANAGEMENT_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_MANAGEMENT_API_PORT}}]
    - to: [{ipBlock: {cidr: "${OK147_WORKLOAD_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_WORKLOAD_API_PORT}}]
    - to: [{ipBlock: {cidr: "${OK147_ARGO_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_ARGO_API_PORT}}]
    - to: [{ipBlock: {cidr: "${OK147_AUTHORIZATION_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_AUTHORIZATION_API_PORT}}]
    - to: [{ipBlock: {cidr: "${OK147_COLLECTOR_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_COLLECTOR_API_PORT}}]
---
apiVersion: batch/v1
kind: Job
metadata:
  name: "${OK147_RUN_ID}"
  namespace: openkubes-execution-system
  annotations:
    openkubes.io/bundle-digest: "${OK147_BUNDLE_DIGEST}"
    openkubes.io/manifest-digest: "${OK147_MANIFEST_DIGEST}"
    openkubes.io/evidence-activation-digest: "${OK147_EVIDENCE_ACTIVATION_DIGEST}"
    openkubes.io/evidence-key-id: "${OK147_EVIDENCE_KEY_ID}"
  labels:
    app.kubernetes.io/name: ok-cluster-contract-executor
    openkubes.io/execution-id: "${OK147_RUN_ID}"
    openkubes.io/stage-id: full-run
spec:
  backoffLimit: 0
  completions: 1
  parallelism: 1
  activeDeadlineSeconds: 11100
  ttlSecondsAfterFinished: 3600
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ok-cluster-contract-executor
        openkubes.io/execution-id: "${OK147_RUN_ID}"
    spec:
      serviceAccountName: ok147-contract-executor-runtime
      automountServiceAccountToken: false
      enableServiceLinks: false
      restartPolicy: Never
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        fsGroupChangePolicy: OnRootMismatch
        seccompProfile: {type: RuntimeDefault}
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - {key: node-role.kubernetes.io/control-plane, operator: DoesNotExist}
      initContainers:
        - name: materialize-full-run
          image: "${OK147_IMAGE_DIGEST}"
          imagePullPolicy: IfNotPresent
          command: ["/ok"]
          args:
            - cluster
            - stage
            - run
            - full
            - materialize
            - --source
            - /var/run/openkubes/source
            - --destination
            - /var/run/openkubes/workspace
            - --handoff
            - /var/run/openkubes/handoff
            - --expected-bundle-digest
            - "${OK147_BUNDLE_DIGEST}"
            - --materialize
          resources:
            requests: {cpu: 25m, memory: 32Mi, ephemeral-storage: 16Mi}
            limits: {cpu: 100m, memory: 64Mi, ephemeral-storage: 32Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: activation-source, mountPath: /var/run/openkubes/source, readOnly: true}
            - {name: executor-private, mountPath: /var/run/openkubes}
            - {name: evidence-handoff, mountPath: /var/run/openkubes/handoff}
        - name: materialize-evidence-authority
          image: "${OK147_IMAGE_DIGEST}"
          imagePullPolicy: IfNotPresent
          command: ["/ok"]
          args:
            - cluster
            - stage
            - evidence
            - observability
            - authority
            - materialize
            - --source
            - /var/run/openkubes/evidence-source
            - --destination
            - /var/run/openkubes/evidence-authority
            - --expected-activation-digest
            - "${OK147_EVIDENCE_ACTIVATION_DIGEST}"
            - --expected-evidence-key-id
            - "${OK147_EVIDENCE_KEY_ID}"
            - --expected-collector-ca-digest
            - "${OK147_COLLECTOR_CA_DIGEST}"
            - --materialize
          resources:
            requests: {cpu: 25m, memory: 32Mi, ephemeral-storage: 16Mi}
            limits: {cpu: 100m, memory: 64Mi, ephemeral-storage: 32Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: evidence-source, mountPath: /var/run/openkubes/evidence-source, readOnly: true}
            - {name: authority-private, mountPath: /var/run/openkubes}
      containers:
        - name: executor
          image: "${OK147_IMAGE_DIGEST}"
          imagePullPolicy: IfNotPresent
          command: ["/ok"]
          args:
            - cluster
            - stage
            - run
            - full
            - execute
            - --manifest
            - /var/run/openkubes/workspace/activation/full-run-manifest.json
            - --expected-manifest-digest
            - "${OK147_MANIFEST_DIGEST}"
            - --independent-evidence-public-key
            - /var/run/openkubes/workspace/input/independent-evidence.pub
            - --execute
          resources:
            requests: {cpu: 50m, memory: 96Mi, ephemeral-storage: 32Mi}
            limits: {cpu: 500m, memory: 256Mi, ephemeral-storage: 64Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: executor-private, mountPath: /var/run/openkubes/workspace, subPath: workspace}
            - {name: evidence-handoff, mountPath: /var/run/openkubes/handoff}
        - name: evidence-authority
          image: "${OK147_IMAGE_DIGEST}"
          imagePullPolicy: IfNotPresent
          command: ["/ok"]
          args:
            - cluster
            - stage
            - evidence
            - observability
            - produce
            - --activation
            - /var/run/openkubes/evidence-authority/activation.json
            - --produce
          resources:
            requests: {cpu: 25m, memory: 48Mi, ephemeral-storage: 16Mi}
            limits: {cpu: 250m, memory: 128Mi, ephemeral-storage: 32Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: authority-private, mountPath: /var/run/openkubes/evidence-authority, subPath: evidence-authority}
            - {name: evidence-handoff, mountPath: /var/run/openkubes/handoff}
      volumes:
        - name: activation-source
          secret:
            secretName: "${OK147_ACTIVATION_SECRET}"
            defaultMode: 0440
            items:
              - {key: bundle-index.json, path: bundle-index.json}
              - {key: activation.full-run-manifest.json, path: activation/full-run-manifest.json}
              - {key: credentials.authorization-ca.crt, path: credentials/authorization-ca.crt}
              - {key: credentials.authorization-token, path: credentials/authorization-token}
              - {key: credentials.collector-query-token, path: credentials/collector-query-token}
              - {key: credentials.collector-tls.crt, path: credentials/collector-tls.crt}
              - {key: credentials.collector-tls.key, path: credentials/collector-tls.key}
              - {key: credentials.collector-webhook-token, path: credentials/collector-webhook-token}
              - {key: credentials.gitops-ca.crt, path: credentials/gitops-ca.crt}
              - {key: credentials.gitops-token, path: credentials/gitops-token}
              - {key: credentials.infrastructure-ca.crt, path: credentials/infrastructure-ca.crt}
              - {key: credentials.infrastructure-token, path: credentials/infrastructure-token}
              - {key: credentials.ledger-ca.crt, path: credentials/ledger-ca.crt}
              - {key: credentials.ledger-token, path: credentials/ledger-token}
              - {key: credentials.management-ca.crt, path: credentials/management-ca.crt}
              - {key: credentials.management-token, path: credentials/management-token}
              - {key: credentials.provider-access-kubeconfig, path: credentials/provider-access-kubeconfig}
              - {key: input.aggregate-profile.json, path: input/aggregate-profile.json}
              - {key: input.authorization-authority.pub, path: input/authorization-authority.pub}
              - {key: input.collector-job.yaml, path: input/collector-job.yaml}
              - {key: input.collector-runtime-authority.yaml, path: input/collector-runtime-authority.yaml}
              - {key: input.enablement.yaml, path: input/enablement.yaml}
              - {key: input.independent-evidence.pub, path: input/independent-evidence.pub}
              - {key: input.network-profile.json, path: input/network-profile.json}
              - {key: input.platform-applications.yaml, path: input/platform-applications.yaml}
              - {key: input.platform-profile.json, path: input/platform-profile.json}
              - {key: input.provider-access-policy.json, path: input/provider-access-policy.json}
              - {key: input.projection.authority-map.json, path: input/projection/authority-map.json}
              - {key: input.projection.ok-infra-prerequisites.yaml, path: input/projection/ok-infra-prerequisites.yaml}
              - {key: input.projection.ok-mgmt-lifecycle.yaml, path: input/projection/ok-mgmt-lifecycle.yaml}
              - {key: input.projection-manifest.json, path: input/projection-manifest.json}
              - {key: input.staged-plan.json, path: input/staged-plan.json}
              - {key: input.target-access.yaml, path: input/target-access.yaml}
              - {key: input.target-credential-policy.json, path: input/target-credential-policy.json}
              - {key: input.target-registration.yaml, path: input/target-registration.yaml}
        - name: evidence-source
          secret:
            secretName: "${OK147_EVIDENCE_AUTHORITY_SECRET}"
            defaultMode: 0440
            items:
              - {key: activation.json, path: activation.json}
              - {key: evidence-authority.key, path: evidence-authority.key}
              - {key: collector-token, path: collector-token}
              - {key: collector-ca.crt, path: collector-ca.crt}
        - name: executor-private
          emptyDir: {medium: Memory, sizeLimit: 8Mi}
        - name: authority-private
          emptyDir: {medium: Memory, sizeLimit: 1Mi}
        - name: evidence-handoff
          emptyDir: {medium: Memory, sizeLimit: 1Mi}
