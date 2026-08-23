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
    - to: [{ipBlock: {cidr: "${OK147_MANAGEMENT_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_MANAGEMENT_API_PORT}}]
    - to: [{ipBlock: {cidr: "${OK147_WORKLOAD_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_WORKLOAD_API_PORT}}]
    - to: [{ipBlock: {cidr: "${OK147_ARGO_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_ARGO_API_PORT}}]
    - to:
        - ipBlock: {cidr: "${OK147_AUTHORIZATION_API_CIDR}"}
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: ok147-stage-authority
      ports: [{protocol: TCP, port: ${OK147_AUTHORIZATION_API_PORT}}]
---
apiVersion: batch/v1
kind: Job
metadata:
  name: "${OK147_RUN_ID}"
  namespace: openkubes-execution-system
  annotations:
    openkubes.io/bundle-digest: "${OK147_BUNDLE_DIGEST}"
    openkubes.io/manifest-digest: "${OK147_MANIFEST_DIGEST}"
  labels:
    app.kubernetes.io/name: ok-cluster-contract-executor
    openkubes.io/execution-id: "${OK147_RUN_ID}"
    openkubes.io/stage-id: post-runtime
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
        seccompProfile: {type: RuntimeDefault}
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - {key: node-role.kubernetes.io/control-plane, operator: DoesNotExist}
      initContainers:
        - name: materialize-private-bundle
          image: "${OK147_IMAGE_DIGEST}"
          imagePullPolicy: IfNotPresent
          command: ["/ok"]
          args:
            - cluster
            - stage
            - run
            - post-runtime
            - materialize
            - --source
            - /var/run/openkubes/source
            - --destination
            - /var/run/openkubes/workspace
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
            - {name: workspace, mountPath: /var/run/openkubes}
      containers:
        - name: executor
          image: "${OK147_IMAGE_DIGEST}"
          imagePullPolicy: IfNotPresent
          command: ["/ok"]
          args:
            - cluster
            - stage
            - run
            - post-runtime
            - execute
            - --manifest
            - /var/run/openkubes/workspace/activation/post-runtime-manifest.json
            - --expected-manifest-digest
            - "${OK147_MANIFEST_DIGEST}"
            - --execute
          resources:
            requests: {cpu: 50m, memory: 64Mi, ephemeral-storage: 16Mi}
            limits: {cpu: 250m, memory: 128Mi, ephemeral-storage: 32Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: workspace, mountPath: /var/run/openkubes}
      volumes:
        - name: activation-source
          secret:
            secretName: "${OK147_ACTIVATION_SECRET}"
            defaultMode: 0440
            items:
              - {key: bundle-index.json, path: bundle-index.json}
              - {key: activation.post-runtime-manifest.json, path: activation/post-runtime-manifest.json}
              - {key: credentials.authorization-ca.crt, path: credentials/authorization-ca.crt}
              - {key: credentials.authorization-token, path: credentials/authorization-token}
              - {key: credentials.gitops-ca.crt, path: credentials/gitops-ca.crt}
              - {key: credentials.gitops-token, path: credentials/gitops-token}
              - {key: credentials.ledger-ca.crt, path: credentials/ledger-ca.crt}
              - {key: credentials.ledger-token, path: credentials/ledger-token}
              - {key: credentials.management-ca.crt, path: credentials/management-ca.crt}
              - {key: credentials.management-token, path: credentials/management-token}
              - {key: credentials.workload-ca.crt, path: credentials/workload-ca.crt}
              - {key: credentials.workload-token, path: credentials/workload-token}
              - {key: input.01-provider-prerequisites.json, path: input/01-provider-prerequisites.json}
              - {key: input.02-cluster-lifecycle.json, path: input/02-cluster-lifecycle.json}
              - {key: input.03-lifecycle-observation.json, path: input/03-lifecycle-observation.json}
              - {key: input.04-enablement.json, path: input/04-enablement.json}
              - {key: input.05-network-observation.json, path: input/05-network-observation.json}
              - {key: input.06-runtime-binding.json, path: input/06-runtime-binding.json}
              - {key: input.07-target-access.json, path: input/07-target-access.json}
${OK147_RECOVERY_RECEIPT_ITEMS}
              - {key: input.aggregate-profile.json, path: input/aggregate-profile.json}
              - {key: input.authorization-authority.pub, path: input/authorization-authority.pub}
              - {key: input.network-profile.json, path: input/network-profile.json}
              - {key: input.platform-applications.yaml, path: input/platform-applications.yaml}
              - {key: input.platform-capability.json, path: input/platform-capability.json}
              - {key: input.platform-profile.json, path: input/platform-profile.json}
              - {key: input.receipt-prefix.json, path: input/receipt-prefix.json}
              - {key: input.runtime-binding-receipt.json, path: input/runtime-binding-receipt.json}
              - {key: input.runtime-binding.json, path: input/runtime-binding.json}
              - {key: input.stage-authority.pub, path: input/stage-authority.pub}
              - {key: input.staged-plan.json, path: input/staged-plan.json}
              - {key: input.target-access.yaml, path: input/target-access.yaml}
              - {key: input.target-credential-grant.json, path: input/target-credential-grant.json}
              - {key: input.target-credential-policy.json, path: input/target-credential-policy.json}
              - {key: input.target-registration.yaml, path: input/target-registration.yaml}
              - {key: input.workload-authority.json, path: input/workload-authority.json}
        - name: workspace
          emptyDir:
            medium: Memory
            sizeLimit: 8Mi
