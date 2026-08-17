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
    - to: [{ipBlock: {cidr: "${OK147_LEDGER_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_LEDGER_API_PORT}}]
    - to: [{ipBlock: {cidr: "${OK147_WORKLOAD_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_WORKLOAD_API_PORT}}]
    - to: [{ipBlock: {cidr: "${OK147_ARGO_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_ARGO_API_PORT}}]
---
apiVersion: batch/v1
kind: Job
metadata:
  name: "${OK147_RUN_ID}"
  namespace: openkubes-execution-system
  labels:
    app.kubernetes.io/name: ok-cluster-contract-executor
    openkubes.io/execution-id: "${OK147_RUN_ID}"
    openkubes.io/stage-id: aggregate-evidence
spec:
  backoffLimit: 0
  completions: 1
  parallelism: 1
  activeDeadlineSeconds: 600
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
      containers:
        - name: executor
          image: "${OK147_IMAGE_DIGEST}"
          imagePullPolicy: IfNotPresent
          command: ["/ok"]
          args:
            - cluster
            - stage
            - evaluate
            - aggregate
            - --execute
            - --plan
            - /var/run/openkubes/input/staged-plan.json
            - --contract-namespace
            - "${OK147_CONTRACT_NAMESPACE}"
            - --contract-name
            - "${OK147_CONTRACT_NAME}"
            - --intent-revision
            - "${OK147_R}"
            - --enablement-revision
            - "${OK147_E}"
            - --platform-revision
            - "${OK147_P}"
            - --execution-fixture
            - "${OK147_FIXTURE}"
            - --infrastructure-authority
            - "${OK147_INFRA_AUTHORITY}"
            - --management-authority
            - "${OK147_MGMT_AUTHORITY}"
            - --gitops-authority
            - "${OK147_GITOPS_AUTHORITY}"
            - --receipt-prefix
            - /var/run/openkubes/input/receipt-prefix.json
            - --receipt-prefix-digest
            - "${OK147_RECEIPT_PREFIX_DIGEST}"
            - --aggregate-profile
            - /var/run/openkubes/input/aggregate-evidence-profile.json
            - --aggregate-profile-digest
            - "${OK147_AGGREGATE_PROFILE_DIGEST}"
            - --network-profile
            - /var/run/openkubes/input/network-profile.json
            - --network-profile-digest
            - "${OK147_NETWORK_PROFILE_DIGEST}"
            - --platform-profile
            - /var/run/openkubes/input/platform-profile.json
            - --platform-profile-digest
            - "${OK147_PLATFORM_PROFILE_DIGEST}"
            - --ledger-api-endpoint
            - "${OK147_LEDGER_API_URL}"
            - --ledger-token-file
            - /var/run/openkubes/ledger/token
            - --ledger-ca-file
            - /var/run/openkubes/ledger/ca.crt
            - --management-api-endpoint
            - "${OK147_MANAGEMENT_API_URL}"
            - --management-token-file
            - /var/run/openkubes/management/token
            - --management-ca-file
            - /var/run/openkubes/management/ca.crt
            - --workload-api-endpoint
            - "${OK147_WORKLOAD_API_URL}"
            - --workload-token-file
            - /var/run/openkubes/workload/token
            - --workload-ca-file
            - /var/run/openkubes/workload/ca.crt
            - --argo-api-endpoint
            - "${OK147_ARGO_API_URL}"
            - --argo-token-file
            - /var/run/openkubes/argo/token
            - --argo-ca-file
            - /var/run/openkubes/argo/ca.crt
            - --runtime-binding
            - /var/run/openkubes/runtime/runtime-binding.json
            - --runtime-binding-receipt
            - /var/run/openkubes/runtime/runtime-binding-receipt.json
            - --platform-capability
            - /var/run/openkubes/capability/platform-capability.json
            - --platform-capability-digest
            - "${OK147_PLATFORM_CAPABILITY_DIGEST}"
          resources:
            requests: {cpu: 50m, memory: 64Mi, ephemeral-storage: 16Mi}
            limits: {cpu: 250m, memory: 128Mi, ephemeral-storage: 32Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: input, mountPath: /var/run/openkubes/input, readOnly: true}
            - {name: ledger-credential, mountPath: /var/run/openkubes/ledger, readOnly: true}
            - {name: management-credential, mountPath: /var/run/openkubes/management, readOnly: true}
            - {name: workload-credential, mountPath: /var/run/openkubes/workload, readOnly: true}
            - {name: argo-credential, mountPath: /var/run/openkubes/argo, readOnly: true}
            - {name: runtime-binding, mountPath: /var/run/openkubes/runtime, readOnly: true}
            - {name: platform-capability, mountPath: /var/run/openkubes/capability, readOnly: true}
      volumes:
        - name: input
          configMap:
            name: "${OK147_INPUT_CONFIGMAP}"
            defaultMode: 0444
            items:
              - {key: staged-plan.json, path: staged-plan.json}
              - {key: receipt-prefix.json, path: receipt-prefix.json}
              - {key: provider-receipt.json, path: provider-receipt.json}
              - {key: lifecycle-receipt.json, path: lifecycle-receipt.json}
              - {key: lifecycle-observation-receipt.json, path: lifecycle-observation-receipt.json}
              - {key: enablement-receipt.json, path: enablement-receipt.json}
              - {key: network-observation-receipt.json, path: network-observation-receipt.json}
              - {key: runtime-binding-receipt.json, path: runtime-binding-receipt.json}
              - {key: target-access-receipt.json, path: target-access-receipt.json}
              - {key: target-credential-receipt.json, path: target-credential-receipt.json}
              - {key: target-registration-receipt.json, path: target-registration-receipt.json}
              - {key: platform-applications-receipt.json, path: platform-applications-receipt.json}
              - {key: platform-observation-receipt.json, path: platform-observation-receipt.json}
              - {key: aggregate-evidence-profile.json, path: aggregate-evidence-profile.json}
              - {key: network-profile.json, path: network-profile.json}
              - {key: platform-profile.json, path: platform-profile.json}
        - name: ledger-credential
          secret:
            secretName: "${OK147_LEDGER_CREDENTIAL_SECRET}"
            defaultMode: 0440
            items:
              - {key: token, path: token}
              - {key: ca.crt, path: ca.crt}
        - name: management-credential
          secret:
            secretName: "${OK147_MANAGEMENT_CREDENTIAL_SECRET}"
            defaultMode: 0440
            items:
              - {key: token, path: token}
              - {key: ca.crt, path: ca.crt}
        - name: workload-credential
          secret:
            secretName: "${OK147_WORKLOAD_CREDENTIAL_SECRET}"
            defaultMode: 0440
            items:
              - {key: token, path: token}
              - {key: ca.crt, path: ca.crt}
        - name: argo-credential
          secret:
            secretName: "${OK147_ARGO_CREDENTIAL_SECRET}"
            defaultMode: 0440
            items:
              - {key: token, path: token}
              - {key: ca.crt, path: ca.crt}
        - name: runtime-binding
          secret:
            secretName: "${OK147_RUNTIME_BINDING_SECRET}"
            defaultMode: 0440
            items:
              - {key: runtime-binding.json, path: runtime-binding.json}
              - {key: runtime-binding-receipt.json, path: runtime-binding-receipt.json}
        - name: platform-capability
          secret:
            secretName: "${OK147_PLATFORM_CAPABILITY_SECRET}"
            defaultMode: 0440
            items:
              - {key: platform-capability.json, path: platform-capability.json}
