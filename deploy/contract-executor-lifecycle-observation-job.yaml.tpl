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
---
apiVersion: batch/v1
kind: Job
metadata:
  name: "${OK147_RUN_ID}"
  namespace: openkubes-execution-system
  labels:
    app.kubernetes.io/name: ok-cluster-contract-executor
    openkubes.io/execution-id: "${OK147_RUN_ID}"
    openkubes.io/stage-id: lifecycle-observation
spec:
  backoffLimit: 0
  completions: 1
  parallelism: 1
  activeDeadlineSeconds: ${OK147_ACTIVE_DEADLINE_SECONDS}
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
            - observe
            - lifecycle
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
            - --poll-interval
            - "${OK147_POLL_INTERVAL}"
            - --poll-timeout
            - "${OK147_POLL_TIMEOUT}"
          resources:
            requests: {cpu: 25m, memory: 48Mi, ephemeral-storage: 16Mi}
            limits: {cpu: 200m, memory: 96Mi, ephemeral-storage: 32Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: input, mountPath: /var/run/openkubes/input/staged-plan.json, subPath: staged-plan.json, readOnly: true}
            - {name: input, mountPath: /var/run/openkubes/input/receipt-prefix.json, subPath: receipt-prefix.json, readOnly: true}
            - {name: input, mountPath: /var/run/openkubes/input/provider-receipt.json, subPath: provider-receipt.json, readOnly: true}
            - {name: input, mountPath: /var/run/openkubes/input/lifecycle-receipt.json, subPath: lifecycle-receipt.json, readOnly: true}
            - {name: ledger-credential, mountPath: /var/run/openkubes/ledger/token, subPath: token, readOnly: true}
            - {name: ledger-credential, mountPath: /var/run/openkubes/ledger/ca.crt, subPath: ca.crt, readOnly: true}
            - {name: management-credential, mountPath: /var/run/openkubes/management/token, subPath: token, readOnly: true}
            - {name: management-credential, mountPath: /var/run/openkubes/management/ca.crt, subPath: ca.crt, readOnly: true}
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
