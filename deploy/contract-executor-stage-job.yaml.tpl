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
    - to: [{ipBlock: {cidr: "${OK147_AUTHORITY_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_AUTHORITY_API_PORT}}]
---
apiVersion: batch/v1
kind: Job
metadata:
  name: "${OK147_RUN_ID}"
  namespace: openkubes-execution-system
  labels:
    app.kubernetes.io/name: ok-cluster-contract-executor
    openkubes.io/execution-id: "${OK147_RUN_ID}"
    openkubes.io/stage-id: "${OK147_STAGE_ID}"
spec:
  backoffLimit: 0
  completions: 1
  parallelism: 1
  activeDeadlineSeconds: 660
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
        seccompProfile:
          type: RuntimeDefault
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: node-role.kubernetes.io/control-plane
                    operator: DoesNotExist
      containers:
        - name: executor
          image: "${OK147_IMAGE_DIGEST}"
          imagePullPolicy: IfNotPresent
          command: ["/ok"]
          args:
            - cluster
            - stage
            - run
            - --execute
            - --expected-stage
            - "${OK147_STAGE_ID}"
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
            - --grant
            - /var/run/openkubes/input/stage-grant.json
            - --grant-key
            - /var/run/openkubes/input/stage-authority.pub
            - --projection-manifest
            - /var/run/openkubes/input/projection-manifest.json
            - --projection-root
            - /var/run/openkubes/input
            - --evaluation-time
            - "${OK147_EVALUATION_TIME}"
            - --ledger-api-endpoint
            - "${OK147_LEDGER_API_URL}"
            - --ledger-token-file
            - /var/run/openkubes/ledger/token
            - --ledger-ca-file
            - /var/run/openkubes/ledger/ca.crt
            - --authority-api-endpoint
            - "${OK147_AUTHORITY_API_URL}"
            - --authority-token-file
            - /var/run/openkubes/authority/token
            - --authority-ca-file
            - /var/run/openkubes/authority/ca.crt
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
              ephemeral-storage: 32Mi
            limits:
              cpu: 250m
              memory: 128Mi
              ephemeral-storage: 64Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
${OK147_INPUT_VOLUME_MOUNTS}            - {name: ledger-credential, mountPath: /var/run/openkubes/ledger/token, subPath: token, readOnly: true}
            - {name: ledger-credential, mountPath: /var/run/openkubes/ledger/ca.crt, subPath: ca.crt, readOnly: true}
            - {name: authority-credential, mountPath: /var/run/openkubes/authority/token, subPath: token, readOnly: true}
            - {name: authority-credential, mountPath: /var/run/openkubes/authority/ca.crt, subPath: ca.crt, readOnly: true}
      volumes:
        - name: input
          configMap:
            name: "${OK147_INPUT_CONFIGMAP}"
            defaultMode: 0444
            items:
${OK147_INPUT_CONFIGMAP_ITEMS}        - name: ledger-credential
          secret:
            secretName: "${OK147_LEDGER_CREDENTIAL_SECRET}"
            defaultMode: 0440
            items:
              - {key: token, path: token}
              - {key: ca.crt, path: ca.crt}
        - name: authority-credential
          secret:
            secretName: "${OK147_AUTHORITY_CREDENTIAL_SECRET}"
            defaultMode: 0440
            items:
              - {key: token, path: token}
              - {key: ca.crt, path: ca.crt}
