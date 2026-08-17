apiVersion: batch/v1
kind: Job
metadata:
  name: "${OK147_RUN_ID}"
  namespace: openkubes-execution-system
  labels:
    app.kubernetes.io/name: ok-cluster-contract-executor
    openkubes.io/execution-id: "${OK147_RUN_ID}"
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
      serviceAccountName: ok147-contract-executor-preflight
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
            - create
            - --dry-run
            - --contract
            - /var/run/openkubes/input/contract.yaml
            - --schema
            - /var/run/openkubes/input/schema.json
            - --projection-manifest
            - /var/run/openkubes/input/projection-manifest.json
            - --projection-root
            - /var/run/openkubes/input
            - --authorization
            - /var/run/openkubes/input/authorization.json
            - --authorization-key
            - /var/run/openkubes/input/trusted-ed25519-public-key.base64
            - --evaluation-time
            - "${OK147_EVALUATION_TIME}"
            - --ledger-inspect
            - --ledger-api-endpoint
            - "${OK147_KUBERNETES_API_URL}"
            - --ledger-token-file
            - /var/run/openkubes/kubernetes/token
            - --ledger-ca-file
            - /var/run/openkubes/kubernetes/ca.crt
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
            - name: input
              mountPath: /var/run/openkubes/input
              readOnly: true
            - name: kubernetes-api
              mountPath: /var/run/openkubes/kubernetes
              readOnly: true
      volumes:
        - name: input
          configMap:
            name: "${OK147_INPUT_CONFIGMAP}"
            defaultMode: 0444
        - name: kubernetes-api
          projected:
            defaultMode: 0400
            sources:
              - serviceAccountToken:
                  path: token
                  expirationSeconds: 600
              - configMap:
                  name: kube-root-ca.crt
                  items:
                    - key: ca.crt
                      path: ca.crt
---
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
    - to:
        - ipBlock:
            cidr: "${OK147_KUBERNETES_API_CIDR}"
      ports:
        - protocol: TCP
          port: 443
