apiVersion: v1
kind: Service
metadata:
  name: "${OK147_COLLECTOR_RUN_ID}"
  namespace: openkubes-execution-system
  annotations:
    openkubes.io/activation-digest: "${OK147_COLLECTOR_ACTIVATION_DIGEST}"
    openkubes.io/public-endpoint-digest: "${OK147_COLLECTOR_PUBLIC_ENDPOINT_DIGEST}"
  labels:
    app.kubernetes.io/name: ok147-observability-evidence-collector
    openkubes.io/execution-id: "${OK147_COLLECTOR_RUN_ID}"
spec:
  type: LoadBalancer
  loadBalancerIP: "${OK147_COLLECTOR_PUBLIC_IP}"
  externalTrafficPolicy: Local
  selector:
    app.kubernetes.io/name: ok147-observability-evidence-collector
    openkubes.io/execution-id: "${OK147_COLLECTOR_RUN_ID}"
  ports:
    - {name: https, protocol: TCP, port: ${OK147_COLLECTOR_PORT}, targetPort: https}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: "${OK147_COLLECTOR_RUN_ID}"
  namespace: openkubes-execution-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: ok147-observability-evidence-collector
      openkubes.io/execution-id: "${OK147_COLLECTOR_RUN_ID}"
  policyTypes: ["Ingress", "Egress"]
  ingress:
    - from: [{ipBlock: {cidr: "${OK147_ALERT_SOURCE_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_COLLECTOR_PORT}}]
    - from:
        - namespaceSelector:
            matchLabels: {kubernetes.io/metadata.name: openkubes-execution-system}
          podSelector:
            matchLabels: {app.kubernetes.io/name: ok-cluster-contract-executor}
      ports: [{protocol: TCP, port: ${OK147_COLLECTOR_PORT}}]
  egress:
    - to: [{ipBlock: {cidr: "${OK147_WORKLOAD_API_CIDR}"}}]
      ports: [{protocol: TCP, port: ${OK147_WORKLOAD_API_PORT}}]
---
apiVersion: batch/v1
kind: Job
metadata:
  name: "${OK147_COLLECTOR_RUN_ID}"
  namespace: openkubes-execution-system
  annotations:
    openkubes.io/activation-digest: "${OK147_COLLECTOR_ACTIVATION_DIGEST}"
    openkubes.io/manifest-digest: "${OK147_COLLECTOR_MANIFEST_DIGEST}"
    openkubes.io/runtime-binding-digest: "${OK147_COLLECTOR_RUNTIME_BINDING_DIGEST}"
    openkubes.io/public-endpoint-digest: "${OK147_COLLECTOR_PUBLIC_ENDPOINT_DIGEST}"
  labels:
    app.kubernetes.io/name: ok147-observability-evidence-collector
    openkubes.io/execution-id: "${OK147_COLLECTOR_RUN_ID}"
spec:
  backoffLimit: 0
  completions: 1
  parallelism: 1
  activeDeadlineSeconds: 10800
  ttlSecondsAfterFinished: 3600
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ok147-observability-evidence-collector
        openkubes.io/execution-id: "${OK147_COLLECTOR_RUN_ID}"
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
        - name: materialize-collector
          image: "${OK147_IMAGE_DIGEST}"
          imagePullPolicy: IfNotPresent
          command: ["/ok"]
          args:
            - cluster
            - stage
            - evidence
            - observability
            - collector
            - materialize
            - --source
            - /var/run/openkubes/collector-source
            - --destination
            - /var/run/openkubes/collector
            - --state-directory
            - /var/lib/openkubes/observability-evidence
            - --expected-activation-digest
            - "${OK147_COLLECTOR_ACTIVATION_DIGEST}"
            - --expected-manifest-digest
            - "${OK147_COLLECTOR_MANIFEST_DIGEST}"
            - --expected-runtime-binding-digest
            - "${OK147_COLLECTOR_RUNTIME_BINDING_DIGEST}"
            - --expected-public-endpoint-digest
            - "${OK147_COLLECTOR_PUBLIC_ENDPOINT_DIGEST}"
            - --materialize
          resources:
            requests: {cpu: 25m, memory: 32Mi, ephemeral-storage: 16Mi}
            limits: {cpu: 100m, memory: 64Mi, ephemeral-storage: 32Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: collector-source, mountPath: /var/run/openkubes/collector-source, readOnly: true}
            - {name: collector-private, mountPath: /var/run/openkubes}
            - {name: collector-state, mountPath: /var/lib/openkubes}
      containers:
        - name: collector
          image: "${OK147_IMAGE_DIGEST}"
          imagePullPolicy: IfNotPresent
          command: ["/ok"]
          args:
            - evidence
            - observability
            - serve
            - --activation
            - /var/run/openkubes/collector/activation.json
          ports: [{name: https, protocol: TCP, containerPort: ${OK147_COLLECTOR_PORT}}]
          resources:
            requests: {cpu: 25m, memory: 48Mi, ephemeral-storage: 16Mi}
            limits: {cpu: 250m, memory: 128Mi, ephemeral-storage: 32Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: collector-private, mountPath: /var/run/openkubes/collector, subPath: collector, readOnly: true}
            - {name: collector-state, mountPath: /var/lib/openkubes/observability-evidence, subPath: observability-evidence}
      volumes:
        - name: collector-source
          secret:
            secretName: "${OK147_COLLECTOR_ACTIVATION_SECRET}"
            defaultMode: 0440
            items:
              - {key: activation.json, path: activation.json}
              - {key: webhook-token, path: webhook-token}
              - {key: query-token, path: query-token}
              - {key: workload-token, path: workload-token}
              - {key: workload-ca.crt, path: workload-ca.crt}
              - {key: tls.crt, path: tls.crt}
              - {key: tls.key, path: tls.key}
        - name: collector-private
          emptyDir: {medium: Memory, sizeLimit: 1Mi}
        - name: collector-state
          emptyDir: {sizeLimit: 8Mi}
