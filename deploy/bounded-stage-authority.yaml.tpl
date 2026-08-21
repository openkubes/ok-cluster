apiVersion: v1
kind: ServiceAccount
metadata:
  name: "${OK147_AUTHORITY_NAME}"
  namespace: "${OK147_AUTHORITY_NAMESPACE}"
automountServiceAccountToken: false
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: "${OK147_AUTHORITY_NAME}-state"
  namespace: "${OK147_AUTHORITY_NAMESPACE}"
spec:
  accessModes: ["ReadWriteOnce"]
  storageClassName: "${OK147_STORAGE_CLASS}"
  resources:
    requests:
      storage: "${OK147_STORAGE_REQUEST}"
---
apiVersion: v1
kind: Service
metadata:
  name: "${OK147_AUTHORITY_NAME}"
  namespace: "${OK147_AUTHORITY_NAMESPACE}"
spec:
  selector:
    app.kubernetes.io/name: "${OK147_AUTHORITY_NAME}"
  ports:
    - {name: https, protocol: TCP, port: 8443, targetPort: https}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: "${OK147_AUTHORITY_NAME}"
  namespace: "${OK147_AUTHORITY_NAMESPACE}"
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: "${OK147_AUTHORITY_NAME}"
  policyTypes: ["Ingress", "Egress"]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: ok-cluster-contract-executor
      ports: [{protocol: TCP, port: 8443}]
  egress: []
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: "${OK147_AUTHORITY_NAME}"
  namespace: "${OK147_AUTHORITY_NAMESPACE}"
  annotations:
    openkubes.io/policy-digest: "${OK147_POLICY_DIGEST}"
    openkubes.io/key-id: "${OK147_KEY_ID}"
spec:
  serviceName: "${OK147_AUTHORITY_NAME}"
  replicas: 1
  podManagementPolicy: OrderedReady
  updateStrategy: {type: RollingUpdate}
  selector:
    matchLabels:
      app.kubernetes.io/name: "${OK147_AUTHORITY_NAME}"
  template:
    metadata:
      labels:
        app.kubernetes.io/name: "${OK147_AUTHORITY_NAME}"
    spec:
      serviceAccountName: "${OK147_AUTHORITY_NAME}"
      automountServiceAccountToken: false
      enableServiceLinks: false
      terminationGracePeriodSeconds: 30
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        fsGroupChangePolicy: OnRootMismatch
        seccompProfile: {type: RuntimeDefault}
      initContainers:
        - name: materialize
          image: "${OK147_IMAGE_DIGEST}"
          imagePullPolicy: IfNotPresent
          command: ["/ok"]
          args:
            - authority
            - stage
            - materialize
            - --source
            - /var/run/openkubes/source
            - --destination
            - /var/run/openkubes/private
            - --state-directory
            - /var/lib/openkubes/stage-authority/claims
            - --expected-policy-digest
            - "${OK147_POLICY_DIGEST}"
            - --expected-key-id
            - "${OK147_KEY_ID}"
            - --materialize
          resources:
            requests: {cpu: 10m, memory: 24Mi, ephemeral-storage: 8Mi}
            limits: {cpu: 100m, memory: 64Mi, ephemeral-storage: 16Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: source, mountPath: /var/run/openkubes/source, readOnly: true}
            - {name: private, mountPath: /var/run/openkubes}
            - {name: state, mountPath: /var/lib/openkubes/stage-authority}
      containers:
        - name: authority
          image: "${OK147_IMAGE_DIGEST}"
          imagePullPolicy: IfNotPresent
          command: ["/ok"]
          args:
            - authority
            - stage
            - serve
            - --policy
            - /var/run/openkubes/private/policy.json
            - --expected-policy-digest
            - "${OK147_POLICY_DIGEST}"
            - --private-key
            - /var/run/openkubes/private/authority.key
            - --token-file
            - /var/run/openkubes/private/client-token
            - --state-directory
            - /var/lib/openkubes/stage-authority/claims
            - --listen
            - 0.0.0.0:8443
            - --tls-cert
            - /var/run/openkubes/private/tls.crt
            - --tls-key
            - /var/run/openkubes/private/tls.key
            - --grant-valid-for
            - 10m
          ports: [{name: https, containerPort: 8443, protocol: TCP}]
          readinessProbe:
            tcpSocket: {port: https}
            periodSeconds: 5
            timeoutSeconds: 1
            failureThreshold: 3
          resources:
            requests: {cpu: 25m, memory: 48Mi, ephemeral-storage: 8Mi}
            limits: {cpu: 250m, memory: 128Mi, ephemeral-storage: 16Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: private, mountPath: /var/run/openkubes, readOnly: true}
            - {name: state, mountPath: /var/lib/openkubes/stage-authority}
      volumes:
        - name: source
          secret:
            secretName: "${OK147_PRIVATE_SECRET}"
            defaultMode: 0440
            items:
              - {key: policy.json, path: policy.json}
              - {key: authority.key, path: authority.key}
              - {key: client-token, path: client-token}
              - {key: tls.crt, path: tls.crt}
              - {key: tls.key, path: tls.key}
        - name: private
          emptyDir: {medium: Memory, sizeLimit: 1Mi}
        - name: state
          persistentVolumeClaim:
            claimName: "${OK147_AUTHORITY_NAME}-state"
