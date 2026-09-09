apiVersion: v1
kind: ConfigMap
metadata:
  name: ok147-console-dry-run-schema
  namespace: openkubes-system
data:
  schema.json: |
    ${OK147_CONTRACT_SCHEMA_JSON}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ok147-console-dry-run
  namespace: openkubes-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: ok147-console-dry-run
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ok147-console-dry-run
    spec:
      automountServiceAccountToken: false
      containers:
        - name: runner
          image: ghcr.io/openkubes/ok-cluster-runner@${OK147_IMAGE_DIGEST}
          imagePullPolicy: IfNotPresent
          args: ["cluster", "dry-run", "serve", "--schema", "/etc/ok147/schema.json", "--listen", "0.0.0.0:8790"]
          ports:
            - name: dry-run
              containerPort: 8790
          readinessProbe:
            tcpSocket: {port: dry-run}
            periodSeconds: 5
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            capabilities: {drop: [ALL]}
          volumeMounts:
            - name: schema
              mountPath: /etc/ok147
              readOnly: true
      volumes:
        - name: schema
          configMap:
            name: ok147-console-dry-run-schema
---
apiVersion: v1
kind: Service
metadata:
  name: ok147-console-dry-run
  namespace: openkubes-system
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: ok147-console-dry-run
  ports:
    - name: dry-run
      port: 8790
      targetPort: dry-run
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ok147-console-dry-run
  namespace: openkubes-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: ok147-console-dry-run
  policyTypes: [Ingress, Egress]
  ingress:
    - ports: [{protocol: TCP, port: 8790}]
  egress: []
