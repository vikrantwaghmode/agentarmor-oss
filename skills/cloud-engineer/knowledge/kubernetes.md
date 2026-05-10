# Kubernetes Best Practices

## Resource Definitions
Always set requests AND limits on every container:
```yaml
resources:
  requests:
    cpu: "100m"
    memory: "128Mi"
  limits:
    cpu: "500m"
    memory: "512Mi"
```

## Health Checks
- **livenessProbe**: restart container if unhealthy (use for deadlock detection)
- **readinessProbe**: remove from service endpoints until ready (use for warm-up)
- **startupProbe**: give slow-starting containers time before liveness kicks in

## Security Hardening
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
```
- Use `NetworkPolicy` to restrict pod-to-pod traffic
- Never mount service account tokens unless needed (`automountServiceAccountToken: false`)
- Store secrets in external vault (Vault, Secrets Manager) + CSI driver — avoid K8s Secrets for sensitive values

## Deployment Strategy
- `RollingUpdate` (default): zero-downtime; set `maxUnavailable: 0` and `maxSurge: 1`
- `Recreate`: downtime accepted; simpler for stateful apps
- Use `PodDisruptionBudget` to guarantee minimum replicas during node drains

## Autoscaling
- **HPA**: scale on CPU/memory or custom metrics (Prometheus via KEDA)
- **VPA**: recommend right-sized requests; use in recommendation mode first
- **Cluster Autoscaler**: provision new nodes when pods are unschedulable

## Observability
- Structured JSON logs to stdout; collect with Fluentd / Fluent Bit → ELK / Loki
- Expose `/metrics` in Prometheus format; scrape with Prometheus Operator
- Distributed tracing with OpenTelemetry SDK + Tempo / Jaeger
