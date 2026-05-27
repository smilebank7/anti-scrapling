# Anti-Scrapling Helm Chart

Deploys the Anti-Scrapling security middleware as a Kubernetes workload.

## Quickstart

```bash
helm install anti-scrapling ./deploy/helm/anti-scrapling \
  --set upstream.target=http://my-app.default.svc.cluster.local:3000
```

## Prerequisites

- Kubernetes 1.25+
- Helm 3.10+
- (Optional) Prometheus Operator for PodMonitor support

## Installation

### Minimal (defaults)

```bash
helm install anti-scrapling ./deploy/helm/anti-scrapling \
  --set upstream.target=http://my-app.default.svc.cluster.local:3000
```

### With Redis (distributed token cache)

```bash
helm install anti-scrapling ./deploy/helm/anti-scrapling \
  --set upstream.target=http://my-app.default.svc.cluster.local:3000 \
  --set redis.enabled=true \
  --set redis.url=redis://redis-master.default.svc.cluster.local:6379/0
```

### With autoscaling

```bash
helm install anti-scrapling ./deploy/helm/anti-scrapling \
  --set upstream.target=http://my-app.default.svc.cluster.local:3000 \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=2 \
  --set autoscaling.maxReplicas=20 \
  --set autoscaling.targetCPUUtilizationPercentage=70
```

### With ingress (nginx)

```bash
helm install anti-scrapling ./deploy/helm/anti-scrapling \
  --set upstream.target=http://my-app.default.svc.cluster.local:3000 \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set "ingress.hosts[0].host=myapp.example.com" \
  --set "ingress.hosts[0].paths[0]=/"
```

### With strict policy

```bash
helm install anti-scrapling ./deploy/helm/anti-scrapling \
  --set upstream.target=http://my-app.default.svc.cluster.local:3000 \
  --set policy.preset=strict
```

### With existing token secret

```bash
kubectl create secret generic my-token-secret \
  --from-literal=token-key=$(openssl rand -base64 32)

helm install anti-scrapling ./deploy/helm/anti-scrapling \
  --set upstream.target=http://my-app.default.svc.cluster.local:3000 \
  --set token.existingSecret=my-token-secret
```

### With Prometheus PodMonitor

```bash
helm install anti-scrapling ./deploy/helm/anti-scrapling \
  --set upstream.target=http://my-app.default.svc.cluster.local:3000 \
  --set metrics.podMonitor.enabled=true
```

## Values Reference

| Key | Default | Description |
|-----|---------|-------------|
| `image.repository` | `ghcr.io/smilebank7/anti-scrapling` | Container image repository |
| `image.tag` | `"0.1.0"` | Image tag (defaults to chart appVersion) |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy |
| `replicaCount` | `2` | Number of replicas (ignored when autoscaling enabled) |
| `resources.requests.cpu` | `100m` | CPU request |
| `resources.requests.memory` | `128Mi` | Memory request |
| `resources.limits.cpu` | `500m` | CPU limit |
| `resources.limits.memory` | `512Mi` | Memory limit |
| `service.type` | `ClusterIP` | Main service type |
| `service.port` | `8080` | Main service port |
| `upstream.target` | `http://upstream-service.default.svc.cluster.local:3000` | **Required.** Backend to proxy valid traffic to |
| `policy.preset` | `default` | Policy preset: `default`, `strict`, or `custom` |
| `policy.policyYaml` | `""` | Raw policy YAML (only used when `policy.preset=custom`) |
| `token.existingSecret` | `""` | Name of existing Secret containing token key |
| `token.secretKey` | `token-key` | Key within the secret |
| `redis.enabled` | `false` | Enable Redis for distributed token cache |
| `redis.url` | `""` | Redis URL (e.g. `redis://host:6379/0`) |
| `metrics.enabled` | `true` | Expose metrics endpoint |
| `metrics.service.port` | `9090` | Metrics service port |
| `metrics.podMonitor.enabled` | `false` | Create Prometheus Operator PodMonitor |
| `admin.enabled` | `true` | Expose admin API |
| `admin.service.type` | `ClusterIP` | Admin service type |
| `admin.service.port` | `9091` | Admin service port |
| `ingress.enabled` | `false` | Create Ingress resource |
| `ingress.className` | `""` | Ingress class name |
| `ingress.annotations` | `{}` | Ingress annotations |
| `ingress.hosts` | `[{host: chart-example.local, paths: ["/"]}]` | Ingress host rules |
| `ingress.tls` | `[]` | Ingress TLS configuration |
| `autoscaling.enabled` | `false` | Enable HorizontalPodAutoscaler |
| `autoscaling.minReplicas` | `2` | HPA minimum replicas |
| `autoscaling.maxReplicas` | `10` | HPA maximum replicas |
| `autoscaling.targetCPUUtilizationPercentage` | `80` | HPA CPU target |
| `podSecurityContext` | `{fsGroup: 65532, runAsNonRoot: true, runAsUser: 65532}` | Pod-level security context |
| `securityContext` | `{allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, readOnlyRootFilesystem: true}` | Container-level security context |
| `nodeSelector` | `{}` | Node selector |
| `tolerations` | `[]` | Tolerations |
| `affinity` | `{}` | Affinity rules |
| `podAnnotations` | `{}` | Extra pod annotations |

## Policy Presets

### default

Balanced policy. Challenges suspicious traffic (score ≥ 40), denies extreme cases (score ≥ 80). Default action is `challenge`.

```yaml
scoring:
  challenge_threshold: 40
  deny_threshold: 80
challenge:
  pow_difficulty: 4
token:
  ttl: 24h
  bind_to: [ip, ua, ja3]
```

### strict

High-security policy. Denies datacenter IPs, challenges everything with score ≥ 10. Default action is `deny`.

```yaml
scoring:
  challenge_threshold: 10
  deny_threshold: 50
challenge:
  pow_difficulty: 6
token:
  ttl: 8h
  bind_to: [ip, ua, ja3, ja4]
```

### custom

Provide your own policy YAML via `policy.policyYaml`:

```bash
helm install anti-scrapling ./deploy/helm/anti-scrapling \
  --set upstream.target=http://my-app:3000 \
  --set policy.preset=custom \
  --set-file policy.policyYaml=./my-policy.yaml
```

## Upgrading

```bash
helm upgrade anti-scrapling ./deploy/helm/anti-scrapling \
  --set upstream.target=http://my-app.default.svc.cluster.local:3000
```

The token secret is annotated with `helm.sh/resource-policy: keep` and will survive `helm uninstall`.

## Uninstalling

```bash
helm uninstall anti-scrapling
kubectl delete secret anti-scrapling-token
```
