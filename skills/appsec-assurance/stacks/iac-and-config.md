# Infrastructure as Code and server configuration

**Detector keys:** IaC/config detections in `stack.json` (Terraform/OpenTofu, CloudFormation/SAM/CDK synth output, Kubernetes manifests, Helm charts, Kustomize, Dockerfile, Docker Compose, Nginx, Apache, serverless.yml)

This guide gives stack-specific pointers for locating and reading these files.
The detailed check lists live in `checklists/containers-and-kubernetes.md` and
`checklists/cloud-and-iac.md`; record pass/fail there. Review the **rendered**
configuration where possible (`terraform plan -out` → `terraform show -json`,
`helm template`, `kustomize build`, `cdk synth`, `docker compose config`) —
defaults, variables and overlays change the effective result.

## Untrusted input sources

- Variables and parameters from CI (`TF_VAR_*`, `-var-file`, CloudFormation `Parameters`, Helm `values.yaml` overrides, `--set`), PR-controlled files in pipelines that run `plan`/`template` on untrusted branches (plan-time code execution via `external` data sources, providers, `local-exec`).
- Remote modules and charts (`source = "git::..."`, registry modules without version pins, Helm repo dependencies), container base images, Terraform providers.
- Request headers and paths reaching Nginx/Apache rules (`$host`, `$http_*`, `$request_uri`, `$uri`), environment variables injected into containers and functions.

## Dangerous sinks

| Sink / setting | Vulnerability class | CWE | Safe alternative |
|----------------|--------------------|-----|------------------|
| Security groups / NSGs / firewall rules `0.0.0.0/0` or `::/0` on admin/DB ports | Exposed service | CWE-284 | Restrict CIDRs; private subnets; bastion/SSM |
| IAM `"Action": "*"`, `"Resource": "*"`, `iam:PassRole` on `*`, wildcard trust principals | Excessive privilege | CWE-269, CWE-250 | Least privilege; condition keys; `aws:SourceArn`/`SourceAccount` |
| S3/GCS/Blob public ACLs or policies, `block_public_acls = false` | Public data exposure | CWE-200, CWE-732 | Public access block; private + signed URLs/CDN with OAC |
| Storage/DB without encryption, `storage_encrypted = false`, unencrypted EBS | Missing encryption at rest | CWE-311 | KMS-backed encryption |
| Secrets in `variable default`, `.tfvars`, CFN `Parameters` without `NoEcho`, Helm values, Compose `environment:`, Dockerfile `ENV`/`ARG` | Hard-coded credentials | CWE-798 | Secrets Manager / Key Vault / Secret Manager refs; External Secrets; BuildKit `--mount=type=secret` |
| Terraform state in local/unencrypted backend or public bucket | Sensitive data exposure | CWE-312 | Encrypted remote backend with locking and restricted access |
| K8s `privileged: true`, `hostPath`, `hostNetwork/hostPID/hostIPC`, `allowPrivilegeEscalation: true`, `runAsUser: 0`, added capabilities (`SYS_ADMIN`, `NET_ADMIN`) | Container escape / privilege escalation | CWE-250, CWE-269 | Pod Security Standards `restricted`; `runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault` |
| RBAC `ClusterRoleBinding` to `cluster-admin`, verbs `*`, `secrets` `get/list` cluster-wide, `automountServiceAccountToken` default | Excessive privilege | CWE-269 | Namespaced Roles, minimal verbs, `automountServiceAccountToken: false` |
| Docker socket mount (`/var/run/docker.sock`) in Compose/K8s | Host takeover | CWE-250 | Never mount the socket; use rootless BuildKit or a remote builder |
| `FROM image:latest`, unpinned digests, `curl \| sh` in Dockerfile, `ADD http://...` | Supply-chain integrity | CWE-494, CWE-829 | Pin by digest; verify checksums/signatures |
| Dockerfile without `USER` (runs as root) | Excess privilege | CWE-250 | Non-root `USER` |
| Nginx `alias` with `location /x` (no trailing slash) | Path traversal (off-by-slash) | CWE-22 | Matching trailing slashes on `location` and `alias` |
| Nginx `proxy_pass http://$arg_host`, Apache `ProxyPass` built from request data, `ProxyRequests On` | SSRF / open proxy | CWE-918 | Static upstreams |
| Nginx `add_header` in a nested block (drops parent headers), missing HSTS/CSP, `server_tokens on`, `autoindex on` | Missing headers / info disclosure | CWE-693, CWE-200, CWE-548 | Re-declare headers per block or use `include`; `server_tokens off` |
| `return 302 https://$host$request_uri` with unvalidated Host; `$uri` in redirects/headers | Host header / CRLF injection | CWE-644, CWE-113 | `$server_name`; `$request_uri` (not decoded `$uri`) |
| TLS `ssl_protocols TLSv1 TLSv1.1`, weak ciphers, Apache `SSLProtocol all` | Weak TLS | CWE-326, CWE-327 | TLS 1.2+ (Mozilla intermediate profile) |
| Apache `AllowOverride All` + writable dirs, `Options Indexes`, `ExecCGI` in upload dirs | Code execution / listing | CWE-434, CWE-548 | `AllowOverride None`, no exec in upload dirs |
| serverless.yml `iamRoleStatements` with `*`, `cors: true` + credentials, `authorizer` missing on `http`/`httpApi` events, env secrets in plain text | Excess privilege / unauthenticated function | CWE-269, CWE-306, CWE-798 | Per-function roles, authorizers, SSM/Secrets Manager refs |

## Framework pitfalls and insecure defaults

- **Terraform/OpenTofu:** `local-exec`/`remote-exec` provisioners and `external` data sources run code during `plan`/`apply` — a PR can execute in CI if plans run on untrusted branches; modules without `?ref=<tag or commit>` pins; providers without `.terraform.lock.hcl` committed; `sensitive = true` hides values from CLI output but **not** from state; `count`/`for_each` conditionals that disable encryption or logging in non-prod environments that still hold real data.
- **CloudFormation/SAM/CDK:** `NoEcho` parameters are still visible in `Metadata`/outputs if referenced; `DeletionPolicy` absent on data stores; CDK constructs default some resources to `RemovalPolicy.DESTROY`; review `cdk.out/*.template.json`, not just the TypeScript/Python source; SAM `Auth` blocks default to no authorizer.
- **Kubernetes:** no `NetworkPolicy` = all pods can talk to all pods (and cloud metadata at 169.254.169.254); missing `resources.limits` (noisy-neighbour DoS); secrets in ConfigMaps; `Service type: LoadBalancer`/`NodePort` exposing internal services; Ingress without TLS or with permissive annotations (e.g. ingress-nginx `configuration-snippet`/`server-snippet` — snippet annotations have enabled config injection and were the vector for the 2025 "IngressNightmare" CVEs; disable `allow-snippet-annotations`); default namespace use; images from mutable tags.
- **Helm:** chart defaults are often permissive (`securityContext: {}`); `tpl` on user-supplied values renders templates; `lookup` reading secrets; chart dependencies from unpinned repos. Always lint the rendered output.
- **Docker Compose:** `ports: "5432:5432"` binds to all interfaces (and Docker bypasses host firewalls such as ufw); `privileged`, `network_mode: host`, `pid: host`; `.env` files committed.
- **Nginx:** regex `location ~` ordering, `merge_slashes off`, `proxy_set_header Host $host` with upstream trusting it, `X-Forwarded-For` appended blindly (`$proxy_add_x_forwarded_for` is append, so the app must trust only the last hop), missing `client_max_body_size`/timeouts.
- **Apache:** `.htaccess` in web-writable dirs, `mod_status`/`server-status` public, `TraceEnable On`, `ServerSignature On`.
- **serverless.yml:** wildcard `provider.iam.role.statements`, `functions.*.url` (Lambda function URLs) with `authorizer: none`, plugin supply chain, `package.patterns` shipping `.env` or test data.

## Authn/authz idioms to verify

- Cloud identities: workload identity / IRSA / Pod Identity instead of static keys; GitHub Actions OIDC trust conditions pin `sub` to repo **and** branch/environment (`repo:org/repo:ref:refs/heads/main`), never `repo:org/*`.
- API gateways and load balancers: authorizers attached to every route/stage; admin UIs (Kubernetes dashboard, Argo CD, Grafana, Jenkins) not exposed publicly; IMDSv2 required (`http_tokens = "required"`).
- Kubernetes: `kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>` (in an authorized cluster) to confirm effective permissions.

## Useful grep patterns

```bash
rg -n '0\.0\.0\.0/0|::/0' -g '*.{tf,json,yaml,yml}'
rg -n '"Action"\s*:\s*"\*"|"Resource"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"|Action:\s*["\x27]?\*' -g '*.{tf,json,yaml,yml}'
rg -n 'acl\s*=\s*"public-read|block_public_(acls|policy)\s*=\s*false|encrypted\s*=\s*false|storage_encrypted\s*=\s*false|http_tokens\s*=\s*"optional"' -g '*.tf'
rg -n 'local-exec|remote-exec|data\s+"external"|source\s*=\s*"git::[^"?]*"' -g '*.tf'
rg -n 'privileged:\s*true|allowPrivilegeEscalation:\s*true|host(Network|PID|IPC):\s*true|hostPath:|runAsUser:\s*0|SYS_ADMIN|docker\.sock' -g '*.{yaml,yml}'
rg -n 'cluster-admin|verbs:\s*\[\s*"\*"|resources:\s*\[\s*"\*"' -g '*.{yaml,yml}'
rg -n '^FROM\s+\S+(:latest)?\s*$|curl[^|]*\|\s*(ba)?sh|^ADD\s+https?://' -g 'Dockerfile*' -g '*.dockerfile'
rg -n '(PASSWORD|SECRET|TOKEN|API_KEY)\s*[:=]\s*\S+' -i -g '*.{tf,tfvars,yaml,yml,env}' -g 'Dockerfile*'
rg -n 'alias\s+|autoindex\s+on|server_tokens\s+on|proxy_pass\s+\S*\$|ssl_protocols[^;]*TLSv1(\.1)?\b|snippet' -g '*.conf' -g 'nginx*'
rg -n 'Options\s+.*Indexes|AllowOverride\s+All|ProxyRequests\s+On|TraceEnable\s+On|SSLProtocol\s+all' -g '*.conf' -g '.htaccess'
rg -n 'authorizer|cors:\s*true|iamRoleStatements|url:\s*true' -g 'serverless.y*ml'
```

## Recommended tools

- Checkov (Terraform, CFN, K8s, Helm, Dockerfile, serverless), Trivy (`trivy config`, which absorbed tfsec; also images), KICS, cfn-lint + cfn-guard, kube-score, kubeconform, Kubescape, Polaris, Hadolint (Dockerfiles), testssl.sh (deployed TLS, authorized targets only), Semgrep (`p/terraform`, `p/kubernetes`, `p/dockerfile`), Gitleaks.

## Secure code patterns

```hcl
# Vulnerable
resource "aws_security_group_rule" "db" { type = "ingress" from_port = 5432 to_port = 5432
  protocol = "tcp" cidr_blocks = ["0.0.0.0/0"] security_group_id = aws_security_group.db.id }
# Fixed
resource "aws_security_group_rule" "db" { type = "ingress" from_port = 5432 to_port = 5432
  protocol = "tcp" source_security_group_id = aws_security_group.app.id security_group_id = aws_security_group.db.id }
```

```yaml
# Vulnerable pod spec
containers: [{ name: app, image: "app:latest", securityContext: { privileged: true } }]
# Fixed
automountServiceAccountToken: false
securityContext: { runAsNonRoot: true, seccompProfile: { type: RuntimeDefault } }
containers:
  - name: app
    image: registry.example.com/app@sha256:<digest>
    securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
    resources: { limits: { cpu: "500m", memory: "256Mi" } }
```

```nginx
# Vulnerable: /static../etc/passwd escapes the alias
location /static { alias /srv/app/static/; }
# Fixed
location /static/ { alias /srv/app/static/; }
```

```dockerfile
# Vulnerable
FROM node:latest
RUN curl -fsSL https://example.com/install.sh | sh
# Fixed
FROM node:22-slim@sha256:<digest>
COPY --chown=node:node . /app
USER node
```
