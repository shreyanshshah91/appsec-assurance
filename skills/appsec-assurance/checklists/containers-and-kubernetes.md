# Containers and Kubernetes

Scope: container image definitions (Dockerfile/Containerfile, compose),
Kubernetes workload and cluster-scoped manifests, Helm charts and Kustomize
overlays: runtime privilege, isolation from host, image provenance, secrets
handling, network segmentation, RBAC and service account usage.

**Applies when:** `Dockerfile*`, `Containerfile`, `docker-compose*.yml`,
Kubernetes YAML (`apiVersion:`/`kind:`), `Chart.yaml`/`values*.yaml`,
`kustomization.yaml`, Skaffold/Tilt configs, or ECS/Cloud Run task definitions
are present. Use Trivy/Checkov/kube-linter/kubescape output when available and
render Helm (`helm template`) only if Helm is installed and the chart has no
untrusted plugins — templating does not execute chart code beyond Go templates.

**Standards:** OWASP A05:2021 Security Misconfiguration, A08:2021, A06:2021;
ASVS V13 Configuration; CWE-250, CWE-269, CWE-732, CWE-1188, CWE-668, CWE-798,
CWE-770, CWE-494; CIS Docker/Kubernetes Benchmarks and Kubernetes Pod Security
Standards (baseline/restricted) as references.

## Dockerfile and images
- **CTR-01 — Non-root runtime user** (medium)
  - Verify: `USER` instruction with non-zero UID after package installs; base images that default to root (most do); compose `user:`.
  - Fail: no `USER` → container runs as root.
- **CTR-02 — Pinned base images** (medium)
  - Verify: `FROM image:tag@sha256:...`; no `:latest` or tagless `FROM`; automated digest updates (Renovate/Dependabot).
  - Fail: `FROM node:latest`, `FROM python` (non-reproducible, silent upstream changes).
- **CTR-03 — Minimal and maintained base** (low–medium)
  - Verify: distroless, `-slim`, Alpine, Chainguard/Wolfi, scratch for static binaries; base not EOL; image scan results (Trivy/Grype).
  - Fail: full OS images with compilers/shells in runtime stage; EOL distro.
- **CTR-04 — Multi-stage builds** (low)
  - Verify: build tools, source, `.git`, test deps stay in builder stage; final stage copies artifacts only.
- **CTR-05 — No secrets in layers** (high)
  - Verify: `ARG`/`ENV` holding tokens/passwords, `COPY .env`, `COPY . .` without `.dockerignore` excluding `.git`, `.env`, keys; `RUN echo $TOKEN > ~/.npmrc` even if deleted later (persists in layer). Use `RUN --mount=type=secret`.
  - Fail: secret retrievable via `docker history`/layer extraction.
- **CTR-06 — `ADD` with remote URLs and unverified downloads** (medium)
  - Verify: `ADD http...`, `RUN curl ... | sh`, downloads without checksum (`sha256sum -c`) or signature check; prefer `COPY` and `ADD --checksum=`.
  - Fail: unverified remote content in image.
- **CTR-07 — Healthy build hygiene** (low)
  - Verify: package manager caches cleaned, `--no-install-recommends`, no `chmod 777`, no `sudo` installed, no SSH server in image, exposed ports minimal.

## Kubernetes workloads
- **CTR-08 — No privileged containers** (critical)
  - Verify: `securityContext.privileged: true`, `allowPrivilegeEscalation` not set to `false`.
  - Fail: privileged pod = host root.
- **CTR-09 — Host namespaces and hostPath** (critical/high)
  - Verify: `hostNetwork`, `hostPID`, `hostIPC: true`; `hostPath` volumes (especially `/`, `/var/run/docker.sock`, `/var/lib/kubelet`, `/etc`, `/proc`); `hostPort`.
  - Fail: container can reach host processes/network or mount the container runtime socket.
- **CTR-10 — Linux capabilities** (high)
  - Verify: `capabilities.drop: ["ALL"]` then add only required; flag `add: [SYS_ADMIN, NET_ADMIN, SYS_PTRACE, DAC_READ_SEARCH, NET_RAW]`.
  - Fail: dangerous capabilities added or defaults kept for internet-facing pods.
- **CTR-11 — runAsNonRoot, UID and seccomp/AppArmor** (medium)
  - Verify: `runAsNonRoot: true`, `runAsUser` ≥ 10000, `seccompProfile.type: RuntimeDefault`, AppArmor/SELinux profiles; Pod Security Admission labels (`pod-security.kubernetes.io/enforce: restricted`) on namespaces.
  - Fail: no pod-level securityContext; namespaces without PSA enforcement.
- **CTR-12 — readOnlyRootFilesystem** (low–medium)
  - Verify: `readOnlyRootFilesystem: true` with `emptyDir` for writable paths.
- **CTR-13 — Resource requests and limits** (low–medium)
  - Verify: CPU/memory requests and limits (or LimitRange/ResourceQuota per namespace); ephemeral-storage limits.
  - Fail: no limits on internet-facing workloads (noisy-neighbor/DoS amplification).
- **CTR-14 — NetworkPolicy default deny** (medium–high)
  - Verify: per-namespace default-deny ingress *and* egress policies, explicit allows; egress to cloud metadata (`169.254.169.254/32`) blocked; CNI supports NetworkPolicy.
  - Fail: no NetworkPolicies → flat network; any compromised pod reaches DBs and metadata.
- **CTR-15 — RBAC least privilege** (high; critical for cluster-admin bindings)
  - Verify: Roles/ClusterRoles with `verbs: ["*"]`, `resources: ["*"]`, `apiGroups: ["*"]`; access to `secrets`, `pods/exec`, `pods/attach`, `nodes/proxy`, `serviceaccounts/token`, `create pods`, `escalate`, `bind`, `impersonate`; bindings to `system:authenticated`/`system:anonymous`; `cluster-admin` bound to app SAs.
  - Fail: wildcard or escalation-capable permissions for workloads.
- **CTR-16 — Service account tokens** (medium)
  - Verify: `automountServiceAccountToken: false` for pods not calling the API; dedicated SA per workload (not `default`); projected, audience-bound, short-lived tokens; no legacy long-lived SA token Secrets.
  - Fail: every pod mounts a token with broad RBAC.
- **CTR-17 — Secrets handling** (medium–high)
  - Verify: secrets via `secretKeyRef`/volumes from External Secrets/CSI driver/Sealed Secrets/SOPS, not literal `env.value`; ConfigMaps without credentials; etcd encryption at rest (cluster config, ask user); Secret manifests not committed with real values.
  - Fail: passwords in `env: - name: DB_PASSWORD value: ...`; plaintext Secret YAML in git.
- **CTR-18 — Image pull policy and provenance** (medium)
  - Verify: images referenced by digest (or immutable tags with `imagePullPolicy: Always` where mutable); private registry with `imagePullSecrets`; admission policy enforcing signature verification and allowed registries (Kyverno, Gatekeeper, Sigstore policy-controller).
  - Fail: `image: myapp:latest` with `IfNotPresent` (stale/poisoned node cache); images from arbitrary public registries.
- **CTR-19 — Exposure: Services, Ingress, dashboards** (high)
  - Verify: `type: LoadBalancer`/`NodePort` for internal services, Ingress without TLS or auth on admin paths, Kubernetes Dashboard, Argo CD/Grafana/Prometheus/etcd/kubelet ports exposed publicly, `loadBalancerSourceRanges` absent.
  - Fail: internal tooling internet-reachable.
- **CTR-20 — Probes, lifecycle and debug** (low)
  - Verify: no debug sidecars, `kubectl debug` ephemeral container policies, `shareProcessNamespace` only when needed, `stdin/tty` off in prod.

## Helm and Kustomize
- **CTR-21 — Secure chart defaults** (medium)
  - Verify: `values.yaml` defaults set securityContext, resources, NetworkPolicy enabled, `serviceAccount.create` with `automount: false`; no default passwords (`password: admin`); `lookup`/`tpl` on user values reviewed; third-party charts pinned by version and digest, from trusted repos; Helm plugins and post-renderers reviewed.
  - Fail: hardening only available as opt-in values that production overlays don't set — check rendered prod values.

## Common false positives
- `privileged`/`hostPath` in genuine node agents (CNI, CSI, log collectors, security agents) in `kube-system` — verify it's the vendor's manifest and pinned.
- `USER root` in builder stages of multi-stage builds.
- Missing NetworkPolicy where a service mesh enforces equivalent L4/L7 authorization (verify mesh policies).
- Local-dev compose files not used in deployment.

## Safe validation ideas
- Static analysis of manifests and rendered Helm output is sufficient for `confirmed` on configuration items.
- If a local cluster (kind/minikube) is in scope: `kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>` (read-only) to confirm RBAC breadth.
- `docker history --no-trunc <local-image>` / extracting layers of a locally built image to confirm secrets in layers — report redacted.
- Never exec into production pods, never attempt container escapes.
