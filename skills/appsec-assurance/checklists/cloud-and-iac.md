# Cloud and infrastructure as code

Scope: cloud resources declared in Terraform/OpenTofu, CloudFormation/SAM/CDK
output, Azure Bicep/ARM, Pulumi programs, Serverless Framework and similar:
storage exposure, network ingress, IAM breadth, encryption, logging,
compute metadata settings, key management, IaC state handling and data
snapshots. Use Checkov/tfsec/Trivy config/KICS/cfn-lint+cfn-guard output when
present, then verify by reading the resource and every module input that feeds it.

**Applies when:** `*.tf`, `*.tfvars`, `*.tfstate`, CloudFormation/SAM templates
(`AWSTemplateFormatVersion`, `Transform: AWS::Serverless`), `cdk.json`/`cdk.out`,
`*.bicep`, ARM JSON, `Pulumi.yaml`, `serverless.yml` exist.

**Standards:** OWASP A05:2021 Security Misconfiguration, A01:2021, A02:2021,
A09:2021; API8:2023; ASVS V13 Configuration, V14 Data Protection; CWE-284,
CWE-732, CWE-269, CWE-250, CWE-311, CWE-319, CWE-778, CWE-1188, CWE-798,
CWE-668; CIS cloud benchmarks as references.

## Items

- **CLOUD-01 — No public object storage unless intended** (critical for sensitive data)
  - Verify: AWS `aws_s3_bucket_public_access_block` with all four flags true (and account-level block), bucket policies with `Principal: "*"` without restrictive conditions, ACLs `public-read`/`public-read-write`; GCS `allUsers`/`allAuthenticatedUsers` bindings, `uniform_bucket_level_access`, `public_access_prevention = "enforced"`; Azure `allow_blob_public_access`/`allowBlobPublicAccess`, container `access_type = "blob"|"container"`, SAS tokens in code.
  - Fail: public read/write on non-static-site buckets; public static sites must contain only public content.
- **CLOUD-02 — No unrestricted ingress** (critical for admin/DB ports, high otherwise)
  - Verify: security groups/NSGs/firewall rules with `0.0.0.0/0` or `::/0` on 22, 3389, 5432, 3306, 1433, 6379, 9200, 27017, 2375/2376, 10250, 5601, all ports (`-1`, `0-65535`); GCP `source_ranges = ["0.0.0.0/0"]`; Azure `source_address_prefix = "*"`.
  - Fail: SSH/RDP/DB open to internet; prefer SSM Session Manager/IAP/Bastion.
- **CLOUD-03 — IAM least privilege, no wildcards** (high; critical for `*:*`)
  - Verify: `Action: "*"`, `"<svc>:*"`, `Resource: "*"` on write/admin actions, `NotAction` with Allow, `iam:PassRole` on `*`, `iam:*`, `sts:AssumeRole` on `*`, managed `AdministratorAccess`/`PowerUserAccess` attached to workloads; GCP primitive roles (`roles/owner`, `roles/editor`); Azure `Owner`/`Contributor` at subscription scope for app identities.
  - Fail: workload roles able to escalate (`iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `lambda:UpdateFunctionCode` + PassRole).
- **CLOUD-04 — Trust policies and cross-account access** (critical)
  - Verify: role trust `Principal: {"AWS": "*"}` without conditions; third-party roles without `sts:ExternalId`; service principals without `aws:SourceArn`/`aws:SourceAccount` (confused deputy); OIDC providers (GitHub, GitLab) without `sub` condition (see CICD-08); resource policies (KMS, SQS, SNS, Lambda, ECR) granting `*`.
  - Fail: any account/repo can assume the role.
- **CLOUD-05 — Encryption at rest** (medium; high for regulated data)
  - Verify: S3 default encryption (SSE-KMS for sensitive), EBS `encrypted = true` and account default, RDS/Aurora `storage_encrypted`, DynamoDB SSE with CMK where required, EFS, SQS/SNS `kms_master_key_id`, Elasticache `at_rest_encryption_enabled`, GCP CMEK where policy requires, Azure storage `min_tls_version` + infrastructure encryption.
  - Fail: unencrypted stores holding PII/secrets.
- **CLOUD-06 — Encryption in transit** (medium)
  - Verify: S3 bucket policy denying `aws:SecureTransport = false`, ALB HTTPS listeners with modern TLS policies and HTTP→HTTPS redirect, CloudFront `viewer_protocol_policy = "redirect-to-https"` and minimum TLS, Elasticache `transit_encryption_enabled`, Azure `https_traffic_only_enabled`.
- **CLOUD-07 — KMS key policies and rotation** (medium)
  - Verify: `enable_key_rotation = true` for symmetric CMKs, key policies not granting `kms:*` to `*`, separation of key admins and key users, deletion window set.
  - Fail: broad decrypt rights; no rotation.
- **CLOUD-08 — Compute metadata hardening (IMDSv2)** (high)
  - Verify: `metadata_options { http_tokens = "required", http_put_response_hop_limit = 1 }` on instances and launch templates (hop limit 2 only if containers need it and with justification); account default IMDSv2; GCP/Azure equivalents (block metadata from untrusted workloads).
  - Fail: IMDSv1 allowed — SSRF becomes credential theft (chain with SSRF-06).
- **CLOUD-09 — Logging and audit trails** (medium)
  - Verify: CloudTrail multi-region with log file validation and S3/KMS protection, organization trail; VPC flow logs; S3 server access/data events for sensitive buckets; ALB/CloudFront access logs; GCP audit logs (Data Access for sensitive services); Azure diagnostic settings/Activity Log export; GuardDuty/Security Command Center/Defender enabled (ask user if not in IaC).
  - Fail: no audit trail for control-plane actions (missing-control).
- **CLOUD-10 — Public snapshots, images and shared resources** (critical)
  - Verify: `aws_db_snapshot`/`aws_ebs_snapshot` with `create_volume_permission`/`shared_accounts` = `all`, public AMIs, public ECR repositories with internal images, RDS `publicly_accessible = true`, public Lambda function URLs (`authorization_type = "NONE"`) on non-public functions, API Gateway without authorizers.
  - Fail: data snapshot or internal image shared publicly.
- **CLOUD-11 — IaC state and variable secrets** (high)
  - Verify: `terraform.tfstate*` or `.terraform/` committed; remote backend encrypted with restricted access and locking (S3 + KMS + DynamoDB/S3 lock, GCS with CMEK, Terraform Cloud); `sensitive = true` on secret variables/outputs; no secret defaults in `variables.tf`; Pulumi config secrets encrypted (`pulumi config set --secret`); CloudFormation `NoEcho` parameters and dynamic references to Secrets Manager rather than literals.
  - Fail: state in git (contains plaintext secrets); backend bucket world-readable.
- **CLOUD-12 — Serverless function configuration** (medium)
  - Verify: per-function least-privilege roles, env vars free of secrets (or KMS-encrypted + fetched at runtime), reserved concurrency for cost/DoS protection, function URLs/API routes authenticated, runtimes not deprecated.
- **CLOUD-13 — Network architecture** (medium)
  - Verify: data tier in private subnets, no public IPs on app instances by default (`associate_public_ip_address`, `map_public_ip_on_launch`), VPC endpoints for S3/KMS/Secrets Manager where egress restricted, default VPC/default security group not used and restricted.
- **CLOUD-14 — Backup, retention and deletion protection** (medium)
  - Verify: `deletion_protection = true` for prod DBs, S3 versioning and Object Lock for audit/backup buckets, backup vaults with access policies, `prevent_destroy` lifecycle for critical resources.
- **CLOUD-15 — Managed service exposure** (high)
  - Verify: OpenSearch/Elasticsearch domains with open access policies, Redis without auth, Kubernetes API endpoint public with `0.0.0.0/0` (`endpoint_public_access_cidrs`), Azure Storage/Key Vault/SQL `public_network_access_enabled = true` without firewall rules, GCP Cloud SQL `ipv4_enabled` with `0.0.0.0/0` authorized network.
- **CLOUD-16 — Policy-as-code and drift** (low)
  - Verify: Checkov/tfsec/OPA/Sentinel/cfn-guard in CI; drift detection; organization guardrails (SCPs, Org Policies, Azure Policy) — ask user if outside repo.

## Common false positives
- Public buckets intentionally hosting static websites/assets behind CloudFront (prefer OAC with private bucket; still low if content is public).
- `Resource: "*"` for actions that do not support resource-level permissions (e.g. some `Describe*`/`List*`), read-only.
- `0.0.0.0/0` on 80/443 for public load balancers.
- Example/test modules not instantiated in any environment root.

## Safe validation ideas
- Static evaluation of plans: if the user approves and credentials are already configured, `terraform plan`/`cdk synth` are read-only against cloud APIs, but prefer reviewing code; never `apply`/`deploy`/`destroy`.
- Use IAM policy simulators or `aws iam simulate-principal-policy` only with user approval and read-only credentials; never assume roles found in IaC.
- Do not probe cloud endpoints or buckets you find referenced; report from config evidence.
