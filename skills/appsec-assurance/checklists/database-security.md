# Database security

Scope: configuration and operation of data stores used by the application —
relational, document, key-value, search, cache and analytics stores: account
privilege, authentication, network exposure, encryption in transit and at
rest, row-level security, backups and snapshots, migrations, and connection
string handling. Query construction is covered in injection.md.

**Applies when:** any data store appears in `stack.json` or IaC (Postgres,
MySQL/MariaDB, SQL Server, Oracle, SQLite, MongoDB, Redis, Elasticsearch/
OpenSearch, Cassandra, DynamoDB, Firestore, Supabase, etc.), docker-compose
services, migrations, or connection strings.

**Standards:** OWASP A05:2021 Security Misconfiguration, A02:2021, A01:2021;
ASVS V13 Configuration, V14 Data Protection, V8 Authorization; CWE-250,
CWE-269, CWE-284, CWE-306, CWE-311, CWE-319, CWE-1188, CWE-1392, CWE-798,
CWE-530.

## Items

- **DB-01 — Application uses a least-privilege DB account** (high)
  - Verify: connection user in config/IaC is not `root`, `postgres`, `sa`, `admin`, `rdsadmin`; grants (migrations, `GRANT` scripts, Terraform `postgresql_grant`) limited to DML on app schemas; no `SUPERUSER`, `FILE`, `GRANT OPTION`, `xp_cmdshell`, `CREATE EXTENSION`, `pg_read_server_files`.
  - Fail: app connects as superuser — any SQLi becomes full DB/host compromise.
- **DB-02 — Separate accounts for migrations, app, read-only and analytics** (medium)
  - Verify: DDL-capable credentials used only by migration jobs; reporting uses read replica / read-only role.
  - Fail: runtime app holds DDL rights.
- **DB-03 — Authentication enabled; no default or weak credentials** (critical)
  - Verify: Redis `requirepass`/ACLs (`protected-mode yes`), MongoDB `--auth`/`security.authorization: enabled`, Elasticsearch security enabled (`xpack.security.enabled`), Memcached not network-exposed, docker-compose `POSTGRES_PASSWORD=postgres`, `MYSQL_ALLOW_EMPTY_PASSWORD`, `MYSQL_ROOT_PASSWORD=root`, `trust` in `pg_hba.conf`.
  - Fail: unauthenticated or default-credential stores reachable beyond localhost.
- **DB-04 — Network exposure** (critical if internet-reachable)
  - Verify: IaC `publicly_accessible = true` (RDS), security groups open on 5432/3306/1433/27017/6379/9200 to `0.0.0.0/0`, compose `ports: "5432:5432"` on hosts with public IPs, managed DB "allow all IPs" rules (Atlas `0.0.0.0/0`, Azure `AllowAllWindowsAzureIps`, Cloud SQL authorized networks), Firestore/Firebase rules `allow read, write: if true`.
  - Fail: DB reachable from the internet; permissive Firebase/Supabase rules.
- **DB-05 — Encryption in transit** (high)
  - Verify: `sslmode=verify-full` (or `require` at minimum), `useSSL=true&requireSSL=true`, `Encrypt=True;TrustServerCertificate=False`, `tls=true` for Mongo/Redis; server-side `rds.force_ssl`/`require_secure_transport`.
  - Fail: `sslmode=disable`, `TrustServerCertificate=True` across networks.
- **DB-06 — Encryption at rest** (medium)
  - Verify: `storage_encrypted = true`, KMS CMK where required, encrypted EBS/volumes for self-hosted DBs, encrypted snapshots and replicas, field-level encryption for high-sensitivity columns (CRYPTO-14).
  - Fail: unencrypted storage for PII/regulated data.
- **DB-07 — Row-level security and tenant isolation in the DB** (high for multi-tenant)
  - Verify: Postgres `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` with policies using `current_setting('app.tenant_id')`; app role not `BYPASSRLS`/owner; Supabase tables exposed via PostgREST all have RLS enabled and policies use `auth.uid()`; Supabase `service_role` key never in clients.
  - Fail: Supabase table without RLS (world-readable via anon key); tenant setting not reset between pooled connections.
- **DB-08 — Connection strings and credentials** (high)
  - Verify: credentials from secret manager/env, not committed (`DATABASE_URL=postgres://user:pass@`); IAM/managed identity DB auth where available; connection strings not logged on errors.
  - Fail: committed DSN with password (see SEC-01).
- **DB-09 — Backups and snapshots** (high)
  - Verify: automated backups enabled with retention; snapshots encrypted and **not public** (`aws_db_snapshot` sharing `all`, manual `restore` attributes); backup storage access restricted and in a separate account/project where possible; restore tested (ask user).
  - Fail: public or cross-account-shared snapshots; dumps in public buckets or committed (`*.sql`, `*.dump`, `*.bak`, `*.sqlite` in repo).
- **DB-10 — Migrations safety** (medium)
  - Verify: migrations reviewed for grants (`GRANT ALL ... TO PUBLIC`), disabling RLS, dropping constraints that enforce business rules, seeding default admin users/passwords, data backfills that log PII.
  - Fail: migration creates `admin/admin` or `GRANT ALL ON ALL TABLES TO public`.
- **DB-11 — Dangerous features disabled** (medium)
  - Verify: MSSQL `xp_cmdshell` off, MySQL `local_infile=0`, Postgres untrusted languages (`plpythonu`) not installed, Mongo server-side JS (`--noscripting`/`security.javascriptEnabled: false`), Redis `rename-command` for `CONFIG`/`FLUSHALL`/`MODULE` or ACL restrictions, Elasticsearch dynamic scripting limited.
- **DB-12 — Auditing and monitoring** (medium)
  - Verify: DB audit logs (pgaudit, RDS log exports, MySQL audit plugin, Atlas auditing) for privileged actions and auth failures; slow/failed query alerts.
  - Fail: no audit of privileged DB access (missing-control).
- **DB-13 — Data store version and patching** (medium)
  - Verify: engine versions in IaC/compose/images not EOL; auto minor version upgrade enabled for managed services.
- **DB-14 — Caches and search indexes hold sensitive data** (medium)
  - Verify: Redis/Elasticsearch/OpenSearch content (sessions, tokens, PII) protected like the primary DB; index-level access control; TTLs on cached personal data.
  - Fail: open Elasticsearch with user documents.
- **DB-15 — Connection pooling and session state** (medium)
  - Verify: per-request session variables (tenant ID, role via `SET ROLE`) reset on pool return (`DISCARD ALL`, `SET LOCAL` inside transactions); PgBouncer transaction mode compatibility.
  - Fail: tenant context leaks across requests through pooled connections.

## Common false positives
- Default credentials in docker-compose for local development only, bound to `127.0.0.1` and not used by deployment manifests — report info/low with a note.
- SQLite in desktop/CLI tools where OS user permissions are the boundary.
- `publicly_accessible = true` in a sandbox module that is never instantiated — verify module usage.

## Safe validation ideas
- Static review of IaC, compose, grants and migrations is usually sufficient for `confirmed`.
- On a local container only, connect with the app's configured role and run read-only privilege introspection (`\du`, `SELECT rolsuper FROM pg_roles WHERE rolname=current_user`, `SHOW GRANTS`). Never run DDL/DML against shared or production databases.
- Supabase/Firebase rules: use the official local emulator with seeded `appsec-canary-<rand>` documents to test rule evaluation.
