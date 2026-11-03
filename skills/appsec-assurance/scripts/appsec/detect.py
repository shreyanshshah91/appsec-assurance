"""Technology stack detection from file extensions, manifests and configs."""

import json
import os
import re
from typing import Dict, List

from .walker import read_text

EXT_LANG = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin", ".go": "go", ".rb": "ruby", ".php": "php",
    ".cs": "csharp", ".rs": "rust", ".swift": "swift", ".dart": "dart", ".scala": "scala",
    ".ex": "elixir", ".exs": "elixir", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
    ".hpp": "cpp", ".m": "objective-c", ".vue": "javascript", ".svelte": "javascript",
    ".sql": "sql", ".sh": "shell", ".bash": "shell", ".ps1": "powershell", ".tf": "hcl",
}

SUPPORTED_LANGS = {"python", "javascript", "typescript", "java", "kotlin", "go", "ruby",
                   "php", "csharp", "rust", "swift", "dart", "c", "cpp", "shell", "hcl", "sql"}

# dependency name (lowercase) -> framework / datastore key
JS_FRAMEWORKS = {"express": "express", "@nestjs/core": "nestjs", "next": "nextjs",
                 "react": "react", "vue": "vue", "@angular/core": "angular",
                 "svelte": "svelte", "fastify": "fastify", "koa": "koa", "hapi": "hapi",
                 "@hapi/hapi": "hapi", "graphql": "graphql", "@apollo/server": "graphql",
                 "apollo-server": "graphql", "ws": "websocket", "socket.io": "websocket",
                 "react-native": "react-native", "electron": "electron"}
PY_FRAMEWORKS = {"django": "django", "flask": "flask", "fastapi": "fastapi",
                 "starlette": "starlette", "tornado": "tornado", "aiohttp": "aiohttp",
                 "graphene": "graphql", "strawberry-graphql": "graphql",
                 "ariadne": "graphql", "celery": "celery", "websockets": "websocket",
                 "channels": "websocket", "djangorestframework": "drf"}
DATASTORES = {"pg": "postgresql", "psycopg2": "postgresql", "psycopg2-binary": "postgresql",
              "psycopg": "postgresql", "asyncpg": "postgresql", "mysql": "mysql",
              "mysql2": "mysql", "pymysql": "mysql", "mysqlclient": "mysql",
              "mongoose": "mongodb", "mongodb": "mongodb", "pymongo": "mongodb",
              "motor": "mongodb", "redis": "redis", "ioredis": "redis",
              "sqlite3": "sqlite", "better-sqlite3": "sqlite", "sqlalchemy": "sql-orm",
              "prisma": "sql-orm", "@prisma/client": "sql-orm", "sequelize": "sql-orm",
              "typeorm": "sql-orm", "knex": "sql-orm", "drizzle-orm": "sql-orm",
              "elasticsearch": "elasticsearch", "@elastic/elasticsearch": "elasticsearch",
              "cassandra-driver": "cassandra", "boto3": "aws-sdk", "@aws-sdk/client-s3": "aws-sdk",
              "firebase-admin": "firebase", "@supabase/supabase-js": "supabase"}

LOCKFILES = {
    "npm": ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"],
    "pip": ["requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock"],
    "go": ["go.sum"], "cargo": ["Cargo.lock"], "bundler": ["Gemfile.lock"],
    "composer": ["composer.lock"], "maven": [], "gradle": ["gradle.lockfile"],
    "nuget": ["packages.lock.json"], "pub": ["pubspec.lock"],
}
MANIFESTS = {"package.json": "npm", "pyproject.toml": "pip", "setup.py": "pip",
             "Pipfile": "pip", "requirements.txt": "pip", "go.mod": "go",
             "Cargo.toml": "cargo", "Gemfile": "bundler", "composer.json": "composer",
             "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle",
             "pubspec.yaml": "pub"}


def _deps_from_package_json(text: str) -> List[str]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    names: List[str] = []
    for k in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        if isinstance(data.get(k), dict):
            names.extend(n.lower() for n in data[k])
    return names


_PY_REQ = re.compile(r"^\s*([A-Za-z0-9_.\-]+)")


def _deps_from_python(text: str) -> List[str]:
    names = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "[")):
            continue
        m = _PY_REQ.match(line.strip("\"', "))
        if m:
            names.append(m.group(1).lower().replace("_", "-"))
    return names


def detect(root: str, files: List[str]) -> Dict:
    langs: Dict[str, int] = {}
    frameworks, datastores, iac, containers, ci, mobile, cloud = (set() for _ in range(7))
    managers, manifests_found = set(), []
    basenames = {}
    for rel in files:
        base = os.path.basename(rel)
        basenames.setdefault(base, []).append(rel)
        ext = os.path.splitext(rel)[1].lower()
        if ext in EXT_LANG:
            lang = EXT_LANG[ext]
            langs[lang] = langs.get(lang, 0) + 1
        low = rel.lower()
        if base == "Dockerfile" or base.endswith(".Dockerfile") or base.startswith("Dockerfile."):
            containers.add("docker")
        if base in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            containers.add("docker-compose")
        if low.startswith(".github/workflows/") and ext in (".yml", ".yaml"):
            ci.add("github-actions")
        if base == ".gitlab-ci.yml":
            ci.add("gitlab-ci")
        if base == "Jenkinsfile":
            ci.add("jenkins")
        if low.startswith(".circleci/"):
            ci.add("circleci")
        if base in ("azure-pipelines.yml", "bitbucket-pipelines.yml"):
            ci.add(base.split("-")[0] + "-pipelines")
        if ext == ".tf":
            iac.add("terraform")
        if base == "Chart.yaml":
            iac.add("helm")
        if base in ("serverless.yml", "serverless.yaml"):
            iac.add("serverless-framework")
        if base == "Pulumi.yaml":
            iac.add("pulumi")
        if ext == ".bicep":
            iac.add("bicep")
            cloud.add("azure")
        if base == "AndroidManifest.xml":
            mobile.add("android")
        if base == "Info.plist" or ".xcodeproj/" in rel:
            mobile.add("ios")
        if base == "pubspec.yaml":
            mobile.add("flutter")
        if ext in (".graphql", ".gql"):
            frameworks.add("graphql")
        if base in MANIFESTS:
            managers.add(MANIFESTS[base])
            manifests_found.append(rel)
        if ext == ".csproj":
            managers.add("nuget")
            frameworks.add("dotnet")

    # Manifest-driven framework/datastore detection
    for rel in manifests_found:
        try:
            text = read_text(root, rel)
        except (OSError, ValueError):
            continue
        base = os.path.basename(rel)
        if base == "package.json":
            for d in _deps_from_package_json(text):
                if d in JS_FRAMEWORKS:
                    frameworks.add(JS_FRAMEWORKS[d])
                if d in DATASTORES:
                    datastores.add(DATASTORES[d])
                if d.startswith("@aws-sdk/") or d == "aws-sdk":
                    cloud.add("aws")
                if d.startswith("@google-cloud/"):
                    cloud.add("gcp")
                if d.startswith("@azure/"):
                    cloud.add("azure")
        elif base in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py"):
            deps = _deps_from_python(text) if base == "requirements.txt" else \
                [m.lower().replace("_", "-") for m in re.findall(r"[\"']([A-Za-z0-9_.\-]+)", text)]
            for d in deps:
                if d in PY_FRAMEWORKS:
                    frameworks.add(PY_FRAMEWORKS[d])
                if d in DATASTORES:
                    datastores.add(DATASTORES[d])
                if d in ("boto3", "botocore"):
                    cloud.add("aws")
                if d.startswith("google-cloud"):
                    cloud.add("gcp")
                if d.startswith("azure-"):
                    cloud.add("azure")
        elif base == "go.mod":
            for key, fw in (("gin-gonic/gin", "gin"), ("labstack/echo", "echo"),
                            ("gofiber/fiber", "fiber"), ("gorilla/mux", "gorilla"),
                            ("gorilla/websocket", "websocket"), ("gqlgen", "graphql"),
                            ("aws-sdk-go", "aws")):
                if key in text:
                    (cloud if fw == "aws" else frameworks).add(fw)
        elif base in ("pom.xml", "build.gradle", "build.gradle.kts"):
            if "spring-boot" in text or "springframework" in text:
                frameworks.add("spring")
            if "graphql" in text:
                frameworks.add("graphql")
        elif base == "Gemfile":
            if re.search(r"gem ['\"]rails['\"]", text):
                frameworks.add("rails")
        elif base == "composer.json":
            if "laravel/framework" in text:
                frameworks.add("laravel")
            if "symfony/" in text:
                frameworks.add("symfony")
        elif base == "Cargo.toml":
            for fw in ("actix-web", "axum", "rocket", "warp"):
                if fw in text:
                    frameworks.add(fw.replace("-web", ""))

    # YAML/JSON content sniffing for k8s / CloudFormation, Terraform providers
    for rel in files:
        ext = os.path.splitext(rel)[1].lower()
        if ext not in (".yml", ".yaml", ".json", ".tf", ".template"):
            continue
        if ext == ".json" and os.path.basename(rel) in ("package.json", "package-lock.json"):
            continue
        try:
            head = read_text(root, rel)[:20000]
        except (OSError, ValueError):
            continue
        if re.search(r"^apiVersion:\s*\S+", head, re.M) and re.search(r"^kind:\s*\S+", head, re.M):
            iac.add("kubernetes")
        if "AWSTemplateFormatVersion" in head or re.search(r"Type:\s*['\"]?AWS::", head):
            iac.add("cloudformation")
            cloud.add("aws")
        if ext == ".tf":
            for prov, name in (("aws", "aws"), ("google", "gcp"), ("azurerm", "azure")):
                if re.search(rf'provider\s+"{prov}"|resource\s+"{prov}_', head):
                    cloud.add(name)

    lockfiles = {}
    missing_locks = []
    for mgr in sorted(managers):
        found = [lf for lf in LOCKFILES.get(mgr, []) if lf in basenames]
        lockfiles[mgr] = found
        if not found and LOCKFILES.get(mgr):
            missing_locks.append(mgr)

    primary = [l for l, _ in sorted(langs.items(), key=lambda kv: (-kv[1], kv[0]))]
    unsupported = [l for l in primary if l not in SUPPORTED_LANGS]
    return {
        "languages": dict(sorted(langs.items(), key=lambda kv: (-kv[1], kv[0]))),
        "primary_languages": primary[:5],
        "frameworks": sorted(frameworks),
        "package_managers": sorted(managers),
        "manifests": sorted(manifests_found),
        "lockfiles": lockfiles,
        "missing_lockfiles": missing_locks,
        "datastores": sorted(datastores),
        "iac": sorted(iac),
        "containers": sorted(containers),
        "ci": sorted(ci),
        "mobile": sorted(mobile),
        "cloud": sorted(cloud),
        "unsupported_languages": unsupported,
        "file_count": len(files),
    }
