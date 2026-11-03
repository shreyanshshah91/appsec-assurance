# Stack guides

Load a guide after `stack.json` reports a language or framework (Phase 1). Each
guide lists untrusted input sources, dangerous sinks (with CWE and the safe
alternative), framework pitfalls and insecure defaults, authn/authz idioms to
verify, ripgrep patterns for hot-spot hunting, recommended open-source tools and
vulnerable-vs-fixed code patterns.

Guides are review aids, not proof. A grep hit is a lead to trace from source to
sink; a clean grep is not evidence of absence.

## Language keys

| Detector key | Guide |
|--------------|-------|
| `python` | [python.md](python.md) |
| `javascript` | [javascript-typescript.md](javascript-typescript.md) |
| `typescript` | [javascript-typescript.md](javascript-typescript.md) |
| `java` | [java-kotlin.md](java-kotlin.md) |
| `kotlin` | [java-kotlin.md](java-kotlin.md) (+ [mobile.md](mobile.md) if `android`) |
| `go` | [go.md](go.md) |
| `ruby` | [ruby-rails.md](ruby-rails.md) |
| `php` | [php.md](php.md) |
| `csharp` | [dotnet.md](dotnet.md) |
| `rust` | [rust.md](rust.md) |
| `swift` | [mobile.md](mobile.md) (iOS section) |
| `dart` | [mobile.md](mobile.md) (Flutter section) |
| `scala` | [java-kotlin.md](java-kotlin.md) (JVM sinks apply) + generic checklists — partial coverage |
| `elixir` | none — generic checklists; record coverage gap (see below) |
| `c` | [c-cpp.md](c-cpp.md) |
| `cpp` | [c-cpp.md](c-cpp.md) |

## Framework keys

| Detector key | Guide | Section |
|--------------|-------|---------|
| `django` | [python.md](python.md) | Django, DRF |
| `flask` | [python.md](python.md) | Flask, Jinja2 |
| `fastapi` | [python.md](python.md) | FastAPI |
| `express` | [javascript-typescript.md](javascript-typescript.md) | Node/Express |
| `nestjs` | [javascript-typescript.md](javascript-typescript.md) | NestJS |
| `nextjs` | [javascript-typescript.md](javascript-typescript.md) | Next.js |
| `react` | [javascript-typescript.md](javascript-typescript.md) | Front-end escape hatches |
| `vue` | [javascript-typescript.md](javascript-typescript.md) | Front-end escape hatches |
| `angular` | [javascript-typescript.md](javascript-typescript.md) | Front-end escape hatches |
| `svelte` | [javascript-typescript.md](javascript-typescript.md) | Front-end escape hatches |
| `spring` | [java-kotlin.md](java-kotlin.md) | Spring / Spring Security |
| `rails` | [ruby-rails.md](ruby-rails.md) | all |
| `laravel` | [php.md](php.md) | Laravel |
| `symfony` | [php.md](php.md) | Symfony |
| `aspnet` | [dotnet.md](dotnet.md) | all |
| `gin` | [go.md](go.md) | gin/echo/fiber |
| `echo` | [go.md](go.md) | gin/echo/fiber |
| `fiber` | [go.md](go.md) | gin/echo/fiber |
| `actix` | [rust.md](rust.md) | actix/axum |
| `axum` | [rust.md](rust.md) | actix/axum |
| `graphql` | language guide for the server, plus `checklists/api-graphql-websocket.md` (resolver authz, depth/complexity limits, introspection, batching) | — |
| `android` | [mobile.md](mobile.md) | Android |
| `ios` | [mobile.md](mobile.md) | iOS |
| `flutter` | [mobile.md](mobile.md) | Flutter |
| `react-native` | [mobile.md](mobile.md) + [javascript-typescript.md](javascript-typescript.md) | React Native |

## Infrastructure and configuration

Terraform, CloudFormation, Kubernetes manifests, Helm, Docker/Compose, Nginx,
Apache and serverless.yml: [iac-and-config.md](iac-and-config.md), with the
detailed checks in `checklists/containers-and-kubernetes.md` and
`checklists/cloud-and-iac.md`.

## Multiple stacks

Load every matching guide. Monorepos commonly need a back-end guide, the
JS/TS guide for the front end, `mobile.md` and `iac-and-config.md`. Pay special
attention to the boundaries between them (e.g. a typed TS client that assumes a
server-side check exists).

## Unsupported or partially supported stacks

When the detector reports a key with no guide (e.g. `elixir`, or anything not
listed — Perl, Lua, Haskell, Clojure, COBOL, Solidity, R, low-code platforms):

1. Tell the user the stack has no dedicated guide.
2. Continue with the generic checklists in `checklists/README.md`, mapping each
   checklist concept onto the language's own APIs (find its equivalents of
   raw SQL, shell exec, eval, deserialization, template rendering, file paths,
   outbound HTTP, crypto RNG).
3. Run language-agnostic tools: Semgrep (check its registry for the language),
   OSV-Scanner on any lockfile, Gitleaks, Trivy for IaC/containers.
4. Record a coverage limitation in `.appsec/manual-findings.json`
   (`limitations`), e.g. "No stack guide for Elixir/Phoenix; manual review used
   generic checklists only; framework-specific pitfalls (e.g. Ecto fragments,
   Phoenix raw/1) may be under-covered." Mark stack-specific checklist items
   `untested` rather than `pass`.
5. For `elixir` specifically, at minimum review `Ecto.Adapters.SQL.query`/
   `fragment/1` with interpolation, `Phoenix.HTML.raw/1`, `:erlang.binary_to_term/1`
   (use the `[:safe]` option, still risky), `String.to_atom/1` on input (atom
   table exhaustion), `System.cmd`/`:os.cmd`, and run Sobelow and `mix_audit`.
