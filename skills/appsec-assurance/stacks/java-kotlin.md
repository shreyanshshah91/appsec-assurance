# Java / Kotlin (Spring, Spring Boot, Spring Security, Jakarta EE)

**Detector keys:** `java`, `kotlin`, `spring`, `scala` (JVM sinks only, partial), `graphql` (Spring for GraphQL / graphql-java)

Android apps: read [mobile.md](mobile.md) for platform-specific issues; the JVM sinks below still apply to app code.

## Untrusted input sources

- Spring MVC/WebFlux: `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, `@ModelAttribute` (binds *every* matching field), `MultipartFile` (incl. `getOriginalFilename()`), `ServerRequest`, `HttpServletRequest.getParameter/getHeader/getInputStream`.
- JAX-RS: `@QueryParam`, `@PathParam`, `@FormParam`, `@HeaderParam`, entity bodies.
- Spring for GraphQL `@Argument`, WebSocket/STOMP `@MessageMapping` payloads, `@KafkaListener`/`@RabbitListener`/`@JmsListener` messages, `@Scheduled` jobs reading external data, RMI/JMX endpoints.

## Dangerous sinks

| Sink | Vulnerability class | CWE | Safe alternative |
|------|--------------------|-----|------------------|
| `Statement.execute*(sql + x)`, `JdbcTemplate.query("..."+x)` | SQL injection | CWE-89 | `PreparedStatement`, `?`/named params, `NamedParameterJdbcTemplate` |
| `EntityManager.createQuery("..."+x)`, `createNativeQuery`, `@Query` with SpEL concatenation, Criteria `builder.literal` misuse | JPQL/SQL injection | CWE-89 | `setParameter`, `:name` binding, Spring Data derived queries |
| `Sort.by(userField)` / `ORDER BY` from input | SQL injection (order) | CWE-89 | Allowlist sortable columns |
| `Runtime.exec(String)`, `ProcessBuilder("sh","-c", x)` | OS command injection | CWE-78 | `ProcessBuilder(List)` with fixed binary and validated args |
| `SpelExpressionParser.parseExpression(input).getValue()` with `StandardEvaluationContext` | Expression injection → RCE | CWE-917 | Don't evaluate input; `SimpleEvaluationContext.forReadOnlyDataBinding()` |
| OGNL/MVEL/JEXL evaluation of input | Expression injection | CWE-917 | Avoid; strict sandbox |
| `ObjectInputStream.readObject`, `XMLDecoder`, XStream `fromXML`, Hessian, Kryo without registration, SnakeYAML `new Yaml()` (< 2.0 `Constructor`) | Unsafe deserialization | CWE-502 | JSON with explicit types; `ObjectInputFilter` (JEP 290) allowlist; SnakeYAML `SafeConstructor` |
| Jackson `enableDefaultTyping()`, `activateDefaultTyping(LaissezFaireSubTypeValidator)`, `@JsonTypeInfo(use = Id.CLASS)` | Polymorphic deserialization gadgets | CWE-502 | `Id.NAME` + `@JsonSubTypes`; `BasicPolymorphicTypeValidator` allowlist |
| `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, JAXB `Unmarshaller` with defaults | XXE | CWE-611 | `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`; `XMLConstants.ACCESS_EXTERNAL_DTD=""` |
| Log4j 2 < 2.17.1 with lookups; logging attacker strings into `${jndi:...}`-interpreting loggers; `InitialContext.lookup(input)` | JNDI injection / RCE | CWE-917, CWE-74 | Patched Log4j (≥ 2.17.1 on Java 8), no JNDI lookups of input |
| Thymeleaf `return "view/" + input` (view name), `__${...}__` preprocessing, `th:utext` | SSTI / XSS | CWE-1336, CWE-79 | Fixed view names; `th:text`; Thymeleaf ≥ 3.1 restrictions |
| Freemarker `new Template(input)`, `?new` builtin; Velocity `evaluate` | SSTI | CWE-1336 | `TemplateClassResolver.ALLOWS_NOTHING_RESOLVER`; static templates |
| `new File(base, input)`, `Paths.get(input)`, `ResourceLoader.getResource(input)` | Path traversal | CWE-22 | `normalize()` + `startsWith(base)`; IDs instead of names |
| `RestTemplate/WebClient/URL.openConnection(input)` | SSRF | CWE-918 | Host allowlist; block link-local/private ranges |
| `"redirect:" + input` | Open redirect | CWE-601 | Allowlist targets |
| `java.util.Random` for tokens | Weak PRNG | CWE-338 | `SecureRandom` |
| `TrustManager` that accepts all, `HostnameVerifier` returning `true` | Improper cert validation | CWE-295 | Default `SSLContext`; pinned truststore |
| `Cipher.getInstance("AES")` (ECB default), `DES`, `MD5` passwords | Weak crypto | CWE-327, CWE-916 | `AES/GCM/NoPadding`; `BCryptPasswordEncoder`/`Argon2PasswordEncoder` |

## Framework pitfalls and insecure defaults

- **Actuator:** `management.endpoints.web.exposure.include=*` exposes `/env`, `/heapdump` (secrets in memory), `/configprops`, `/loggers` (write), `/threaddump`, `/jolokia`, `/gateway` (Spring Cloud Gateway route injection, CVE-2022-22947 class). Expose only `health`/`info`, put management on a separate port, require auth; `show-values` should be `never`.
- **Spring Security config:** `permitAll()` rules ordered before specific ones; `requestMatchers` patterns that miss trailing slashes/suffixes or differ between MVC and servlet matching; `csrf().disable()` / `csrf(AbstractHttpConfigurer::disable)` on cookie-session apps; `anyRequest().permitAll()`; `WebSecurityCustomizer.ignoring()` bypasses the whole filter chain (no headers either); multiple `SecurityFilterChain` beans without `securityMatcher` ordering; method security not enabled (`@EnableMethodSecurity` missing → `@PreAuthorize` ignored).
- **Mass assignment:** binding request bodies/`@ModelAttribute` directly to JPA entities (`role`, `isAdmin`, `accountId`) — use DTOs or `@InitBinder setAllowedFields` (CWE-915). Spring4Shell (CVE-2022-22965) class: data binding on old Spring on JDK 9+ with WAR deployment — check versions.
- **Spring Data REST** auto-exposes repositories (incl. delete/patch) unless `@RepositoryRestResource(exported=false)`.
- **Error handling:** `server.error.include-stacktrace=always`, `include-message`, H2 console enabled (`spring.h2.console.enabled=true`), devtools in production.
- **Secrets:** `application.yml`/`application.properties`, `bootstrap.yml`, Spring Cloud Config without encryption.
- **CORS:** `@CrossOrigin` with no args (all origins) or `allowedOriginPatterns("*")` + `allowCredentials(true)`.
- **Kotlin:** `!!` on input → NPE crashes; data classes bound directly to entities; coroutine context losing `SecurityContext` (use `ReactiveSecurityContextHolder` / context propagation).
- **Scala:** same JVM sinks; check Play `Action` without auth composition, Slick `#$` interpolation (raw SQL), Anorm string interpolation.

## Authn/authz idioms to verify

- `@PreAuthorize("hasRole('ADMIN')")`, `@PostAuthorize`, `@Secured`, `@RolesAllowed` — confirm method security is enabled and annotations are on proxied public methods (self-invocation bypasses proxies).
- Object-level: `@PreAuthorize("@authz.canRead(#id, authentication)")` or explicit `repository.findByIdAndOwner(id, principal)`; flag `findById(id)` followed by no ownership check.
- JWT resource server: `oauth2ResourceServer().jwt()` with issuer/audience validators; custom filters parsing JWTs with jjwt must call `parseSignedClaims` (not `parseUnsecured*`) and pin keys.
- Session fixation protection, `remember-me` key strength, `PasswordEncoder` choice, `DelegatingPasswordEncoder` with no `{noop}` entries.

## Useful grep patterns

```bash
rg -n '(createQuery|createNativeQuery|executeQuery|executeUpdate|prepareStatement|query|update)\(\s*"[^"]*"\s*\+' -g '*.{java,kt,scala}'
rg -n 'Runtime\.getRuntime\(\)\.exec|new ProcessBuilder\(' -g '*.{java,kt}'
rg -n 'ObjectInputStream|readObject\(|XMLDecoder|XStream|enableDefaultTyping|activateDefaultTyping|JsonTypeInfo\.Id\.CLASS|new Yaml\(' -g '*.{java,kt}'
rg -n 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|SAXReader|SAXBuilder' -g '*.{java,kt}'
rg -n 'SpelExpressionParser|parseExpression\(|StandardEvaluationContext|InitialContext\(\)\.lookup' -g '*.{java,kt}'
rg -n 'permitAll\(\)|csrf\(\)\.disable|AbstractHttpConfigurer::disable|ignoring\(\)|anyRequest\(\)\.permitAll' -g '*.{java,kt}'
rg -n 'management\.endpoints\.web\.exposure\.include|h2\.console\.enabled|include-stacktrace' -g '*.{properties,yml,yaml}'
rg -n 'th:utext|"redirect:"\s*\+|return\s+"[^"]*"\s*\+\s*\w+;' -g '*.{java,kt,html}'
rg -n 'X509TrustManager|HostnameVerifier|new Random\(|Cipher\.getInstance\("(AES|DES)' -g '*.{java,kt}'
rg -n 'log4j-core.*2\.(0|1[0-6])\.|<log4j2?\.version>' -g '*.{xml,gradle,kts}'
```

## Recommended tools

- SpotBugs + FindSecBugs, Semgrep (`p/java`, `p/kotlin`, `p/spring`), PMD, OWASP Dependency-Check, OSV-Scanner (`gradle.lockfile`, `pom.xml`), Trivy (JARs in images), detekt (Kotlin), CodeQL (where licence permits), Gitleaks.

## Secure code patterns

```java
// Vulnerable: JPQL injection
em.createQuery("FROM User u WHERE u.name = '" + name + "'");
// Fixed
em.createQuery("FROM User u WHERE u.name = :name", User.class).setParameter("name", name);

// Vulnerable: XXE
DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
// Fixed
DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
f.setXIncludeAware(false); f.setExpandEntityReferences(false);

// Vulnerable: Jackson polymorphic typing
mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, DefaultTyping.EVERYTHING);
// Fixed
mapper.activateDefaultTyping(BasicPolymorphicTypeValidator.builder()
    .allowIfSubType("com.example.dto.").build(), DefaultTyping.NON_FINAL);

// Vulnerable: Thymeleaf view-name SSTI
@GetMapping("/page") String page(@RequestParam String lang) { return "welcome_" + lang; }
// Fixed
return switch (lang) { case "en" -> "welcome_en"; case "fr" -> "welcome_fr"; default -> "welcome_en"; };

// Vulnerable: IDOR
return repo.findById(id).orElseThrow();
// Fixed
return repo.findByIdAndOwnerId(id, principal.getId()).orElseThrow(NotFoundException::new);
```
