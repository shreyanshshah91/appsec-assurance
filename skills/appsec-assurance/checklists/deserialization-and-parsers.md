# Deserialization and parsers

Scope: conversion of untrusted bytes into objects or structures where the
format or library can instantiate types, execute code, fetch resources or
mutate shared prototypes: native serialization (pickle, Java, .NET, PHP, Ruby
Marshal), polymorphic JSON/YAML, XML parsers (XXE, entity expansion), and
JavaScript prototype pollution via unsafe merge/clone/path-set.

**Applies when:** inventory shows deserialization or XML parsing, cache/session
stores holding serialized objects, message queues with object payloads, or
deep-merge utilities on request data.

**Standards:** OWASP A08:2021 Software and Data Integrity Failures, A05:2021
(XXE); ASVS V1 Encoding and Sanitization, V15 Secure Coding and Architecture;
CWE-502, CWE-611, CWE-776, CWE-827, CWE-1321, CWE-915, CWE-94.

## Items

### Native and polymorphic deserialization
- **DESER-01 — Python pickle and friends** (critical when input is untrusted)
  - Verify: `pickle.load(s)`, `cPickle`, `dill`, `shelve`, `jsonpickle.decode`, `joblib.load`, `torch.load` (`weights_only=False` default in older versions), `numpy.load(allow_pickle=True)`, pandas `read_pickle`. Trace data origin: uploads, cookies, cache (Redis), queues, ML model files from users/hubs.
  - Fail: any untrusted or tamperable source. Signing with HMAC is mitigation only if the key is secret and verified before load.
- **DESER-02 — Java deserialization** (critical)
  - Verify: `ObjectInputStream.readObject`, `XMLDecoder`, XStream (without allowlist), Jackson `enableDefaultTyping`/`activateDefaultTyping` or `@JsonTypeInfo(use = Id.CLASS)`, SnakeYAML `new Yaml()` (pre-2.0 default constructor), Kryo without registration, Hessian, RMI/JMX endpoints. Look for `ObjectInputFilter` (JEP 290) allowlists.
  - Fail: untrusted streams deserialized with gadget-bearing classpath (commons-collections etc.).
- **DESER-03 — .NET deserialization** (critical)
  - Verify: `BinaryFormatter` (obsolete/removed in .NET 9), `NetDataContractSerializer`, `SoapFormatter`, `LosFormatter`, `ObjectStateFormatter`, Json.NET `TypeNameHandling` != `None`, `JavaScriptSerializer` with type resolver, ViewState without MAC/with leaked machineKey.
  - Fail: any of these on untrusted data.
- **DESER-04 — PHP and Ruby** (critical)
  - Verify: PHP `unserialize(` on input (use `json_decode` or `allowed_classes => false`), `phar://` wrappers on file functions with user paths; Ruby `Marshal.load`, `YAML.load` (Psych < 4 unsafe by default; use `safe_load`), `Oj.load` in object mode.
  - Fail: user-controlled serialized strings in cookies/params.
- **DESER-05 — YAML loaders** (high)
  - Verify: PyYAML `yaml.load(` without `SafeLoader` / `yaml.unsafe_load` / `FullLoader` on old versions; `ruamel` `typ='unsafe'`; js-yaml < 4 `load` (use default safe schema); SnakeYAML constructor.
  - Fail: untrusted YAML (CI configs, uploads, import features) parsed with object construction enabled.
- **DESER-06 — Node.js unsafe deserializers** (critical)
  - Verify: `node-serialize`, `serialize-to-js` with `eval`, `funcster`, `eval(`-based JSON parsing.
  - Fail: any on input.
- **DESER-07 — Integrity of serialized state** (high)
  - Verify: server-side state in cookies/hidden fields (ViewState, signed cookies, Rails `cookies.signed` with Marshal serializer on old versions) is MAC'd with a secret key and the key is not committed.
  - Fail: leaked `secret_key_base`/`machineKey`/`SECRET_KEY` combined with object deserialization = RCE.

### XML
- **DESER-08 — XXE: external entities disabled** (high)
  - Verify: Java `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory`/`TransformerFactory`/`SchemaFactory` with `disallow-doctype-decl` or external entities off; Python `lxml` `resolve_entities=False`, `no_network=True` (or `defusedxml`); .NET `XmlReaderSettings.DtdProcessing = Prohibit` (default safe in modern .NET, check `XmlResolver`); PHP `libxml_disable_entity_loader` (older) / no `LIBXML_NOENT`; Node `libxmljs` `noent: true` is unsafe.
  - Fail: default-configured factory in Java parsing uploads, SAML, SOAP, SVG, DOCX/XLSX, RSS.
- **DESER-09 — Entity expansion (billion laughs) and size limits** (medium)
  - Verify: DTDs disabled or entity expansion limits; max document size.
- **DESER-10 — XInclude and XSLT** (high)
  - Verify: `XIncludeAware(false)`; XSLT from users disabled (XSLT can read files / call extension functions); `FEATURE_SECURE_PROCESSING`.

### Prototype pollution and unsafe merge
- **DESER-11 — Deep merge / clone / set-by-path on user objects** (high)
  - Verify: `_.merge`, `_.defaultsDeep`, `_.set`/`_.setWith` with user paths, `deepmerge`, `merge-deep`, `dot-prop`, `object-path`, `jQuery.extend(true, ...)`, hand-written recursive merge without `__proto__`/`constructor`/`prototype` key filtering; `qs` with `allowPrototypes`. Check library versions for known pollution fixes.
  - Fail: `merge({}, req.body)` where body may contain `{"__proto__": {...}}`.
- **DESER-12 — Pollution gadgets** (high)
  - Verify: where pollution is possible, look for sinks reading inherited properties: options objects to `child_process.spawn` (`shell`, `env`), template engine options (EJS `outputFunctionName`, Pug), `isAdmin` checks on plain objects. Mitigations: `Object.create(null)`, `Map`, `Object.freeze(Object.prototype)`, `--disable-proto=delete`, schema validation rejecting `__proto__`.
  - Fail: pollution chain to authz bypass or RCE.
- **DESER-13 — Python class pollution / attribute setting** (medium)
  - Verify: `setattr(obj, key, value)` loops over user dicts, recursive merge into objects (can reach `__class__`, `__init__.__globals__`).
  - Fail: user-controlled attribute names.
- **DESER-14 — Other parsers** (medium)
  - Verify: CSV with formula injection on export (XSS-13); `ast.literal_eval` on huge inputs (DoS); TOML/INI/JSON parsers with duplicate keys handled differently across services (parser differential for authz); `JSON.parse` reviver misuse; MessagePack/CBOR ext types.

## Common false positives
- `pickle.load` on files produced and stored by the same trusted process in a non-user-writable location (still note if a cache like Redis is shared/unauthenticated).
- `yaml.load(..., Loader=yaml.SafeLoader)` or `yaml.safe_load`.
- Jackson with default typing disabled and no `@JsonTypeInfo(use=CLASS)`.
- Modern .NET `XmlDocument` with default `XmlResolver = null`.

## Safe validation ideas
- Never use gadget chains or RCE payloads. For pickle/Java/.NET, static proof (source → `load` call) is sufficient for `confirmed` when the source is clearly attacker-controlled.
- XXE: in a unit test, parse a local XML with an external entity pointing to a scratch file containing `appsec-canary-<rand>`; assert whether the marker appears. No network entities, no system files.
- Prototype pollution: unit-test the merge function with `JSON.parse('{"__proto__":{"appsecCanary":"<rand>"}}')` and check `({}).appsecCanary`; run in an isolated `node` process in the scratchpad.
- YAML: load a document with a harmless tag (e.g. `!!python/name:builtins.str`) in a test and assert the loader rejects it.
