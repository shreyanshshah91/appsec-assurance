# C / C++

**Detector keys:** `c`, `cpp` (also native code under Android NDK, iOS, Python/Node/Ruby extensions, Rust FFI)

Memory-unsafe code turns ordinary bugs into exploitable primitives. Review
every place where an attacker-influenced length, index, pointer lifetime or
format string meets memory. Prove reachability from an input source before
assigning high severity; a theoretical overflow in dead code is low.

## Untrusted input sources

- `read`/`recv`/`recvfrom`/`fread`/`fgets`/`getline`/`scanf` family, `argv`, `getenv` (esp. setuid binaries), `mmap`'d files, IPC (pipes, shared memory, D-Bus, Binder), file formats parsed by hand (images, archives, fonts, protocol frames), network protocol fields (lengths, offsets, counts), plugin/config files, JNI arguments (`GetStringUTFChars`, `GetByteArrayElements`), Python/Node extension arguments.

## Dangerous sinks

| Sink | Vulnerability class | CWE | Safe alternative |
|------|--------------------|-----|------------------|
| `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets` (removed in C11) | Stack/heap buffer overflow | CWE-120, CWE-121, CWE-122 | `snprintf`, `strlcpy`/`strlcat` (where available), `std::string`, `std::format` |
| `memcpy/memmove(dst, src, attacker_len)` | Out-of-bounds write | CWE-787 | Check `len <= sizeof dst` / remaining buffer; `std::span` / `std::vector::at` |
| `strncpy` (may not NUL-terminate), `strncat` size misuse | Missing terminator / overflow | CWE-170, CWE-787 | Explicit termination; `snprintf` |
| Array indexing with unchecked index; off-by-one loops (`<=`) | OOB read/write | CWE-125, CWE-787, CWE-193 | Bounds checks, `.at()`, hardened libc++/libstdc++ assertions |
| `printf(user)`, `syslog(prio, user)`, `fprintf(f, user)` | Format string | CWE-134 | `printf("%s", user)`; `-Wformat-security` |
| `malloc(n * size)`, `new T[n]` with attacker `n`; `size_t`↔`int` conversions | Integer overflow → undersized allocation | CWE-190, CWE-680, CWE-681 | `calloc`, `__builtin_mul_overflow`, `reallocarray`, C23 `ckd_mul`, `SIZE_MAX` checks |
| Signed/unsigned comparison of lengths | Integer signedness error | CWE-195, CWE-196 | Use `size_t` consistently; `-Wsign-compare` |
| `free` then use; returning pointers/references to locals; iterator invalidation after `push_back`/`erase` | Use-after-free / dangling reference | CWE-416, CWE-825 | RAII, `std::unique_ptr`/`shared_ptr`, null after free, no raw owning pointers |
| Double `free` / mismatched `new[]`/`delete` | Double free / heap corruption | CWE-415, CWE-762 | Single ownership; smart pointers |
| Uninitialized stack/heap variables | Info leak / undefined behavior | CWE-457, CWE-908 | Initialize; `-ftrivial-auto-var-init=zero`; `calloc` |
| Null deref on failed `malloc` | NULL pointer dereference | CWE-476 | Check return values |
| `system`, `popen`, `execl("/bin/sh","-c",...)` with input | OS command injection | CWE-78 | `execve`/`posix_spawn` with argv array |
| `access()` then `open()`; `/tmp` files with predictable names (`tmpnam`, `mktemp`) | TOCTOU / insecure temp file | CWE-367, CWE-377 | `open(O_CREAT\|O_EXCL\|O_NOFOLLOW)`, `mkstemp`, `openat` with dirfd |
| `rand()`, `srand(time(NULL))` for secrets | Weak PRNG | CWE-338 | `getrandom`, `arc4random_buf`, `BCryptGenRandom`, OpenSSL `RAND_bytes` |
| `memset` to clear secrets (optimized away) | Sensitive data retained | CWE-14 | `explicit_bzero`, `memset_s`, `SecureZeroMemory`, `OPENSSL_cleanse` |
| `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, ...)`, missing hostname check (`SSL_set1_host`) | Improper cert validation | CWE-295, CWE-297 | `SSL_VERIFY_PEER` + hostname verification; libcurl `CURLOPT_SSL_VERIFYPEER/HOST` left on |
| `alloca`/VLAs with attacker size; deep recursion | Stack exhaustion | CWE-770, CWE-674 | Heap allocation with limits; iteration |
| Data races on shared state; signal handlers calling non-async-signal-safe functions | Race condition | CWE-362, CWE-364 | Mutexes/atomics; `sig_atomic_t` flags only |

## Framework pitfalls and insecure defaults

- **Undefined behavior is exploitable:** signed overflow, strict-aliasing violations and null checks after deref can be optimized away (`if (p + len < p)` overflow checks are removed by the compiler — use `__builtin_add_overflow`).
- **C++ is not automatically safe:** `std::vector::operator[]`, `std::string_view`/`std::span` outliving their buffer, `c_str()` of temporaries, lambdas capturing by reference across async boundaries, `std::move`d-from objects, `reinterpret_cast`, `static_cast` downcasts on attacker-selected types (type confusion, CWE-843).
- **Parsers:** length fields trusted before validating against the remaining buffer; nested structures without depth limits; decompression bombs (CWE-409).
- **Build hardening often missing** in CMake/Makefiles/Bazel: check for `-O2 -D_FORTIFY_SOURCE=3` (or `=2`), `-fstack-protector-strong`, `-fstack-clash-protection`, `-fPIE -pie`, `-Wl,-z,relro,-z,now`, `-Wl,-z,noexecstack`, `-fcf-protection=full` (x86 CET) / `-mbranch-protection=standard` (AArch64), `-D_GLIBCXX_ASSERTIONS` or `-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST`, `-ftrivial-auto-var-init=zero`, `-Wall -Wextra -Wformat=2 -Wformat-security -Werror=format-security -Wconversion -Wsign-conversion -Wimplicit-fallthrough`. MSVC: `/GS`, `/guard:cf`, `/DYNAMICBASE`, `/HIGHENTROPYVA`, `/NXCOMPAT`, `/sdl`, `/Qspectre` where relevant. Follow the OpenSSF *Compiler Options Hardening Guide for C and C++*.
- **Verify the shipped binary** (not just the build file): `checksec --file=bin` (pwntools or the checksec.sh project), `readelf -d`, `hardening-check` (Debian devscripts).
- **setuid/privileged programs:** environment sanitization, `LD_PRELOAD`, relative paths, `PATH` lookups, dropping privileges correctly (`setgid` before `setuid`, check return values).
- **Vendored libraries** (zlib, libpng, OpenSSL, sqlite, expat) copied into the tree escape package scanners — inventory their versions manually.

## Authn/authz idioms to verify

- Privilege separation and dropping: `setresuid`/`setresgid` with checks, `capset`, seccomp-bpf or pledge/unveil sandboxes around parsers.
- Peer authentication on local sockets (`SO_PEERCRED`, `getpeereid`), file permission checks via `fstat` on the opened fd (not the path), `umask` set before creating sensitive files.
- Constant-time comparisons for MACs (`CRYPTO_memcmp`, `timingsafe_bcmp`), no home-grown crypto.

## Useful grep patterns

```bash
rg -n -t c -t cpp '\b(strcpy|strcat|sprintf|vsprintf|gets|wcscpy|wcscat|stpcpy|lstrcpy[AW]?|StrCpy)\s*\('
rg -n -t c -t cpp '\b(memcpy|memmove|strncpy|strncat|snprintf)\s*\('
rg -n -t c -t cpp '\b(printf|fprintf|syslog|vprintf|vsnprintf|wprintf)\s*\(\s*[a-zA-Z_]\w*\s*[,)]'
rg -n -t c -t cpp '\b(malloc|realloc|alloca)\s*\([^)]*\*'
rg -n -t c -t cpp '\b(system|popen|execlp|execvp)\s*\(|\b(tmpnam|tempnam|mktemp)\s*\('
rg -n -t c -t cpp '\b(rand|srand|random)\s*\(|SSL_VERIFY_NONE|CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*0'
rg -n -t c -t cpp '\bfree\s*\(|\bdelete\b|reinterpret_cast|const_cast'
rg -n -t c -t cpp '\b(access|stat|lstat)\s*\(' # then check for a later open() on the same path (TOCTOU)
rg -n 'FORTIFY_SOURCE|fstack-protector|-z,?relro|-z,?now|fPIE|-pie|fsanitize|Wformat-security' -g 'CMakeLists.txt' -g '*.cmake' -g 'Makefile*' -g '*.mk' -g 'meson.build' -g 'BUILD*'
```

## Recommended tools

- Compilers as analyzers: Clang/GCC warnings above, Clang Static Analyzer (`scan-build`), GCC `-fanalyzer`, clang-tidy (`bugprone-*`, `cert-*`, `cppcoreguidelines-*`), Cppcheck, Flawfinder (hot-spot listing), Semgrep (`p/c`), CodeQL (where licence permits).
- Sanitizers in tests/CI: AddressSanitizer (`-fsanitize=address`), UndefinedBehaviorSanitizer (`-fsanitize=undefined`), MemorySanitizer (Clang), ThreadSanitizer, LeakSanitizer; Valgrind memcheck.
- Fuzzing: libFuzzer, AFL++, honggfuzz; OSS-Fuzz / ClusterFuzzLite for continuous fuzzing of parsers.
- Binary checks: checksec, `hardening-check`. Dependencies: OSV-Scanner (Conan/vcpkg lockfiles where supported), Trivy for container images.

## Secure code patterns

```c
/* Vulnerable: unbounded copy */
char name[64]; strcpy(name, input);
/* Fixed */
char name[64];
if (snprintf(name, sizeof name, "%s", input) >= (int)sizeof name) return ERR_TOO_LONG;

/* Vulnerable: format string */
syslog(LOG_INFO, user_msg);
/* Fixed */
syslog(LOG_INFO, "%s", user_msg);

/* Vulnerable: integer overflow in allocation */
item_t *items = malloc(count * sizeof(item_t));
/* Fixed */
size_t bytes;
if (__builtin_mul_overflow(count, sizeof(item_t), &bytes)) return ERR_OVERFLOW;
item_t *items = malloc(bytes);   /* or: calloc(count, sizeof *items) */

/* Vulnerable: trusting a length field */
uint16_t len = read_u16(pkt); memcpy(out, pkt + 2, len);
/* Fixed */
if (len > pkt_len - 2 || len > sizeof out) return ERR_MALFORMED;
memcpy(out, pkt + 2, len);
```

```cpp
// Vulnerable: dangling view / iterator invalidation
std::string_view v = make_string();          // temporary destroyed
for (auto it = vec.begin(); it != vec.end(); ++it) if (bad(*it)) vec.push_back(fix(*it));
// Fixed
std::string s = make_string(); std::string_view v = s;
std::vector<T> extra; for (const auto& x : vec) if (bad(x)) extra.push_back(fix(x));
vec.insert(vec.end(), extra.begin(), extra.end());
```
