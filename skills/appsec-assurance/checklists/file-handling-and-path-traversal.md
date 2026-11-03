# File handling and path traversal

Scope: file uploads (validation, size, storage, naming, serving), processing of
uploaded content (images, documents, media, archives), filesystem access built
from user input (path traversal, symlinks), archive extraction (zip slip,
decompression bombs) and serving user files back to browsers.

**Applies when:** upload handlers (multer, busboy, formidable, `request.FILES`,
`MultipartFile`, `IFormFile`, Active Storage, CarrierWave, Shrine), file system
calls with request-derived paths, archive libraries, image/document processors,
or object storage signed URLs are present.

**Standards:** OWASP A01:2021 Broken Access Control (traversal), A04:2021
Insecure Design, A05:2021; ASVS V5 File Handling; CWE-22, CWE-23, CWE-36,
CWE-73, CWE-59, CWE-434, CWE-400, CWE-409, CWE-646, CWE-552.

## Items

### Path traversal
- **FILE-01 — No user input in filesystem paths without canonical containment** (high; critical for write)
  - Verify: grep `open\(`, `readFile`, `createReadStream`, `sendFile`, `res.download`, `File(`, `Paths.get(`, `Path.Combine(`, `os.path.join(`, `filepath.Join(`, `send_file`, `send_from_directory`, `include`/`require` with variables (PHP LFI). Correct pattern: resolve to absolute canonical path (`realpath`, `Path.resolve()`, `getCanonicalPath`, `filepath.Clean` + `EvalSymlinks`) and verify it is inside the base dir with a separator-aware prefix check. Prefer ID→path mapping.
  - Fail: `os.path.join(BASE, user)` (absolute `user` discards BASE); `path.join` without containment; `startsWith(base)` without trailing separator (`/data/app` vs `/data/app-secrets`); decoding after validation.
- **FILE-02 — Encoded and platform-specific traversal** (medium)
  - Verify: handling of `%2e%2e%2f`, double encoding, `..\` on Windows, UNC paths, NUL bytes (older runtimes), Unicode normalization, `Path.Combine` with rooted second arg.
  - Fail: denylist stripping `../` once (`....//`).
- **FILE-03 — Symlinks and hard links** (medium)
  - Verify: serving or processing directories where users can create symlinks (uploaded archives, git repos, shared volumes); `O_NOFOLLOW`, `lstat` checks, `follow_symlinks=False`, express `static` `dotfiles`/symlink settings.
  - Fail: symlink inside upload dir points to `/etc` or app secrets.
- **FILE-04 — Archive extraction (zip slip)** (high)
  - Verify: `ZipFile.extractall`, `tarfile.extractall` (Python ≥ 3.12 `filter='data'`), `ZipInputStream` loops, `adm-zip`, `unzipper`, `archiver`, Go `archive/zip`, `SharpZipLib`. Each entry's resolved destination must stay inside target; reject symlink/hardlink entries and absolute paths.
  - Fail: entry names like `../../app/config.py` written outside target.
- **FILE-05 — Decompression bombs and resource limits** (medium)
  - Verify: limits on total uncompressed size, entry count, compression ratio, nesting depth; image pixel limits (`PIL.Image.MAX_IMAGE_PIXELS`, sharp `limitInputPixels`); PDF page limits.
  - Fail: unbounded extraction or decode of user files.

### Uploads
- **FILE-06 — Type validation by content, with allowlist** (high)
  - Verify: allowlist of extensions *and* magic-byte/content checks (`python-magic`, `file-type`, Apache Tika); extension from server-side mapping, not client filename; `Content-Type` from client ignored for decisions.
  - Fail: denylist (`.php` blocked but `.phtml`, `.php5`, `.phar`, `.jsp`, `.aspx`, `.svg`, `.html` allowed); trusting `file.mimetype` alone.
- **FILE-07 — Size limits** (medium)
  - Verify: body/upload size limits at proxy (`client_max_body_size`), framework (`limits.fileSize`, `MAX_CONTENT_LENGTH`, `spring.servlet.multipart.max-file-size`, `RequestSizeLimit`), and per-user quotas; streaming rather than buffering in memory.
  - Fail: no limits (disk/memory exhaustion).
- **FILE-08 — Storage location and naming** (high)
  - Verify: uploads stored outside web root/static dirs and never in an executable path; server-generated names (UUID); original name stored as metadata only; object storage bucket private; per-tenant prefixes.
  - Fail: uploads saved under `public/` with original filename → web shell if server executes that extension; overwrite of others' files by name collision.
- **FILE-09 — Serving user files safely** (high)
  - Verify: served from a separate sandbox origin/domain or with `Content-Disposition: attachment`, accurate `Content-Type`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox` for inline display; filename in `Content-Disposition` encoded (RFC 6266 `filename*`) to prevent header injection.
  - Fail: HTML/SVG/PDF uploads rendered inline on the main origin (stored XSS; see XSS-10).
- **FILE-10 — Access control on download** (high)
  - Verify: download endpoints check ownership (AUTHZ-12); signed URLs short-lived and scoped to one object; no listable bucket/directory.
  - Fail: guessable `/uploads/<id>` with no auth; presigned URLs valid for days.
- **FILE-11 — Image and document processing libraries** (high)
  - Verify: ImageMagick (`policy.xml` disabling `MVG`, `MSL`, `EPHEMERAL`, `URL`, `PS`, `PDF` coders if unused), GraphicsMagick, Ghostscript, LibreOffice, ExifTool, ffmpeg (`-protocol_whitelist file`), Pillow, libvips — versions current and processing isolated (container, seccomp, no network).
  - Fail: user files processed by outdated ImageMagick/Ghostscript with default policy; ffmpeg HLS playlists reading local files.
- **FILE-12 — Metadata and privacy** (low–medium)
  - Verify: EXIF/GPS stripped from images published to others; document metadata (author, paths) removed where relevant.
- **FILE-13 — Malware scanning where business-appropriate** (low–medium)
  - Verify: files shared between users (e.g. B2B document exchange) scanned (ClamAV, cloud provider scanning) before availability; quarantine state.
  - Fail: no scanning on a file-sharing product (missing-control).
- **FILE-14 — Temporary files** (low–medium)
  - Verify: `tempfile.mkstemp`/`NamedTemporaryFile`, `Files.createTempFile`, not predictable names in `/tmp` (`/tmp/upload_` + id); cleanup on error.
  - Fail: predictable temp paths (symlink race, CWE-377).
- **FILE-15 — Server-side includes and template lookup by name** (high)
  - Verify: template/view/locale/plugin names taken from input (`render(params[:page])`, `res.render(req.query.view)`, `require(userPath)`).
  - Fail: arbitrary local file inclusion or template execution.

## Common false positives
- `path.join(BASE, path.basename(user))` — basename strips directories (still check empty and `..` names).
- Paths built only from DB-generated UUIDs.
- Object storage keys with traversal sequences — S3 keys are flat; only an issue if later mapped to a filesystem or used in signed URL prefixes.

## Safe validation ideas
- Unit-test the path resolver with `../appsec-canary`, `%2e%2e/`, absolute paths and symlinks inside a scratch temp dir; assert rejection.
- Zip slip: craft a local test archive in the scratchpad with an entry `../appsec-canary-<rand>.txt` and extract via the app's function into a temp dir; check whether the marker escapes. Never target system paths.
- Upload: on a local instance, upload a benign text file renamed `appsec-canary.html` with `<p>appsec-canary</p>` and check serving headers. No web shells, no executable payloads.
