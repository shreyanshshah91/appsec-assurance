"""Deterministic file enumeration honoring exclusions and size limits."""

import fnmatch
import os
from typing import Iterator, List, Tuple

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".pdf", ".zip", ".gz",
    ".tgz", ".bz2", ".xz", ".7z", ".jar", ".war", ".class", ".so", ".dylib", ".dll",
    ".exe", ".bin", ".o", ".a", ".pyc", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi", ".wasm", ".sqlite", ".db", ".keystore", ".jks",
}


def is_excluded(rel: str, patterns: List[str]) -> bool:
    for p in patterns:
        if fnmatch.fnmatch(rel, p):
            return True
        # "dir/*" should also exclude the directory itself
        if p.endswith("/*") and (rel == p[:-2] or fnmatch.fnmatch(rel, p[:-2])):
            return True
    return False


def walk(root: str, excludes: List[str], max_kb: int) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Return (included relative paths, skipped [(path, reason)]). Sorted."""
    files: List[str] = []
    skipped: List[Tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        keep = []
        for d in sorted(dirnames):
            rel = f"{rel_dir}/{d}" if rel_dir else d
            if os.path.islink(os.path.join(dirpath, d)):
                skipped.append((rel, "symlinked directory not followed"))
            elif not is_excluded(rel + "/", excludes) and not is_excluded(rel, excludes):
                keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            rel = f"{rel_dir}/{fn}" if rel_dir else fn
            full = os.path.join(dirpath, fn)
            if is_excluded(rel, excludes):
                continue
            if os.path.islink(full):
                skipped.append((rel, "symlink not followed"))
                continue
            if os.path.splitext(fn)[1].lower() in BINARY_EXT:
                continue
            try:
                size = os.path.getsize(full)
            except OSError as e:
                skipped.append((rel, f"unreadable: {e}"))
                continue
            if size > max_kb * 1024:
                skipped.append((rel, f"larger than {max_kb} KB"))
                continue
            files.append(rel)
    return sorted(files), sorted(skipped)


def read_text(root: str, rel: str) -> str:
    with open(os.path.join(root, rel), "rb") as fh:
        data = fh.read()
    if b"\x00" in data[:8192]:
        raise ValueError("binary content")
    return data.decode("utf-8", "replace")


def iter_lines(text: str) -> Iterator[Tuple[int, str]]:
    for i, line in enumerate(text.splitlines(), 1):
        yield i, line
