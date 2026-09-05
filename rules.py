"""Rule machinery: how a path is matched, and which knowledge base is loaded.

The rules themselves live in a per-platform module -- rules_linux.py or
rules_darwin.py. A cache path is only ever true for one operating system, and a
single merged list would make every match slower and every rule harder to read.

A rule says three things: how safe removal is, what the thing actually is, and
the *native* way to reclaim it (a package manager's own cleanup command always
beats `rm -rf`). Nothing here deletes -- these are report annotations.
"""

import importlib
import sys
from dataclasses import dataclass, field
from fnmatch import fnmatch
from functools import lru_cache

# Safety levels, ordered from "just take it" to "never".
SAFE = "safe"        # regenerable cache, losing it costs CPU time at most
CAUTION = "caution"  # regenerable, but costs a re-download or loses app state
KEEP = "keep"        # real user data; report the size, never suggest removal

SAFETY_ORDER = {SAFE: 0, CAUTION: 1, KEEP: 2}


def _split(p):
    return tuple(x for x in p.split("/") if x)


@dataclass(frozen=True)
class Rule:
    pattern: str          # home-relative glob, or absolute if it starts with /
    safety: str
    label: str            # what this directory is
    hint: str = ""        # how to reclaim it, {path} is substituted
    quit_app: str = ""    # app or service that must be stopped first
    tags: tuple = field(default_factory=tuple)
    descend: object = None  # None -> keep walking unless the match is SAFE

    @property
    def specificity(self):
        """Anchored components decide, so a named rule beats a wildcard one."""
        parts = _split(self.pattern)
        anchored = sum(1 for p in parts if "*" not in p)
        return (anchored, len(parts), len(self.pattern))

    @property
    def walk_in(self):
        """Whether to keep classifying below a match.

        A pure cache is reported whole -- nothing inside it is interesting. A
        profile, a sandbox or a service data directory is reported *and* walked,
        because the disposable parts are buried inside the parts you must keep.
        """
        if self.descend is not None:
            return self.descend
        return self.safety != SAFE


# Basename heuristics: catch caches in apps nobody wrote a rule for. Shared by
# both platforms -- an Electron app names its cache the same everywhere.
CACHE_BASENAMES = {
    "cache": "cache directory",
    "caches": "cache directory",
    ".cache": "cache directory",
    "cachedata": "cached compiled bundles",
    "cache_data": "cache directory",
    "cachestorage": "service-worker cache",
    "cache2": "browser disk cache",
    "code cache": "compiled-JS cache",
    "gpucache": "GPU shader cache",
    "shadercache": "shader cache",
    "dawncache": "GPU pipeline cache",
    "scriptcache": "script cache",
    "component_crx_cache": "extension download cache",
    "crx_cache": "updater's downloaded-package cache",
    "crashpad": "crash dumps",
    "crashes": "crash dumps",
    "logs": "log directory",
    "tmp": "temporary files",
    "temp": "temporary files",
    "thumbnails": "thumbnail cache",
    "blob_storage": "transient blob storage",
    "pendingcache": "pending cache",
    "__pycache__": "compiled Python bytecode",
    ".pytest_cache": "pytest run cache",
    ".mypy_cache": "mypy type-check cache",
    ".ruff_cache": "ruff lint cache",
    ".gradle": "Gradle project cache",
    ".terraform": "Terraform provider plugins (re-downloaded by terraform init)",
}

_MODULES = {"linux": "rules_linux", "darwin": "rules_darwin"}


def load(platform=None):
    """Import the knowledge base for `platform` and return its rules."""
    platform = platform or sys.platform
    name = _MODULES.get(platform)
    if name is None:  # a BSD, WSL, something new: the generic half still works
        for key, mod in _MODULES.items():
            if platform.startswith(key):
                name = mod
                break
    if name is None:
        return []
    return list(importlib.import_module(name).RULES)


def use(platform):
    """Swap the active knowledge base (tests, and cross-platform checks)."""
    global RULES, _BY_SPECIFICITY, HEURISTIC_HINT
    RULES = load(platform)
    mod = sys.modules.get(_MODULES.get(platform, ""))
    HEURISTIC_HINT = getattr(mod, "TRASH_HINT", HEURISTIC_HINT)
    _BY_SPECIFICITY = sorted(RULES, key=lambda r: r.specificity, reverse=True)
    match.cache_clear()
    return RULES


def _match_parts(parts, pat):
    """Glob per path component: `*` never crosses a `/`, `**` spans any depth.

    Plain fnmatch treats `*` as matching separators too, which made
    `Chrome/Profile *` swallow every file nested under a profile.
    """
    if not pat:
        return not parts
    if pat[0] == "**":
        return _match_parts(parts, pat[1:]) or (
            bool(parts) and _match_parts(parts[1:], pat))
    if not parts:
        return False
    return fnmatch(parts[0], pat[0]) and _match_parts(parts[1:], pat[1:])


@lru_cache(maxsize=8192)
def match(rel_path, basename):
    """The most specific rule covering `rel_path`, or a cache-name guess.

    `rel_path` is relative to whichever user's home the path lives in, or
    absolute for paths outside every home.
    """
    parts = _split(rel_path)
    is_abs = rel_path.startswith("/")
    for rule in _BY_SPECIFICITY:
        if rule.pattern.startswith("/") != is_abs:
            continue
        if _match_parts(parts, _split(rule.pattern)):
            return rule
    low = basename.lower()
    if low in CACHE_BASENAMES:
        return Rule("<heuristic>", SAFE, CACHE_BASENAMES[low].capitalize(),
                    HEURISTIC_HINT, "", ("heuristic", "cache"))
    return None


# Filled in by the platform module below: how it phrases "move this aside".
HEURISTIC_HINT = 'mv "{path}" ~/.disku-trash/'

RULES = load()
_BY_SPECIFICITY = sorted(RULES, key=lambda r: r.specificity, reverse=True)
_mod = _MODULES.get(sys.platform)
if _mod and _mod in sys.modules:
    HEURISTIC_HINT = getattr(sys.modules[_mod], "TRASH_HINT", HEURISTIC_HINT)
