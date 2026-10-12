#!/usr/bin/env python3
"""disku -- measure where disk space went, and say what is safe to drop.

Runs on Linux and macOS. The scanner, the arithmetic and the report are the
same on both; everything platform-specific lives in system.py (what to scan,
how the volume reports itself, which mounts must not be walked) and in
rules_linux.py / rules_darwin.py (which paths are junk and which are precious).

This tool is read-only by design: it contains no delete, move or truncate call
anywhere. It measures, classifies, and prints commands for you to run yourself
after reading them.

    ./disku.py                      # full report on the usual suspects
    ./disku.py --tree               # just the size tree
    ./disku.py /var/lib/docker --depth 3
    ./disku.py --md report.md --json report.json
    sudo ./disku.py                 # on Linux, most of /var needs root

Sizes are *allocated blocks* (what the filesystem actually spends), matching
`du`, not the logical file length.
"""

import argparse
import concurrent.futures as cf
import heapq
import json
import os
import sys
import threading
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rules as R
import system as S

SYS = S.detect()
HOME = os.path.expanduser("~")
MB = 1024 * 1024
GB = 1024 * MB
CLASSIFY_FLOOR = 20 * MB  # below this, a finding cannot matter


# --------------------------------------------------------------------- helpers

def human(n):
    if n is None:
        return "?"
    for unit, step in (("T", 1 << 40), ("G", 1 << 30), ("M", 1 << 20), ("K", 1 << 10)):
        if n >= step:
            return f"{n / step:.1f}{unit}"
    return f"{n}B"


def rel(path):
    """Home-relative path when inside $HOME, absolute otherwise (display only)."""
    if path == HOME:
        return "."
    if path.startswith(HOME + "/"):
        return path[len(HOME) + 1:]
    return path


COMMANDS = {
    # generic
    "mv", "rm", "sudo", "find", "git", "truncate", "du", "ncdu",
    # package managers
    "brew", "apt", "apt-get", "aptitude", "dpkg", "dnf", "yum", "pacman",
    "paccache", "snap", "flatpak", "nix-collect-garbage", "localepurge",
    # language toolchains
    "npm", "npx", "yarn", "pnpm", "pip", "pipx", "uv", "poetry", "conda",
    "go", "cargo", "rustup", "nvm", "pyenv", "gem", "bundle", "composer",
    "dotnet", "bazel", "ccache", "sccache", "pre-commit", "pod", "gradle",
    "mvn", "huggingface-cli", "ollama", "terraform",
    # containers
    "docker", "podman", "ctr", "crictl", "nerdctl", "lxc", "machinectl",
    # system
    "journalctl", "systemctl", "systemd-tmpfiles", "coredumpctl", "logrotate",
    "tune2fs", "cloud-init", "gio", "trash-put", "postsuper", "mailq",
    "xcrun", "tmutil", "defaults", "python3",
}


def is_command(hint):
    """A hint is runnable if it starts with something you can actually type."""
    return bool(hint) and hint.split(" ", 1)[0].strip('"') in COMMANDS


def hint_text(f):
    """The hint as you would actually run it against this particular path.

    Substituted by hand, not with str.format: a hint is prose, and prose
    contains braces. One of them is a daemon.json snippet, which format()
    reads as a replacement field and dies on.
    """
    text = f.hint.replace("{path}", f.path)
    if text.startswith('mv "'):
        parent = os.path.dirname(f.path.rstrip("/")) or "/"
        if not os.access(parent, os.W_OK):
            text = "sudo " + text.replace("~/.disku-trash/", "/var/tmp/disku-trash/")
    return text


def bar(fraction, width=22):
    filled = int(round(fraction * width))
    return "#" * filled + "." * (width - filled)


# ---------------------------------------------------------------------- scanner

class Node:
    __slots__ = ("path", "name", "size", "own", "nfiles", "children")

    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path) or path
        self.size = 0     # whole subtree, allocated bytes
        self.own = 0      # files directly inside this directory
        self.nfiles = 0
        self.children = []


class Scanner:
    def __init__(self, one_fs=True, top_files=30, skip=None):
        self.one_fs = one_fs
        self.skip = skip or (lambda path: False)
        self.denied = []
        self.skipped = []          # mounts deliberately not walked
        self.vanished = 0
        self.dirs = 0
        self.files = 0
        self.top_files = top_files
        self._heap = []            # (size, path) min-heap of the biggest files
        self._hardlinks = set()    # (dev, ino) already counted
        self._lock = threading.Lock()

    def _note_file(self, size, path):
        h = self._heap
        if len(h) < self.top_files:
            heapq.heappush(h, (size, path))
        elif size > h[0][0]:
            heapq.heapreplace(h, (size, path))

    def _take_dir(self, path, st, dev):
        """Walk into this directory? Mount rules first, then the one-fs rule."""
        if self.skip(path):
            with self._lock:
                self.skipped.append(path)
            return False
        if self.one_fs and st.st_dev != dev:
            with self._lock:
                self.skipped.append(path)
            return False
        return True

    def scan(self, root, dev=None):
        node = Node(root)
        try:
            st = os.lstat(root)
        except OSError as e:
            self.denied.append((root, e.strerror))
            return node
        if dev is None:
            dev = st.st_dev
        node.size = st.st_blocks * 512

        local_heap = []
        try:
            with os.scandir(root) as it:
                entries = list(it)
        except PermissionError as e:
            with self._lock:
                self.denied.append((root, e.strerror or "permission denied"))
            return node
        except OSError as e:
            with self._lock:
                self.denied.append((root, e.strerror or str(e)))
            return node

        subdirs = []
        for entry in entries:
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                self.vanished += 1
                continue
            if entry.is_symlink():
                node.size += st.st_blocks * 512
                continue
            if entry.is_dir(follow_symlinks=False):
                if self._take_dir(entry.path, st, dev):
                    subdirs.append(entry.path)
                continue
            # regular file / socket / device
            if st.st_nlink > 1:
                key = (st.st_dev, st.st_ino)
                with self._lock:
                    if key in self._hardlinks:
                        continue
                    self._hardlinks.add(key)
            sz = st.st_blocks * 512
            node.own += sz
            node.nfiles += 1
            local_heap.append((sz, entry.path))

        with self._lock:
            self.dirs += 1
            self.files += node.nfiles
            for sz, path in local_heap:
                if sz >= 8 * MB:
                    self._note_file(sz, path)

        node.size += node.own
        for sub in subdirs:
            child = self.scan(sub, dev)
            node.children.append(child)
            node.size += child.size
            node.nfiles += child.nfiles
        node.children.sort(key=lambda c: c.size, reverse=True)
        return node

    def scan_parallel(self, root, workers=8):
        """Scan `root`, fanning its immediate children out over a thread pool.

        stat/scandir release the GIL, so threads genuinely overlap here.
        """
        node = Node(root)
        try:
            st = os.lstat(root)
        except OSError as e:
            self.denied.append((root, e.strerror))
            return node
        dev = st.st_dev
        try:
            with os.scandir(root) as it:
                entries = list(it)
        except OSError as e:
            self.denied.append((root, e.strerror or str(e)))
            return node

        subdirs = []
        for entry in entries:
            try:
                est = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                if self._take_dir(entry.path, est, dev):
                    subdirs.append(entry.path)
            else:
                sz = est.st_blocks * 512
                node.own += sz
                node.nfiles += 1
                if sz >= 8 * MB:
                    self._note_file(sz, entry.path)
        node.size = node.own
        self.dirs += 1
        self.files += node.nfiles

        if subdirs:
            with cf.ThreadPoolExecutor(max_workers=workers) as pool:
                for child in pool.map(lambda p: self.scan(p, dev), subdirs):
                    node.children.append(child)
                    node.size += child.size
                    node.nfiles += child.nfiles
        node.children.sort(key=lambda c: c.size, reverse=True)
        return node

    def biggest_files(self):
        return sorted(self._heap, reverse=True)


# ------------------------------------------------------------------ classifying

@dataclass
class Finding:
    path: str
    size: int
    safety: str
    label: str
    hint: str
    quit_app: str
    tags: tuple
    pattern: str
    opaque: bool = True           # False for rules the walker keeps descending into
    nested_safe: int = 0          # SAFE bytes found inside a CAUTION/KEEP node
    children: list = field(default_factory=list)

    @property
    def own_share(self):
        """Bytes this finding alone accounts for, nested findings excluded."""
        return max(0, self.size - self.nested_safe)

    @property
    def nested_note(self):
        if not self.nested_safe:
            return ""
        return (f"contains {human(self.nested_safe)} that is itemised separately "
                f"({human(self.size)} in total)")


def classify(node, out, depth=0, max_depth=12, min_size=20 * MB):
    """Collect findings, returning only the outermost ones of each subtree.

    Hiding deeper findings from the parent is what keeps the arithmetic honest:
    a parent charges itself only the bytes its own children did not already
    claim, so Docker's data root and the overlay2 tree inside it no longer both
    bill 13G.
    """
    if node.size < min_size or depth > max_depth:
        return []

    rule = R.match(SYS.rulepath(node.path), node.name)
    if rule and not rule.walk_in:
        out.append(Finding(node.path, node.size, rule.safety, rule.label,
                           rule.hint, rule.quit_app, rule.tags, rule.pattern))
        return [out[-1]]

    nested = []
    for child in node.children:
        nested.extend(classify(child, out, depth + 1, max_depth, min_size))

    if rule:
        f = Finding(node.path, node.size, rule.safety, rule.label, rule.hint,
                    rule.quit_app, rule.tags, rule.pattern, opaque=False,
                    nested_safe=sum(n.size for n in nested), children=list(nested))
        out.append(f)
        return [f]
    return nested


def unclassified(node, findings, min_size, limit=15):
    """Dirs holding a lot of bytes directly, with no rule and no cache name.

    This is the "you have to look at this yourself" list. A directory covered
    by a rule is not a decision you have to make, so its subtree is skipped --
    except under the handful of rules tagged `survey` (/home, /srv, /opt, /usr,
    the temp roots), which say nothing about what is *inside* them.
    """
    by_path = {f.path: f for f in findings}
    hits = []

    def walk(n, depth):
        if n.size < min_size or depth > 8:
            return
        f = by_path.get(n.path)
        if f is not None:
            if f.opaque or "survey" not in f.tags:
                return
            for c in n.children:
                walk(c, depth + 1)
            return
        if n.own >= min_size:
            hits.append((n.own, n.path, n.nfiles))
        for c in n.children:
            walk(c, depth + 1)

    walk(node, 0)
    hits.sort(reverse=True)
    return hits[:limit]


def prune_contained(roots):
    """Drop roots that sit inside another root -- scanning both counts twice."""
    kept = []
    for path in sorted(roots, key=len):
        if any(path == k or path.startswith(k.rstrip("/") + "/") for k in kept):
            continue
        kept.append(path)
    return kept


# ---------------------------------------------------------------------- report

class Report:
    def __init__(self, out=sys.stdout, width=96):
        self.lines = []
        self.out = out
        self.width = width

    def w(self, s=""):
        self.lines.append(s)

    def h1(self, s):
        self.w()
        self.w("=" * self.width)
        self.w(f"  {s}")
        self.w("=" * self.width)

    def h2(self, s):
        self.w()
        self.w(f"-- {s} " + "-" * max(0, self.width - len(s) - 4))

    def flush(self):
        self.out.write("\n".join(self.lines) + "\n")

    def text(self):
        return "\n".join(self.lines) + "\n"


def render_tree(rep, node, depth_limit, top, indent="", depth=0, parent_size=None):
    if depth > depth_limit:
        return
    frac = (node.size / parent_size) if parent_size else 1.0
    name = node.name if depth else rel(node.path)
    if depth == 0:
        rep.w(f"{human(node.size):>8}  {name}")
    else:
        rep.w(f"{human(node.size):>8}  {bar(frac, 12)} {indent}{name}")
    shown = [c for c in node.children if c.size >= 20 * MB][:top]
    for c in shown:
        render_tree(rep, c, depth_limit, top, indent + "  ", depth + 1, node.size)
    hidden = [c for c in node.children if c not in shown]
    if hidden and depth < depth_limit:
        rest = sum(c.size for c in hidden)
        if rest >= 20 * MB:
            rep.w(f"{human(rest):>8}  {' ' * 12} {indent}  "
                  f"(+{len(hidden)} smaller entries)")


def emit_one(rep, f, indent="  "):
    rep.w(f"{indent}{human(f.own_share):>8}  {rel(f.path)}")
    rep.w(f"{indent}          {f.label}")
    if f.nested_note:
        rep.w(f"{indent}          {f.nested_note}")
    if f.quit_app:
        rep.w(f"{indent}          {SYS.stop_verb} {f.quit_app} first")
    if f.hint:
        rep.w(f"{indent}          {'$' if is_command(f.hint) else '->'} {hint_text(f)}")
    rep.w()


def build_report(roots, trees, scanner, args):
    rep = Report()
    info = SYS.usage()

    rep.h1("DISK")
    used_frac = info["used"] / info["total"] if info["total"] else 0
    rep.w(f"  volume    {human(info['total'])} total, {human(info['used'])} used "
          f"({used_frac * 100:.0f}%), {human(info['free'])} free")
    rep.w(f"            [{bar(used_frac, 60)}]")
    SYS.render_disk(rep, info, bar, human)
    scanned = sum(t.size for t in trees)
    rep.w()
    rep.w(f"  scanned   {human(scanned)} across {scanner.dirs:,} dirs / "
          f"{scanner.files:,} files")
    if scanner.skipped:
        rep.w(f"  not walked {len(scanner.skipped)} mount point(s): another "
              f"filesystem, or a second view of bytes already counted")

    # ---- where the space is
    rep.h1("WHERE THE SPACE IS")
    for t in sorted(trees, key=lambda n: n.size, reverse=True):
        if t.size < 100 * MB:
            continue
        rep.w()
        render_tree(rep, t, args.depth, args.top)

    # ---- findings
    # Classification always walks down to a fixed floor, so --min-size only
    # changes what gets printed, never the totals.
    findings = []
    for t in trees:
        classify(t, findings, min_size=CLASSIFY_FLOOR)
    # de-duplicate: keep the outermost record for a given path
    seen, uniq = set(), []
    for f in sorted(findings, key=lambda f: (len(f.path), -f.size)):
        if f.path in seen:
            continue
        seen.add(f.path)
        uniq.append(f)
    findings = uniq

    safe = sorted([f for f in findings if f.safety == R.SAFE],
                  key=lambda f: f.own_share, reverse=True)
    caution = sorted([f for f in findings if f.safety == R.CAUTION],
                     key=lambda f: f.own_share, reverse=True)
    keep = sorted([f for f in findings if f.safety == R.KEEP],
                  key=lambda f: f.own_share, reverse=True)

    safe_total = sum(f.own_share for f in safe)
    caution_total = sum(f.own_share for f in caution)

    rep.h1("VERDICT")
    rep.w(f"  {human(safe_total):>8}  SAFE      pure caches -- rebuilt automatically, "
          f"no data loss")
    rep.w(f"  {human(caution_total):>8}  CAUTION   recoverable but costs a re-download "
          f"or loses app state")
    pct = (safe_total + caution_total) / info["total"] * 100 if info["total"] else 0
    rep.w(f"  {human(safe_total + caution_total):>8}  reclaimable in total "
          f"({pct:.0f}% of the volume)")
    rep.w()
    rep.w("  Nothing below has been touched. This tool cannot delete: run the")
    rep.w("  commands yourself, top of the list first, and re-run to verify.")

    rep.h2("DO THIS, IN THIS ORDER")
    rep.w("   Free wins first, then the ones that cost you something. The running")
    rep.w("   total is what you get back if you stop at that line.")
    if SYS.trash_setup:
        rep.w(f"   Some hints move things aside instead of deleting them; run "
              f"`{SYS.trash_setup}` once first.")
    step, cum = 1, 0
    for tier, title in ((safe, "no downside"), (caution, "you pay something")):
        rows = [f for f in tier if f.own_share >= 500 * MB][:10]
        if not rows:
            continue
        rep.w()
        rep.w(f"   -- {title} " + "-" * 30)
        for f in rows:
            cum += f.own_share
            rep.w(f"  {step:>2}. {human(f.own_share):>7}  (total {human(cum):>7})  "
                  f"{rel(f.path)}")
            if f.hint:
                rep.w(f"      {'$' if is_command(f.hint) else '->'} {hint_text(f)}")
            step += 1
    rep.w()

    def emit(group, title, note):
        rep.h2(title)
        rep.w(f"   {note}")
        rep.w()
        small = 0
        for f in group:
            if f.own_share < args.min_size:
                small += f.own_share
                continue
            emit_one(rep, f)
        if small:
            rep.w(f"  {human(small):>8}  ... plus smaller entries below the "
                  f"{human(args.min_size)} cutoff")

    if safe:
        emit(safe, "SAFE TO REMOVE", "Regenerated on demand. Worst case: one slow "
                                     "app launch or one re-index.")
    if caution:
        emit(caution, "REMOVE WITH CARE",
             "Recoverable, but you pay for it -- bandwidth, re-login, lost local state.")
    if keep:
        rep.h2("KEEP -- REAL DATA")
        rep.w("   Big, but it is yours. Shrink these through the app that owns them,")
        rep.w("   never with rm.")
        rep.w()
        for f in keep:
            if f.own_share < args.min_size or "bundle" in f.tags:
                continue
            rep.w(f"  {human(f.own_share):>8}  {rel(f.path)}")
            rep.w(f"            {f.label}")
            if f.hint:
                rep.w(f"            -> {hint_text(f)}")
            rep.w()

    # ---- installed apps: the one KEEP category worth enumerating (macOS)
    apps = next((t for t in trees if t.path == "/Applications"), None)
    if apps:
        rep.h2("INSTALLED APPS, LARGEST FIRST")
        rep.w("   Uninstalling is the only safe way to shrink these. Anything you")
        rep.w("   have not opened in a year is a better target than any cache.")
        rep.w()
        for c in apps.children[:15]:
            if c.size < 200 * MB:
                break
            rep.w(f"  {human(c.size):>8}  {c.name}")

    # ---- unknowns
    rep.h2("UNCLASSIFIED HEAVYWEIGHTS")
    rep.w("   Directories with many bytes sitting directly inside them and no rule")
    rep.w("   matching. Decide these by hand.")
    rep.w()
    unknowns = 0
    for t in sorted(trees, key=lambda n: n.size, reverse=True)[:6]:
        for own, path, nfiles in unclassified(t, findings, args.min_size, 8):
            rep.w(f"  {human(own):>8}  {rel(path)}  ({nfiles} files here)")
            unknowns += 1
    if not unknowns:
        rep.w(f"   None above {human(args.min_size)}: every heavy directory matched "
              f"a rule.")

    rep.h2("BIGGEST INDIVIDUAL FILES")
    rep.w()
    biggest = scanner.biggest_files()[:20]
    for sz, path in biggest:
        rep.w(f"  {human(sz):>8}  {rel(path)}")
    if not biggest:
        rep.w("   Nothing above 8M -- the space is in the count of files, not in any"
              " one of them.")

    # ---- what a directory walk cannot see (platform-specific)
    SYS.render_extras(rep, human, probe=not args.no_probe)

    # ---- caveats
    rep.h2("READ BEFORE YOU DELETE")
    rep.w("""
   * Stop the service or app that owns a cache first. Deleting a live cache
     under a running process is how you corrupt its database, and that is the
     one way a "safe" cache removal turns into data loss.
   * Move things aside instead of rm -rf. The space comes back only once you
     empty the trash or the staging directory, but until then it is reversible.
   * A cache re-fills. If you need the space permanently, cap it in the tool
     that writes it -- the hints above say how, wherever such a setting exists.""")
    if SYS.caveats:
        rep.w(SYS.caveats)
    if scanner.denied:
        rep.h2(f"NOT MEASURED -- {len(scanner.denied)} PATHS DENIED")
        rep.w("   Numbers above are lower bounds.")
        rep.w()
        for path, err in scanner.denied[:12]:
            rep.w(f"   {rel(path)}  ({err})")
        if len(scanner.denied) > 12:
            rep.w(f"   ... and {len(scanner.denied) - 12} more")

    return rep, {
        "platform": SYS.name,
        "disk": {k: v for k, v in info.items() if not isinstance(v, bytes)},
        "safe_total": safe_total,
        "caution_total": caution_total,
        "findings": [
            {"path": f.path, "size": f.size, "own_share": f.own_share,
             "safety": f.safety, "label": f.label, "hint": f.hint,
             "quit_app": f.quit_app, "tags": list(f.tags), "rule": f.pattern}
            for f in safe + caution + keep
        ],
        "biggest_files": [{"path": p, "size": s}
                          for s, p in scanner.biggest_files()[:30]],
        "denied": [{"path": p, "error": e} for p, e in scanner.denied],
        "not_walked": scanner.skipped,
    }


def to_markdown(data, args):
    L = ["# Disk report", ""]
    d = data["disk"]
    L.append(f"- Volume: **{human(d['used'])} used** of {human(d['total'])}, "
             f"{human(d['free'])} free")
    L.append(f"- Safe to remove: **{human(data['safe_total'])}**")
    L.append(f"- Remove with care: **{human(data['caution_total'])}**")
    L.append("")
    for safety, title in ((R.SAFE, "Safe to remove"),
                          (R.CAUTION, "Remove with care"),
                          (R.KEEP, "Keep -- real data")):
        rows = [f for f in data["findings"] if f["safety"] == safety
                and f["own_share"] >= args.min_size]
        if not rows:
            continue
        L += [f"## {title}", "", "| Size | Path | What it is | How to reclaim |",
              "|---|---|---|---|"]
        for f in rows:
            hint = f["hint"].replace("{path}", f["path"]).replace("|", "\\|") or "--"
            L.append(f"| {human(f['own_share'])} | `{rel(f['path'])}` | "
                     f"{f['label']} | `{hint}` |")
        L.append("")
    L += ["## Biggest files", ""]
    for f in data["biggest_files"][:20]:
        L.append(f"- {human(f['size'])} `{rel(f['path'])}`")
    return "\n".join(L) + "\n"


def parse_size(s):
    s = s.strip().upper()
    mult = 1
    if s and s[-1] in "KMGT":
        mult = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[s[-1]]
        s = s[:-1]
    return int(float(s) * mult)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Measure disk usage and report what is safe to reclaim. "
                    "Never deletes anything.")
    p.add_argument("roots", nargs="*", help="paths to scan (default: usual suspects)")
    p.add_argument("--depth", type=int, default=2, help="tree depth to print (2)")
    p.add_argument("--top", type=int, default=8, help="children per tree level (8)")
    p.add_argument("--min-size", type=parse_size, default=100 * MB,
                   metavar="SIZE", help="ignore entries below this (100M)")
    p.add_argument("--tree", action="store_true", help="print the size tree only")
    p.add_argument("--json", metavar="FILE", help="also write machine-readable results")
    p.add_argument("--md", metavar="FILE", help="also write a markdown report")
    p.add_argument("-j", "--jobs", type=int, default=8, help="scan threads (8)")
    p.add_argument("--cross-fs", action="store_true",
                   help="follow into other filesystems (default: stay on one)")
    p.add_argument("--no-probe", action="store_true",
                   help="skip external probes (journalctl, snap, docker system df)")
    args = p.parse_args(argv)

    raw = args.roots or SYS.default_roots
    roots = []
    for r in raw:
        path = os.path.realpath(os.path.expanduser(r))
        if os.path.isdir(path) and path not in roots:
            roots.append(path)
        elif not args.roots:
            continue
        elif not os.path.isdir(path):
            print(f"disku: no such directory: {r}", file=sys.stderr)
    roots = prune_contained(roots)

    if not roots:
        print("disku: nothing to scan", file=sys.stderr)
        return 1

    scanner = Scanner(one_fs=not args.cross_fs, skip=SYS.skip_dir)
    trees = []
    for root in roots:
        print(f"scanning {rel(root)} ...", file=sys.stderr, end="", flush=True)
        t = scanner.scan_parallel(root, workers=args.jobs)
        trees.append(t)
        print(f" {human(t.size)}", file=sys.stderr, flush=True)

    if args.tree:
        rep = Report()
        for t in sorted(trees, key=lambda n: n.size, reverse=True):
            rep.w()
            render_tree(rep, t, args.depth, args.top)
        rep.flush()
        return 0

    rep, data = build_report(roots, trees, scanner, args)
    rep.flush()

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(data, fh, indent=2)
        print(f"\nwrote {args.json}", file=sys.stderr)
    if args.md:
        with open(args.md, "w") as fh:
            fh.write(to_markdown(data, args))
        print(f"wrote {args.md}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
