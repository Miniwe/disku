#!/usr/bin/env python3
"""disku-clean -- run the reclaim commands that disku only prints.

disku measures and classifies and has no delete call anywhere, on purpose.
This is the other half, kept in a separate file so that stays true: it reads
disku's own findings, keeps the ones the knowledge base calls SAFE, and runs
the reclaim command the matching rule names -- the owning tool's command where
there is one (`apt-get clean`, `docker builder prune`), a move into a staging
directory where there is not.

Nothing runs without --yes. Without it the plan is printed and the disk is not
touched.

    ./disku-clean                   # the plan, nothing else
    ./disku-clean --yes             # run it
    ./disku-clean --yes --trash     # move aside instead of deleting, wherever
                                    # a rule would delete outright
    ./disku-clean --from report.json --yes
    sudo ./disku-clean --yes        # most of /var needs root, to see and to clean
    ./disku-clean --yes --caution   # also what costs a re-download or app state

What it will not do, with any flag: touch anything classified KEEP, remove a
docker volume or a named image in use, run a hint that is advice rather than a
command, or remove a path that is a system root or a home directory -- every
command is re-checked against that list after the path is interpolated into it.
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import disku as D          # human(), rel(), hint_text(), is_command()
import rules as R          # SAFE / CAUTION / KEEP

MB = 1024 * 1024
GB = 1024 * MB
HOME = os.path.expanduser("~")

# Paths no generated command may remove, whatever a rule says. Hints are
# curated text, but a scanned path is interpolated into them, so the result is
# checked once more here, right before it would run.
PROTECTED = {
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt",
    "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr",
    "/usr/bin", "/usr/lib", "/usr/local", "/usr/sbin", "/usr/share", "/usr/src",
    "/var", "/var/cache", "/var/lib", "/var/lib/docker", "/var/log", "/var/tmp",
    "/Applications", "/Library", "/System", "/Users", "/Volumes",
    HOME, os.path.join(HOME, "Documents"), os.path.join(HOME, "Desktop"),
}

# A command whose first word is one of these is deleting by path, so it gets
# the path check, the "is the owner running" check, and --trash rewriting.
DESTRUCTIVE = {"rm", "mv", "truncate", "shred", "find"}

DUPLICATE = "same command as an earlier line"

# ... and one of these frees nothing by itself: the rule is telling you to go
# look. Those are reported, never run.
INSPECTION = {"ls", "df", "list", "status", "show", "du", "ncdu", "mailq", "-l"}


def run(cmd, timeout=900, capture=True):
    """Run a shell command, returning (rc, output). Never raises."""
    try:
        p = subprocess.run(["sh", "-c", cmd], timeout=timeout, text=True,
                           stdin=subprocess.DEVNULL,   # a prompt must fail, not hang
                           stdout=subprocess.PIPE if capture else None,
                           stderr=subprocess.STDOUT if capture else None)
        return p.returncode, (p.stdout or "")
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except OSError as e:
        return 127, str(e)


def free_bytes(path="/"):
    try:
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize
    except OSError:
        return 0


# ------------------------------------------------------------------ the plan

class Action:
    """One command, what it is expected to free, and why it might not run."""

    def __init__(self, label, cmd, size=0, path="", quit_app="", note="",
                 safety=R.SAFE, group="safe", what=""):
        self.label = label
        self.what = what or label     # one line of prose under the path
        self.cmd = cmd
        self.size = size          # what disku measured, or docker's own estimate
        self.path = path
        self.quit_app = quit_app
        self.note = note          # the "# then: ..." half of a hint
        self.safety = safety
        self.group = group        # safe | docker | caution
        self.skip = ""            # set when the action will not run, and why
        self.freed = 0            # measured afterwards, not estimated

    @property
    def where(self):
        return D.rel(self.path) if self.path else self.label

    @property
    def destructive(self):
        return first_word(self.cmd) in DESTRUCTIVE


def first_word(cmd):
    parts = cmd.split()
    if parts and parts[0] == "sudo":
        parts = parts[1:]
    return parts[0].strip('"') if parts else ""


def split_hint(text):
    """A hint is `command   # what to do afterwards`. Keep the halves apart."""
    cmd, _, note = text.partition("#")
    return cmd.strip(), note.strip()


def looks_like_inspection(cmd):
    """`docker system df`, `nvm ls`, `docker volume ls` free nothing."""
    words = [w for w in cmd.split()[:3] if w != "sudo"]
    return any(w in INSPECTION for w in words[1:])


def unsafe_target(cmd):
    """The reason this command must not run, or None.

    Checks every path-looking argument after it has been interpolated: a root,
    a home directory, or anything shallow enough to be one is refused, and so
    is a command this parser cannot read.
    """
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return "cannot parse the command safely"
    for tok in tokens:
        if not (tok.startswith("/") or tok.startswith("~")):
            continue
        path = os.path.expanduser(tok)
        # A glob is only ever as dangerous as the directory holding it.
        if "*" in path or "?" in path:
            path = path.split("*")[0].split("?")[0]
            path = path if path.endswith("/") else os.path.dirname(path)
        path = os.path.normpath(path.rstrip("/") or "/")
        parts = [p for p in path.split("/") if p]
        if path in PROTECTED or len(parts) < 2:
            return f"refusing to touch {path}"
        if parts[0] in ("home", "Users") and len(parts) == 2:
            return f"refusing to touch the home directory {path}"
    return None


def plan_findings(data, args):
    """Turn disku's findings into actions, in the order the report recommends."""
    wanted = {R.SAFE} | ({R.CAUTION} if args.caution else set())
    actions = []
    for f in data["findings"]:
        if f["safety"] not in wanted or f["own_share"] < args.min_size:
            continue
        text = D.hint_text(_shim(f))
        cmd, note = split_hint(text)
        label = f"{D.rel(f['path'])} -- {f['label']}"
        if not cmd or not D.is_command(cmd):
            continue                      # advice, not a command: not ours to run
        if looks_like_inspection(cmd):
            continue
        if f["safety"] == R.CAUTION and first_word(cmd) in DESTRUCTIVE:
            continue                      # deleting by hand is never the careful path
        actions.append(Action(label, cmd, f["own_share"], f["path"],
                              f.get("quit_app", ""), note, f["safety"],
                              "safe" if f["safety"] == R.SAFE else "caution",
                              what=f["label"]))
    actions.sort(key=lambda a: (a.safety != R.SAFE, -a.size))
    return actions


class _shim:
    """disku.hint_text() wants a Finding; the JSON gives a dict."""

    def __init__(self, f):
        self.hint = f["hint"]
        self.path = f["path"]


# ---------------------------------------------------------------------- docker

DOCKER_UNITS = {"B": 1, "KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12,
                "KIB": 1 << 10, "MIB": 1 << 20, "GIB": 1 << 30, "TIB": 1 << 40}


def docker_bytes(s):
    m = re.match(r"\s*([\d.]+)\s*([A-Za-z]+)", s or "")
    if not m:
        return 0
    return int(float(m.group(1)) * DOCKER_UNITS.get(m.group(2).upper(), 1))


def docker_prefix():
    """How this user reaches the daemon: directly, or through sudo."""
    if not shutil.which("docker"):
        return None
    if run("docker system df", timeout=30)[0] == 0:
        return ""
    if os.geteuid() != 0 and run("sudo -n docker system df", timeout=30)[0] == 0:
        return "sudo "
    return None


def docker_reclaimable(prefix):
    """What docker itself says it can give back, per object type."""
    rc, out = run(prefix + 'docker system df --format "{{.Type}}\t{{.Reclaimable}}"',
                  timeout=30)
    sizes = {}
    if rc == 0:
        for line in out.splitlines():
            if "\t" in line:
                kind, _, rest = line.partition("\t")
                sizes[kind.strip().lower()] = docker_bytes(rest)
    return sizes


def plan_docker(args):
    """Stopped containers, dangling images, build cache -- never a volume.

    These are the bytes a directory walk cannot attribute. /var/lib/docker is
    one opaque tree to the walker (and disku rightly calls it CAUTION), because
    only the daemon knows which layer nothing refers to any more. So the
    question is asked of the daemon, and reclaimed through its own commands.
    """
    prefix = docker_prefix()
    if prefix is None:
        return [], ("docker is not installed, or its daemon is not reachable "
                    "from here -- skipping that part")
    sizes = docker_reclaimable(prefix)
    old = f" --filter until={args.docker_age}h" if args.docker_age else ""
    unused = f" --filter unused-for={args.docker_age}h" if args.docker_age else ""
    age = (f"older than {args.docker_age}h" if args.docker_age else "any age")

    out = [Action(
        "docker: stopped containers",
        f"{prefix}docker container prune -f{old}",
        sizes.get("containers", 0), group="docker",
        what=f"containers that exited and nothing restarted ({age})")]

    if args.docker_images:
        out.append(Action(
            "docker: unused images",
            f"{prefix}docker image prune -a -f{old}",
            sizes.get("images", 0), safety=R.CAUTION, group="docker",
            what=f"every image no container uses ({age}) -- costs a re-pull",
            note="a running container keeps its image; this only takes the rest"))
    else:
        out.append(Action(
            "docker: dangling images",
            f"{prefix}docker image prune -f{old}",
            0, group="docker",
            what=f"layers left untagged by a rebuild ({age}), referenced by nothing",
            note="docker reports dangling and unused-but-tagged as one number, "
                 "so the share freed here is not knowable in advance"))

    out.append(Action(
        "docker: build cache",
        f"{prefix}docker builder prune -f{unused}",
        sizes.get("build cache", 0), group="docker",
        what=f"BuildKit's cache of past build steps ({age})",
        note="the next build of each image is a cold one"))

    if run(prefix + "docker buildx version", timeout=20)[0] == 0:
        out.append(Action(
            "docker: buildx cache",
            f"{prefix}docker buildx prune -f{unused}", 0, group="docker",
            what="the same, for builders created with buildx"))
    return out, ""


# ----------------------------------------------------------------- guard rails

def process_running(name):
    """Best effort: an exact process name, or a systemd unit of that name."""
    if not name:
        return False
    if shutil.which("pgrep") and subprocess.run(
            ["pgrep", "-x", name], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL).returncode == 0:
        return True
    if shutil.which("systemctl") and subprocess.run(
            ["systemctl", "is-active", "--quiet", name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        return True
    return False


def vet(actions, args):
    """Mark what will not run, and why. Nothing is dropped silently."""
    seen = {}
    for a in actions:
        if a.cmd in seen:
            a.skip = DUPLICATE
            seen[a.cmd].size = max(seen[a.cmd].size, a.size)
            continue
        seen[a.cmd] = a

        bad = unsafe_target(a.cmd)
        if bad:
            a.skip = bad
            continue
        if a.destructive:
            if a.path and not os.path.exists(a.path):
                a.skip = "already gone"
                continue
            if a.quit_app and not args.force and process_running(a.quit_app):
                a.skip = (f"{a.quit_app} is running -- deleting a live cache is "
                          f"the one way this loses data (--force overrides)")
                continue
        if a.cmd.startswith("sudo ") and os.geteuid() == 0:
            a.cmd = a.cmd[5:]          # already root, keep the log honest
    return actions


def ensure_trash(actions):
    """Create the staging directory before the first move into it.

    `mv x ~/.disku-trash/` with no such directory yet does not fail -- it
    renames x *to* ~/.disku-trash, and the next move then lands inside the
    cache it was supposed to replace. Prepending the mkdir is also honest:
    the plan shows every directory the run will create.
    """
    for a in actions:
        if a.skip or "disku-trash" not in a.cmd or a.cmd.lstrip().startswith("mkdir"):
            continue
        m = re.search(r'~?[\w./-]*disku-trash[\w./-]*', a.cmd)
        if not m:
            continue
        sudo = "sudo " if a.cmd.startswith("sudo ") else ""
        a.cmd = f"{sudo}mkdir -p {m.group(0).rstrip('/')} && " + a.cmd
    return actions


def to_trash(actions, trashdir):
    """Rewrite outright removals into a move into a staging directory.

    The space only comes back when that directory is emptied, which is the
    point: until then every step is reversible.
    """
    for a in actions:
        if a.skip or first_word(a.cmd) != "rm":
            continue
        sudo = "sudo " if a.cmd.startswith("sudo ") else ""
        tokens = [t for t in shlex.split(a.cmd)[1:] if not t.startswith("-")]
        tokens = [t for t in tokens if t != "sudo"]
        moves = []
        for t in tokens:
            src = os.path.expanduser(t)
            stem = src.split("*")[0].rstrip("/")
            dest = os.path.join(trashdir, stem.strip("/").replace("/", "_"))
            moves.append(f"{sudo}mkdir -p {shlex.quote(dest)} && "
                         f"{sudo}mv {t} {shlex.quote(dest)}/")
        if moves:
            a.cmd = " && ".join(moves)
            a.note = (a.note + "; " if a.note else "") + \
                f"moved, not deleted -- the space returns when you empty {trashdir}"
    return actions


# --------------------------------------------------------------------- reports

W = 96


def rule(title):
    print(f"\n-- {title} " + "-" * max(0, W - len(title) - 4))


def show_plan(actions, args):
    groups = (("safe", "SAFE -- regenerated on demand"),
              ("docker", "DOCKER -- what the daemon says nothing refers to any more"),
              ("caution", "WITH CARE -- recoverable, but it costs you something"))
    total = 0
    n = 0
    for key, title in groups:
        rows = [a for a in actions if a.group == key and not a.skip]
        if not rows:
            continue
        rule(title)
        for a in rows:
            n += 1
            total += a.size
            size = D.human(a.size) if a.size else "?"
            print(f"  {n:>2}. {size:>8}  {a.where}")
            print(f"              {a.what}")
            print(f"              $ {a.cmd}")
            if a.note:
                print(f"              # {a.note}")
    skipped = [a for a in actions if a.skip and a.skip != DUPLICATE]
    if skipped:
        rule("NOT RUN")
        for a in skipped:
            print(f"  {(D.human(a.size) if a.size else '?'):>12}  {a.where}")
            print(f"              {a.skip}")
    return total, n


def show_untouched(args):
    rule("DELIBERATELY UNTOUCHED")
    print("   Real data, and things whose owner is the only one who should decide.")
    print()
    print("   * docker volumes -- databases and uploads live there")
    if not args.caution:
        print("   * everything disku calls CAUTION (--caution runs the native")
        print("     commands among those, never a hand-written rm)")
    if not args.docker_images:
        print("   * tagged images nothing runs (--docker-images, costs a re-pull)")
    print("   * every hint that is advice rather than a command: /usr/local, /opt,")
    print("     kernels, snap revisions and home directories stay yours to decide")


# ------------------------------------------------------------------- execution

def execute(actions, args):
    done = failures = 0
    freed_total = 0
    runnable = [a for a in actions if not a.skip]
    for i, a in enumerate(runnable, 1):
        before = free_bytes(args.volume)
        print(f"\n[{i}/{len(runnable)}] {a.where} -- {a.what}")
        print(f"          $ {a.cmd}", flush=True)
        rc, out = run(a.cmd, capture=not args.verbose)
        a.freed = max(0, free_bytes(args.volume) - before)
        if rc == 0:
            done += 1
            freed_total += a.freed
            print(f"          ok, {D.human(a.freed)} back")
            if a.note:
                print(f"          next: {a.note}")
        else:
            failures += 1
            print(f"          FAILED (exit {rc})")
            for line in (out or "").strip().splitlines()[-4:]:
                print(f"          | {line}")
            if a.path and os.path.isdir(a.path):
                keep = shlex.quote(args.trashdir)
                print(f"          the owning tool could not do it; by hand: "
                      f"mkdir -p {keep} && mv {shlex.quote(a.path)} {keep}/")
    return done, failures, freed_total


# ------------------------------------------------------------------------ main

def collect(args):
    """Either a report you already have, or a fresh scan by disku itself."""
    if getattr(args, "from_file", None):
        with open(args.from_file) as fh:
            return json.load(fh)
    out = args.json or os.path.join(tempfile.gettempdir(),
                                    f"disku-{os.getpid()}.json")
    cmd = [sys.executable, os.path.join(HERE, "disku.py"), "--json", out,
           "--min-size", str(args.min_size)]
    cmd += args.roots
    print("scanning first -- disku-clean only ever acts on what disku found",
          file=sys.stderr)
    p = subprocess.run(cmd, stdout=subprocess.DEVNULL)
    if p.returncode != 0 or not os.path.exists(out):
        print("disku-clean: the scan failed, nothing to do", file=sys.stderr)
        sys.exit(1)
    with open(out) as fh:
        data = json.load(fh)
    print(f"the scan is in {out} -- `--from {out}` skips rescanning", file=sys.stderr)
    return data


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="disku-clean",
        description="Run the reclaim commands disku prints. Prints the plan "
                    "and changes nothing unless --yes is given.")
    p.add_argument("roots", nargs="*", help="paths to scan (default: disku's own)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="actually run the plan (without this: a dry run)")
    p.add_argument("--from", dest="from_file", metavar="FILE",
                   help="reuse a report from `disku --json` instead of scanning")
    p.add_argument("--json", metavar="FILE", help="keep the fresh scan's json here")
    p.add_argument("--min-size", type=D.parse_size, default=50 * MB,
                   metavar="SIZE", help="ignore entries below this (50M)")
    p.add_argument("--caution", action="store_true",
                   help="also the CAUTION entries, through their own tool's command")
    p.add_argument("--trash", action="store_true",
                   help="move aside into a staging directory instead of deleting")
    p.add_argument("--trashdir", default=("/var/tmp/disku-trash"
                                          if os.geteuid() == 0
                                          else os.path.join(HOME, ".disku-trash")),
                   help="where --trash puts things")
    p.add_argument("--no-docker", dest="docker", action="store_false",
                   help="leave docker alone")
    p.add_argument("--docker-age", type=int, metavar="HOURS", default=0,
                   help="only docker objects unused for longer than this")
    p.add_argument("--docker-images", action="store_true",
                   help="also drop tagged images no container uses (a re-pull)")
    p.add_argument("--force", action="store_true",
                   help="delete a cache even while its app is running")
    p.add_argument("--volume", default="/", metavar="PATH",
                   help="filesystem to measure freed space on (/)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="let each command print its own output")
    args = p.parse_args(argv)

    data = collect(args)
    actions = plan_findings(data, args)
    docker_note = ""
    if args.docker:
        dock, docker_note = plan_docker(args)
        actions += dock
    actions = vet(actions, args)
    actions = ensure_trash(actions)
    if args.trash:
        os.makedirs(args.trashdir, exist_ok=True)
        actions = to_trash(actions, os.path.join(
            args.trashdir, time.strftime("%Y%m%d-%H%M%S")))

    print(f"\n{'=' * W}\n  DISKU-CLEAN -- "
          f"{'running the plan' if args.yes else 'dry run, nothing is touched'}"
          f"\n{'=' * W}")
    if docker_note:
        print(f"\n  {docker_note}")
    total, n = show_plan(actions, args)
    if not n:
        print("\n  nothing to reclaim above the cutoff. Try --min-size 10M, "
              "--caution, or sudo.")
        return 0
    print(f"\n  {n} commands, about {D.human(total)} expected back "
          f"(docker's share is its own estimate)")
    show_untouched(args)

    if not args.yes:
        print("\n  Nothing has been touched. Read the commands above, then "
              "re-run with --yes.")
        return 0

    before = free_bytes(args.volume)
    done, failures, freed = execute(actions, args)
    rule("RESULT")
    print(f"   {done} of {done + failures} commands ran")
    print(f"   {D.human(freed)} measured back, {args.volume} now has "
          f"{D.human(free_bytes(args.volume))} free "
          f"(was {D.human(before)})")
    if args.trash:
        print(f"   moved aside, not yet gone: {args.trashdir}")
        print(f"   $ rm -rf {args.trashdir}   # once the machine still works")
    print("   re-run disku to see what the numbers look like now")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
