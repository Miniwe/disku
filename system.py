"""Platform facts: what to scan, what the volume looks like, what else eats space.

The scanner and the report in disku.py are platform-neutral. Everything that is
true of one operating system and false of the other lives here: where the
caches are, how the volume reports its size, which mounts must not be walked,
and the handful of "space that `du` cannot see" cases worth a section of their
own -- Time Machine snapshots on macOS, deleted-but-open files and a journal
with no cap on Linux.
"""

import os
import re
import shutil
import subprocess
import sys

MB = 1024 * 1024
GB = 1024 * MB
HOME = os.path.expanduser("~")


def _run(cmd, timeout=20):
    """Best-effort external probe: never raise, never hang."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return ""
    return p.stdout if p.returncode == 0 else (p.stdout or "")


def _statvfs(path):
    st = os.statvfs(path)
    total = st.f_blocks * st.f_frsize
    free_priv = st.f_bfree * st.f_frsize      # includes the root reserve
    avail = st.f_bavail * st.f_frsize         # what a normal user may use
    return {
        "total": total,
        "used": total - free_priv,
        "free": avail,
        "reserved": max(0, free_priv - avail),
        "inodes_total": st.f_files,
        "inodes_used": st.f_files - st.f_ffree if st.f_files else 0,
    }


# --------------------------------------------------------------------- base

class System:
    name = "generic"
    stop_verb = "stop"          # "quit Chrome first" vs "stop docker first"
    home_parents = ()           # /home, /Users -- one directory per account
    home_roots = ()             # /root, /var/root -- root's home
    trash_setup = ""            # run once before following any move-aside hint
    default_roots = []

    def volume(self):
        return "/"

    def usage(self):
        return _statvfs(self.volume())

    def rulepath(self, path):
        """Path as the rules see it: relative to whichever home it lives in.

        A rule written `.cache/pip` has to hold for /home/ubuntu, /home/deploy
        and /root alike, so home-stripping cannot be tied to the *current* user.
        """
        if path == HOME:
            return "."
        if path.startswith(HOME + "/"):
            return path[len(HOME) + 1:]
        for parent in self.home_parents:
            if path.startswith(parent + "/"):
                rest = path[len(parent) + 1:]
                _, sep, tail = rest.partition("/")
                return tail if sep and tail else "."
        for root in self.home_roots:
            if path == root:
                return "."
            if path.startswith(root + "/"):
                return path[len(root) + 1:]
        return path

    def skip_dir(self, path):
        return False

    def render_disk(self, rep, info, bar, human):
        pass

    def render_extras(self, rep, human, probe=True):
        pass

    caveats = ""


# -------------------------------------------------------------------- darwin

class Darwin(System):
    name = "macOS"
    stop_verb = "quit"
    home_parents = ("/Users",)
    home_roots = ("/var/root",)
    trash_setup = ""

    default_roots = [
        "~/Library",
        "~/.cache", "~/.npm", "~/.gradle", "~/.m2", "~/.cargo", "~/.rustup",
        "~/go", "~/.docker", "~/.nvm", "~/.pyenv", "~/.local/share",
        "~/.Trash", "~/Downloads",
        "/Applications", "/Library/Caches", "/Library/Application Support",
    ]

    def volume(self):
        return "/System/Volumes/Data"

    def usage(self):
        total, used, free = shutil.disk_usage(self.volume())
        info = {"total": total, "used": used, "free": free, "reserved": 0,
                "inodes_total": 0, "inodes_used": 0}
        out = _run(["tmutil", "listlocalsnapshots", "/"])
        info["snapshots"] = [l.strip() for l in out.splitlines()
                             if l.strip().startswith("com.apple")]
        for line in _run(["diskutil", "info", self.volume()]).splitlines():
            if "Purgeable" in line and ":" in line:
                info["purgeable_raw"] = line.split(":", 1)[1].strip()
        return info

    def render_disk(self, rep, info, bar, human):
        if info.get("purgeable_raw"):
            rep.w(f"  purgeable {info['purgeable_raw']}  (macOS frees this on demand; "
                  f"it is already counted as free)")
        if info.get("snapshots"):
            rep.w(f"  snapshots {len(info['snapshots'])} Time Machine local snapshot(s) "
                  f"holding deleted files hostage")
            for s in info["snapshots"][:5]:
                rep.w(f"            {s}")
            rep.w("            they expire on their own within 24h; "
                  "to force: tmutil deletelocalsnapshots <date>")

    caveats = """
   * Sizes are allocated blocks. APFS clones share blocks, so a cloned file is
     counted in full under every name -- the sum can exceed real disk usage, and
     deleting one copy frees less than stated.
   * Paths your terminal cannot read are listed as not measured. Grant Full Disk
     Access to the terminal (System Settings -> Privacy & Security) to see them."""


# --------------------------------------------------------------------- linux

PSEUDO_FS = {
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "ramfs", "cgroup", "cgroup2",
    "securityfs", "pstore", "bpf", "tracefs", "debugfs", "configfs", "fusectl",
    "mqueue", "hugetlbfs", "autofs", "binfmt_misc", "efivarfs", "nsfs",
    "rpc_pipefs", "selinuxfs", "squashfs", "overlay", "aufs", "iso9660",
}
NETWORK_FS = {
    "nfs", "nfs4", "cifs", "smb3", "ceph", "glusterfs", "9p", "afs", "fuse.sshfs",
    "fuse.s3fs", "fuse.rclone", "fuse.gvfsd-fuse", "fuse.portal",
}
ALWAYS_SKIP = ("/proc", "/sys", "/dev", "/run")


def _unescape(s):
    return re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1), 8)), s)


class Mount:
    __slots__ = ("majmin", "root", "point", "fstype", "source")

    def __init__(self, majmin, root, point, fstype, source):
        self.majmin, self.root, self.point = majmin, root, point
        self.fstype, self.source = fstype, source

    @property
    def real(self):
        return (self.fstype not in PSEUDO_FS and self.fstype not in NETWORK_FS
                and self.source.startswith("/"))


class Linux(System):
    name = "Linux"
    stop_verb = "stop"
    home_parents = ("/home",)
    home_roots = ("/root",)
    trash_setup = "mkdir -p ~/.disku-trash /var/tmp/disku-trash"

    default_roots = ["/var", "/usr", "/opt", "/srv", "/home", "/root", "/tmp",
                     "/boot", "/nix", "~"]

    def __init__(self):
        self.mounts = self._read_mounts()
        self._skip = self._mounts_to_skip()

    # -- mounts ------------------------------------------------------------
    @staticmethod
    def _read_mounts():
        out = []
        try:
            with open("/proc/self/mountinfo") as fh:
                lines = fh.readlines()
        except OSError:
            return out
        for line in lines:
            f = line.split()
            if "-" not in f:
                continue
            sep = f.index("-")
            if sep + 2 >= len(f) or sep < 6:
                continue
            out.append(Mount(f[2], _unescape(f[3]), _unescape(f[4]),
                             f[sep + 1], f[sep + 2]))
        return out

    def _mounts_to_skip(self):
        """Mount points the walker must not enter.

        Two reasons, and the second one is the one that would otherwise lie:
        pseudo and network filesystems are not this disk's bytes at all, and a
        bind mount shows a subtree that is already reachable under its original
        mount -- walking both counts those bytes twice.
        """
        skip = set(ALWAYS_SKIP)
        seen = {}
        for m in self.mounts:
            if not m.real:
                skip.add(m.point)
                continue
            roots = seen.setdefault(m.majmin, [])
            if any(m.root == r or m.root.startswith(r.rstrip("/") + "/")
                   for r in roots):
                skip.add(m.point)   # bind mount / second view of the same subtree
            else:
                roots.append(m.root)
        skip.discard("/")
        return skip

    def skip_dir(self, path):
        return path in self._skip

    def mount_for(self, path, real_only=True):
        best = None
        for m in self.mounts:
            if real_only and not m.real:
                continue
            if path == m.point or path.startswith(m.point.rstrip("/") + "/"):
                if best is None or len(m.point) > len(best.point):
                    best = m
        return best

    # -- volume ------------------------------------------------------------
    def usage(self):
        info = _statvfs("/")
        m = self.mount_for("/", real_only=False)
        info["fstype"] = m.fstype if m else "?"
        info["source"] = m.source if m else "?"
        return info

    def render_disk(self, rep, info, bar, human):
        rep.w(f"  fs        {info['source']} ({info['fstype']})")
        if info["reserved"]:
            pct = info["reserved"] / info["total"] * 100
            rep.w(f"  reserved  {human(info['reserved'])} ({pct:.0f}%) held back for "
                  f"root -- df calls it used, you cannot have it")
            if info["fstype"] in ("ext2", "ext3", "ext4") and pct > 2:
                rep.w(f"            sudo tune2fs -m 1 {info['source']}  "
                      f"# releases most of it on a data volume")
        if info["inodes_total"]:
            used = info["inodes_used"]
            frac = used / info["inodes_total"]
            note = "   <- a full inode table fails writes with free bytes left" \
                if frac > 0.8 else ""
            rep.w(f"  inodes    {used:,} of {info['inodes_total']:,} used "
                  f"({frac * 100:.0f}%){note}")

        others, seen = [], set()
        try:
            seen.add(os.stat("/").st_dev)   # the volume above, under any other name
        except OSError:
            pass
        for m in self.mounts:
            if not m.real or m.point == "/" or m.point in self._skip:
                continue
            try:
                if not os.path.isdir(m.point):
                    continue            # bind-mounted single files (/etc/hosts)
                dev = os.stat(m.point).st_dev
                if dev in seen:
                    continue            # a second view of a filesystem already listed
                u = _statvfs(m.point)
            except OSError:
                continue
            if u["total"] < 200 * MB:
                continue
            seen.add(dev)
            others.append((m, u))
        if others:
            rep.w()
            rep.w("  other filesystems on this machine (each is scanned on its own,")
            rep.w("  and none of them borrows space from the volume above):")
            for m, u in sorted(others, key=lambda x: -x[1]["used"])[:10]:
                frac = u["used"] / u["total"] if u["total"] else 0
                flag = "  <-- nearly full" if frac > 0.9 else ""
                rep.w(f"    {human(u['used']):>8} / {human(u['total']):<8} "
                      f"{frac * 100:>3.0f}%  {m.point}  ({m.fstype}){flag}")

    # -- the space du cannot see -------------------------------------------
    def deleted_open_files(self, floor=50 * MB):
        """Files unlinked while a process still holds them open.

        The classic Linux "df says full, du says empty": the directory entry is
        gone so no walker can find the bytes, but the inode lives until the last
        descriptor closes. A restart of the process frees it instantly.
        """
        hits, seen = [], set()
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return hits
        for pid in pids:
            fddir = f"/proc/{pid}/fd"
            try:
                fds = os.listdir(fddir)
            except OSError:
                continue
            for fd in fds:
                link = f"{fddir}/{fd}"
                try:
                    target = os.readlink(link)
                except OSError:
                    continue
                if not target.endswith(" (deleted)"):
                    continue
                try:
                    st = os.stat(link)
                except OSError:
                    continue
                key = (st.st_dev, st.st_ino)
                if key in seen:
                    continue
                seen.add(key)
                size = st.st_blocks * 512
                if size < floor:
                    continue
                try:
                    with open(f"/proc/{pid}/comm") as fh:
                        comm = fh.read().strip()
                except OSError:
                    comm = "?"
                hits.append((size, pid, comm, target[:-len(" (deleted)")]))
        hits.sort(reverse=True)
        return hits

    def kernels(self):
        running = os.uname().release
        installed = []
        for base in ("/lib/modules", "/usr/lib/modules"):
            try:
                installed = sorted(os.listdir(base))
            except OSError:
                continue
            break
        boot = {}
        try:
            with os.scandir("/boot") as it:
                for e in it:
                    if e.name.startswith(("vmlinuz-", "initrd.img-")):
                        try:
                            boot[e.name] = e.stat().st_blocks * 512
                        except OSError:
                            pass
        except OSError:
            pass
        return running, installed, boot

    def loose_root_files(self, floor=100 * MB):
        out = []
        try:
            with os.scandir("/") as it:
                for e in it:
                    try:
                        if e.is_file(follow_symlinks=False):
                            sz = e.stat(follow_symlinks=False).st_blocks * 512
                            if sz >= floor:
                                out.append((sz, e.path))
                    except OSError:
                        continue
        except OSError:
            pass
        return sorted(out, reverse=True)

    def swaps(self):
        out = []
        try:
            with open("/proc/swaps") as fh:
                for line in fh.readlines()[1:]:
                    f = line.split()
                    if len(f) >= 4:
                        out.append((f[0], f[1], int(f[2]) * 1024, int(f[3]) * 1024))
        except OSError:
            pass
        return out

    def render_extras(self, rep, human, probe=True):
        rep.h2("SPACE THAT A DIRECTORY WALK CANNOT SEE")
        rep.w("   Everything above was found by walking directories. What follows is")
        rep.w("   real bytes on the same volume that no walk can reach.")
        rep.w()
        before = len(rep.lines)

        deleted = self.deleted_open_files()
        if deleted:
            total = sum(d[0] for d in deleted)
            rep.w(f"  {human(total):>8}  deleted files still held open -- freed the "
                  f"moment the process restarts")
            for size, pid, comm, path in deleted[:8]:
                rep.w(f"            {human(size):>8}  {comm} (pid {pid})  {path}")
            rep.w(f"            $ sudo systemctl restart <unit>   "
                  f"# or: kill the pid, if it is not a service")
            rep.w()
        elif os.geteuid() != 0:
            rep.w("            deleted-but-open files: only your own processes were")
            rep.w("            checked. Re-run with sudo to see the services' too.")
            rep.w()

        for dev, kind, size, used in self.swaps():
            rep.w(f"  {human(size):>8}  swap {kind} at {dev}  ({human(used)} in use)")
            if kind == "file":
                rep.w("            it occupies its full size on the filesystem even "
                      "when unused")
        loose = self.loose_root_files()
        if loose:
            rep.w()
            for size, path in loose[:6]:
                rep.w(f"  {human(size):>8}  {path}   (loose file directly in /)")

        if len(rep.lines) == before:
            rep.w("            nothing hiding here.")
            rep.w()

        running, installed, boot = self.kernels()
        if len(installed) > 2 or len(boot) > 6:
            rep.w()
            rep.w(f"  {len(installed)} kernels installed, running {running}")
            for k in installed:
                mark = "  <- running" if k == running else ""
                rep.w(f"            {k}{mark}")
            rep.w("            $ sudo apt-get autoremove --purge   "
                  "# keeps the running one and the previous one")

        if not probe:
            return

        journal = _run(["journalctl", "--disk-usage"], timeout=10).strip()
        snap_all = _run(["snap", "list", "--all"], timeout=15)
        docker_df = _run(["docker", "system", "df"], timeout=25) \
            if shutil.which("docker") else ""

        if journal or snap_all or docker_df:
            rep.h2("WHAT THE TOOLS THEMSELVES REPORT")
            rep.w()
        if journal:
            rep.w(f"  journald  {journal}")
            rep.w("            $ sudo journalctl --vacuum-size=200M")
            rep.w("            permanent cap: SystemMaxUse=200M in "
                  "/etc/systemd/journald.conf, then restart systemd-journald")
            rep.w()
        if snap_all:
            disabled = [l.split()[0] for l in snap_all.splitlines()
                        if "disabled" in l]
            if disabled:
                rep.w(f"  snap      {len(disabled)} disabled revision(s) kept as "
                      f"rollback: {', '.join(sorted(set(disabled))[:8])}")
                rep.w("            $ sudo snap set system refresh.retain=2")
                rep.w("            $ snap list --all | awk '/disabled/{print $1, $3}' "
                      "| while read n r; do sudo snap remove \"$n\" --revision=\"$r\"; done")
                rep.w()
        if docker_df:
            rep.w("  docker    system df says:")
            for line in docker_df.strip().splitlines():
                rep.w(f"            {line}")
            rep.w("            $ docker image prune -a && docker builder prune -a")
            rep.w()

    caveats = """
   * Sizes are allocated blocks, so sparse files (VM disks, database files) are
     charged what they really occupy, not their nominal length.
   * On btrfs and XFS a reflink copy shares blocks but is counted in full under
     every name, so a sum can exceed real usage; with btrfs or ZFS compression
     the opposite holds and totals here can undercount the logical data.
   * btrfs subvolumes and ZFS datasets look like separate filesystems to the
     walker and are skipped by default. They are listed under the volume line;
     scan them explicitly, or pass --cross-fs.
   * Snapshots (btrfs, ZFS, LVM) keep deleted files alive. If deleting changes
     nothing, list the snapshots before looking any further.
   * Paths this user cannot read are listed as not measured -- most of /var
     needs root. Re-run with sudo for a complete number."""


def detect(platform=None):
    platform = platform or sys.platform
    if platform.startswith("darwin"):
        return Darwin()
    if platform.startswith("linux"):
        return Linux()
    return Linux() if os.path.isdir("/proc") else System()
