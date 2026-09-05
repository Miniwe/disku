# disku

Finds where disk space went on **Linux** and **macOS**, and says what is safe to
drop.

**It never deletes anything.** There is no `rm`, `unlink`, `rmtree`, `mv` or
`truncate` call anywhere in the source — the tool measures, classifies, and
prints commands for you to read and run yourself.

```bash
./disku                       # full report on the usual suspects
sudo ./disku                  # on Linux most of /var needs root to measure
./disku --tree                # just the size tree
./disku /var/lib/docker --depth 3
./disku --md report.md --json report.json
./disku --min-size 500M       # only entries worth a click
./disku --no-probe            # do not shell out to journalctl / snap / docker
```

Python 3.8+, standard library only. Nothing to install.

## What it does

1. **Measures.** Parallel `scandir` walk counting *allocated blocks*
   (`st_blocks * 512`), which is what the filesystem actually spends and what
   `du` reports. Hardlinks are counted once. It stays on one filesystem, never
   follows symlinks, and skips bind mounts, so nothing is counted twice through
   a second view of the same bytes.
2. **Classifies** every directory against the knowledge base for the platform it
   is running on — `rules_linux.py` or `rules_darwin.py` — plus basename
   heuristics (`Cache`, `GPUCache`, `logs`, `__pycache__`, …) so tools nobody
   wrote a rule for still get caught. Rules are written relative to a home
   directory, so `.cache/pip` covers `/home/ubuntu`, `/home/deploy` and `/root`
   alike.
3. **Recommends**, in an order you can follow top-down, with a running total of
   what you get back if you stop at any line. Every hint prefers the owning
   tool's own cleanup command — `apt-get clean`, `journalctl --vacuum-size`,
   `docker builder prune` — over `rm -rf`, because those leave the tool with a
   consistent view of its own storage afterwards.

## The three verdicts

| | meaning | example |
|---|---|---|
| `SAFE` | rebuilt automatically; worst case is one slow start | `/var/cache/apt/archives` |
| `CAUTION` | recoverable, but costs bandwidth, a re-login, or local state | Docker's overlay2 tree |
| `KEEP` | your data. Reported for size only, shrink it through the app | `/var/lib/mysql` |

## What a directory walk cannot see

On a Linux box the answer to "df says full, du says empty" is usually not in any
directory, so the report has a section for the four places it hides instead:

- **Deleted files still held open.** The directory entry is gone, so no walker
  can find the bytes, but the inode lives until the last file descriptor closes.
  Restarting the process frees it instantly. Found by reading `/proc/*/fd`.
- **The root reserve.** ext4 holds back 5% for root by default. `df` counts it
  as used and you cannot have it — on a 200G data volume that is 10G, and
  `tune2fs -m 1` releases most of it.
- **Inodes.** A full inode table fails writes with free bytes left on the
  volume. Reported next to the byte usage.
- **Swap files, snapshots and other filesystems.** A swap file occupies its full
  size whether or not it is in use; btrfs/ZFS/LVM snapshots keep deleted files
  alive; a separate `/boot` can be 95% full while `/` looks fine. All three are
  listed rather than silently skipped.

It also asks the tools that know better than a walker can: `journalctl
--disk-usage`, `snap list --all` for retained old revisions, and `docker system
df`. Pass `--no-probe` to skip all three.

## Why the arithmetic is trustworthy

Four mistakes make this kind of tool lie, and each is handled explicitly:

- **Double counting through nesting.** A finding only charges itself the bytes
  its children did not already claim (`Finding.own_share`). Docker's data root
  and the `overlay2` tree inside it do not both bill 13G.
- **Double counting through mounts.** A bind mount shows a subtree that is
  already reachable somewhere else; walking both counts those bytes twice.
  `/proc/self/mountinfo` is read up front and every second view of a filesystem
  is skipped, along with everything that is not disk at all (`tmpfs`, `proc`,
  `overlay`, network mounts, and the squashfs images behind `/snap`).
- **Globs crossing directory boundaries.** `fnmatch`'s `*` matches `/` too,
  which makes `Chrome/Profile *` swallow every file nested under a profile.
  Matching is per path component; `**` is the explicit opt-in for any depth.
- **Scanning the same tree twice.** Roots that contain other roots are pruned
  before the walk, so `./disku / ~` does not count your home twice.

Known limits, also printed at the bottom of every report:

- Sizes are allocated blocks, so sparse files are charged what they occupy. A
  reflink copy (btrfs, XFS) is counted in full under every name, so a sum can
  exceed real usage; with btrfs or ZFS compression it can undercount instead.
- btrfs subvolumes and ZFS datasets look like separate filesystems to the walker
  and are skipped by default — they are listed under the volume line, and
  `--cross-fs` walks into them.
- Paths the current user cannot read are listed as *not measured*; totals are
  lower bounds until you re-run with `sudo`.
- A cache refills. Capping it in the tool that writes it beats deleting it
  repeatedly, and the hints say how wherever such a setting exists.

## Adding a rule

```python
Rule("/var/lib/yourthing/cache",   # home-relative, or absolute if it starts with /
     SAFE,                         # SAFE | CAUTION | KEEP
     "What this directory actually is",
     "yourthing cache clear",      # command, or plain advice
     "yourthing",                  # stop this service first
     ("dev",),
     descend=False)                # walk inside the match?
```

More anchored components win over fewer, so a specific rule always beats a
wildcard one. `descend=True` on a `SAFE` rule turns it into a container: it gets
itemised per tool instead of reported as one opaque lump (that is how
`/var/cache` and `~/.cache` are handled). `descend=False` on a `KEEP` rule keeps
the walker out of things that must stay intact. The `survey` tag marks a
container whose *contents* are nobody's business but yours (`/home`, `/srv`,
`/opt`, `/usr`) — the report lists the heavy directories inside it under
"unclassified heavyweights" instead of hiding them behind the parent.

## Files

- `disku.py` — scanner, classifier, report. Platform-neutral.
- `system.py` — what to scan, how the volume reports itself, which mounts must
  not be walked, and the space a walk cannot see. One class per platform.
- `rules_linux.py` — the Linux knowledge base (~180 rules)
- `rules_darwin.py` — the macOS knowledge base (~120 rules)
- `rules.py` — the `Rule` type and the matcher, shared by both
- `disku` — shim so it runs from anywhere
