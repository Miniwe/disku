# disku

Finds where disk space went on macOS and says what is safe to drop.

**It never deletes anything.** There is no `rm`, `unlink`, `rmtree`, `mv` or
`truncate` call anywhere in the source — the tool measures, classifies, and
prints commands for you to read and run yourself.

```bash
./disku                       # full report on the usual suspects
./disku --tree                # just the size tree
./disku ~/Library/Containers --depth 3
./disku --md report.md --json report.json
./disku --min-size 500M       # only entries worth a click
```

## What it does

1. **Measures.** Parallel `scandir` walk counting *allocated blocks*
   (`st_blocks * 512`), which is what the filesystem actually spends and what
   `du` reports. Hardlinks are counted once. It stays on one filesystem and
   never follows symlinks, so nothing is counted twice through a back-reference.
2. **Classifies** every directory against `rules.py` — ~120 rules covering
   browsers, Electron apps, sandboxed containers, dev toolchains, Xcode, Docker,
   plus basename heuristics (`Cache`, `GPUCache`, `CacheStorage`, `logs`, …) so
   apps nobody wrote a rule for still get caught.
3. **Recommends**, in an order you can follow top-down, with a running total of
   what you get back if you stop at any line.

## The three verdicts

| | meaning | example |
|---|---|---|
| `SAFE` | rebuilt automatically; worst case is one slow app launch | `~/Library/Caches/Google` |
| `CAUTION` | recoverable, but costs bandwidth, a re-login, or local state | Docker's VM image |
| `KEEP` | your data. Reported for size only, shrink it through the app | Photos library, Mail |

## Why the arithmetic is trustworthy

Two mistakes make this kind of tool lie, and both are handled explicitly:

- **Double counting.** A finding only charges itself the bytes its children did
  not already claim (`Finding.own_share`). Docker's container folder and the VM
  image inside it do not both bill 13G.
- **Globs crossing directory boundaries.** `fnmatch`'s `*` matches `/` too,
  which makes `Chrome/Profile *` swallow every file nested under a profile.
  Matching is per path component; `**` is the explicit opt-in for any depth.

Known limits, also printed at the bottom of every report:

- APFS **clones** share blocks but are counted in full under each name, so a sum
  can exceed real usage and deleting one copy frees less than stated.
- Paths your terminal cannot read are listed as *not measured*; totals are lower
  bounds until you grant Full Disk Access.
- A cache refills. Capping it in the app beats deleting it repeatedly.

## Adding a rule

```python
Rule("Library/Application Support/YourApp/Cache",  # home-relative, or absolute
     SAFE,                                         # SAFE | CAUTION | KEEP
     "What this directory actually is",
     'mv "{path}" ~/.Trash/',                      # command, or plain advice
     "YourApp",                                    # quit this first
     ("electron",),
     descend=False)                                # walk inside the match?
```

More anchored components win over fewer, so a specific rule always beats a
wildcard one. `descend=True` on a `SAFE` rule turns it into a container: it gets
itemised per app instead of reported as one opaque lump (that is how
`~/Library/Caches` is handled). `descend=False` on a `KEEP` rule keeps the walker
out of things that must stay intact, like `.app` bundles.

## Files

- `disku.py` — scanner, classifier, report
- `rules.py` — the knowledge base
- `disku` — shim so it runs from anywhere
