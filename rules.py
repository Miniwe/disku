"""Knowledge base: which paths on macOS are junk, which are precious.

Every rule says three things: how safe removal is, what the thing actually is,
and the *native* way to reclaim it (an app's own cleanup command always beats
`rm -rf`). The scanner never deletes anything -- these are report annotations.
"""

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
    quit_app: str = ""    # app that must be closed first
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
        profile or sandbox is reported *and* walked, because the disposable
        parts are buried inside the parts you must keep.
        """
        if self.descend is not None:
            return self.descend
        return self.safety != SAFE


TRASH_HINT = 'mv "{path}" ~/.Trash/'

RULES = [
    # ---------------------------------------------------------------- browsers
    Rule("Library/Application Support/Google/Chrome/*/Service Worker/CacheStorage",
         SAFE, "Chrome service-worker cache (per profile)", TRASH_HINT, "Google Chrome",
         ("browser",)),
    Rule("Library/Application Support/Google/Chrome/*/Service Worker/ScriptCache",
         SAFE, "Chrome service-worker script cache", TRASH_HINT, "Google Chrome",
         ("browser",)),
    Rule("Library/Application Support/Google/Chrome/*/Code Cache",
         SAFE, "Chrome compiled-JS cache", TRASH_HINT, "Google Chrome", ("browser",)),
    Rule("Library/Application Support/Google/Chrome/*/GPUCache",
         SAFE, "Chrome GPU shader cache", TRASH_HINT, "Google Chrome", ("browser",)),
    Rule("Library/Application Support/Google/Chrome/*/File System",
         CAUTION, "Chrome per-site File System API storage", TRASH_HINT, "Google Chrome",
         ("browser",)),
    Rule("Library/Application Support/Google/Chrome/*/IndexedDB",
         CAUTION, "Chrome IndexedDB (offline web-app data: drafts, queued messages)",
         "Clear per-site via chrome://settings/content/all instead of deleting wholesale",
         "Google Chrome", ("browser",)),
    Rule("Library/Application Support/Google/Chrome/*/Local Storage",
         CAUTION, "Chrome localStorage (logins, per-site settings)",
         "Deleting logs you out of many sites", "Google Chrome", ("browser",)),
    Rule("Library/Application Support/Google/Chrome/*/Extensions",
         KEEP, "Chrome extensions -- rule lists and offline data grow here",
         "Audit chrome://extensions and remove what you no longer use",
         "Google Chrome", ("browser",), descend=False),
    Rule("Library/Application Support/Google/Chrome/*/History",
         KEEP, "Chrome history database", "", "", ("browser",)),
    Rule("Library/Application Support/Google/Chrome/Default",
         CAUTION, "Chrome default profile (bookmarks, passwords, cookies + caches)",
         "Do not delete the profile. Use chrome://settings/clearBrowserData "
         "(Cached images and files, All time) -- it walks the caches for you",
         "Google Chrome", ("browser", "profile")),
    Rule("Library/Application Support/Google/Chrome/Profile *",
         CAUTION, "Chrome secondary profile",
         "If unused: chrome://settings/manageProfile -> Delete. Otherwise clear its cache only",
         "Google Chrome", ("browser", "profile")),
    Rule("Library/Application Support/Google/Chrome/Snapshots",
         SAFE, "Chrome rollback snapshots of previous versions",
         TRASH_HINT, "Google Chrome", ("browser", "updater")),
    Rule("Library/Caches/Google/Chrome",
         SAFE, "Chrome HTTP disk cache", TRASH_HINT, "Google Chrome", ("browser",)),
    Rule("Library/Caches/Google",
         SAFE, "Google apps cache (Chrome, updater, Drive)", TRASH_HINT, "", ("browser",)),
    Rule("Library/Caches/com.google.SoftwareUpdate",
         SAFE, "Downloaded Google updater packages", TRASH_HINT, "", ("updater",)),
    Rule("Library/Application Support/Comet", CAUTION,
         "Comet browser profile (Perplexity) -- caches + logins mixed",
         "Clear browsing data from inside Comet", "Comet", ("browser",)),
    Rule("Library/Caches/Comet", SAFE, "Comet browser disk cache", TRASH_HINT, "Comet",
         ("browser",)),
    Rule("Library/Application Support/Yandex", CAUTION,
         "Yandex Browser profile", "Clear browsing data inside the browser, or "
         "uninstall it if unused", "Yandex", ("browser",)),
    Rule("Library/Application Support/Firefox/Profiles/*/cache2",
         SAFE, "Firefox disk cache", TRASH_HINT, "Firefox", ("browser",)),
    Rule("Library/Caches/Firefox", SAFE, "Firefox cache", TRASH_HINT, "Firefox", ("browser",)),

    # ------------------------------------------------------------- containers
    Rule("Library/Containers/com.docker.docker/Data/vms", CAUTION,
         "Docker Desktop VM disk image (images, containers, volumes, build cache)",
         "docker system prune -a --volumes   # then Docker Desktop -> Troubleshoot -> "
         "Clean/Purge data if the file still does not shrink",
         "Docker Desktop", ("dev", "vm")),
    Rule("Library/Containers/com.docker.docker", CAUTION,
         "Docker Desktop container directory",
         "Reclaim from inside Docker: docker system df, then docker system prune -a",
         "Docker Desktop", ("dev", "vm")),
    Rule("Library/Containers/*/Data/Library/Caches", SAFE,
         "Sandboxed app cache", TRASH_HINT, "", ("container",)),
    Rule("Library/Containers/*/Data/Library/Logs", SAFE,
         "Sandboxed app logs", TRASH_HINT, "", ("container",)),
    Rule("Library/Containers/com.apple.mail", KEEP,
         "Apple Mail sandbox (attachments, local mailboxes)",
         "Mail -> Settings -> Accounts -> remove attachments, or reduce sync window",
         "", ("mail",)),
    Rule("Library/Group Containers/*/Library/Caches", SAFE,
         "Shared app-group cache", TRASH_HINT, "", ("container",)),
    Rule("Library/Group Containers/group.com.apple.mail", KEEP,
         "Apple Mail shared data", "", "", ("mail",)),

    # ------------------------------------------------------------ electron apps
    Rule("Library/Application Support/Code/Cache", SAFE, "VS Code HTTP cache",
         TRASH_HINT, "VS Code", ("dev", "electron")),
    Rule("Library/Application Support/Code/CachedData", SAFE,
         "VS Code compiled-JS cache for old versions", TRASH_HINT, "VS Code",
         ("dev", "electron")),
    Rule("Library/Application Support/Code/CachedExtensionVSIXs", SAFE,
         "VS Code downloaded extension packages", TRASH_HINT, "VS Code", ("dev",)),
    Rule("Library/Application Support/Code/Code Cache", SAFE, "VS Code code cache",
         TRASH_HINT, "VS Code", ("dev", "electron")),
    Rule("Library/Application Support/Code/User/workspaceStorage", CAUTION,
         "VS Code per-workspace state (undo history, extension state)",
         "Safe to prune entries for projects you deleted", "VS Code", ("dev",)),
    Rule("Library/Application Support/Code/User/History", CAUTION,
         "VS Code local file history (your own edit backups)",
         "Keep unless you never use Timeline/Local History", "VS Code", ("dev",)),
    Rule("Library/Application Support/Code/logs", SAFE, "VS Code logs", TRASH_HINT,
         "VS Code", ("dev",)),
    Rule("Library/Application Support/Slack/Service Worker/CacheStorage", SAFE,
         "Slack service-worker cache", TRASH_HINT, "Slack", ("electron",)),
    Rule("Library/Application Support/Slack/Cache", SAFE, "Slack HTTP cache",
         TRASH_HINT, "Slack", ("electron",)),
    Rule("Library/Application Support/Slack/logs", SAFE, "Slack logs", TRASH_HINT,
         "Slack", ("electron",)),
    Rule("Library/Application Support/Spotify/PersistentCache", SAFE,
         "Spotify offline audio cache",
         "Spotify -> Settings -> Storage, lower the cache limit", "Spotify", ("media",)),
    Rule("Library/Application Support/**/Service Worker/CacheStorage", SAFE,
         "Electron app service-worker cache", TRASH_HINT, "", ("electron",)),
    Rule("Library/Application Support/**/Cache", SAFE, "Electron app HTTP cache",
         TRASH_HINT, "", ("electron",)),
    Rule("Library/Application Support/**/GPUCache", SAFE, "Electron GPU shader cache",
         TRASH_HINT, "", ("electron",)),
    Rule("Library/Application Support/**/Code Cache", SAFE, "Electron compiled-JS cache",
         TRASH_HINT, "", ("electron",)),
    Rule("Library/Application Support/**/CachedData", SAFE, "Electron cached bundles",
         TRASH_HINT, "", ("electron",)),
    Rule("Library/Application Support/**/logs", SAFE, "App logs", TRASH_HINT, "", ("logs",)),
    Rule("Library/Caches/*ShipIt*", SAFE,
         "Squirrel/ShipIt leftover: downloaded app updates already installed",
         TRASH_HINT, "", ("updater",)),
    Rule("Library/Caches/*-updater", SAFE, "Electron auto-updater downloads",
         TRASH_HINT, "", ("updater",)),
    Rule("Library/Caches/*.ShipIt", SAFE, "Squirrel update staging directory",
         TRASH_HINT, "", ("updater",)),

    # -------------------------------------------------------------- dev caches
    Rule("Library/Caches/Homebrew", SAFE, "Homebrew downloaded bottles and sources",
         "brew cleanup --prune=all", "", ("dev", "pkg")),
    Rule("Library/Caches/Yarn", SAFE, "Yarn package cache", "yarn cache clean", "",
         ("dev", "pkg")),
    Rule("Library/Caches/pip", SAFE, "pip wheel cache", "pip cache purge", "",
         ("dev", "pkg")),
    Rule("Library/Caches/node-gyp", SAFE, "node-gyp downloaded Node headers",
         TRASH_HINT, "", ("dev",)),
    Rule("Library/Caches/ms-playwright*", SAFE,
         "Playwright browser binaries",
         "npx playwright uninstall --all   # re-downloaded on demand", "", ("dev",)),
    Rule("Library/Caches/go-build", SAFE, "Go build cache", "go clean -cache", "",
         ("dev",)),
    Rule("Library/Caches/deno", SAFE, "Deno module cache", TRASH_HINT, "", ("dev",)),
    Rule("Library/Caches/JetBrains", SAFE, "JetBrains IDE caches and indexes",
         TRASH_HINT, "JetBrains IDEs", ("dev",)),
    Rule("Library/Caches/CocoaPods", SAFE, "CocoaPods spec/pod cache",
         "pod cache clean --all", "", ("dev", "pkg")),
    Rule(".npm/_cacache", SAFE, "npm package cache", "npm cache clean --force", "",
         ("dev", "pkg")),
    Rule(".cache/yarn", SAFE, "Yarn Berry cache", "yarn cache clean", "", ("dev", "pkg")),
    Rule(".gradle/caches", SAFE, "Gradle dependency and build cache",
         TRASH_HINT + "   # re-downloaded on next build", "", ("dev", "pkg")),
    Rule(".m2/repository", CAUTION, "Maven local repository",
         "Re-downloaded on next build; delete only whole version folders you do not need",
         "", ("dev", "pkg")),
    Rule(".cargo/registry", SAFE, "Cargo crate sources and archives",
         "cargo cache -a   # or " + TRASH_HINT, "", ("dev", "pkg")),
    Rule(".rustup/toolchains", CAUTION, "Rust toolchains",
         "rustup toolchain list   # then: rustup toolchain uninstall <name>", "",
         ("dev",)),
    Rule("go/pkg/mod", SAFE, "Go module cache", "go clean -modcache", "", ("dev", "pkg")),
    Rule(".pyenv/versions", CAUTION, "pyenv Python builds",
         "pyenv versions   # then: pyenv uninstall <version>", "", ("dev",)),
    Rule(".nvm/versions", CAUTION, "Node versions installed by nvm",
         "nvm ls   # then: nvm uninstall <version>", "", ("dev",)),
    Rule(".docker/buildx", SAFE, "Docker buildx state", "docker buildx prune -a", "",
         ("dev",)),
    Rule("Library/pnpm/store", SAFE, "pnpm content-addressed store",
         "pnpm store prune", "", ("dev", "pkg")),
    Rule("Library/Android/sdk/system-images", CAUTION, "Android emulator system images",
         "Remove unused images in Android Studio -> SDK Manager", "", ("dev",)),
    Rule("Library/Android/sdk", CAUTION, "Android SDK",
         "Prune old platforms/build-tools in SDK Manager", "", ("dev",)),
    Rule("Library/Developer/Xcode/DerivedData", SAFE,
         "Xcode build products and indexes (rebuilt on demand)", TRASH_HINT, "Xcode",
         ("dev", "xcode")),
    Rule("Library/Developer/Xcode/iOS DeviceSupport", SAFE,
         "Xcode debug symbols per iOS version (re-created when a device reconnects)",
         TRASH_HINT, "Xcode", ("dev", "xcode")),
    Rule("Library/Developer/Xcode/watchOS DeviceSupport", SAFE,
         "Xcode watchOS debug symbols", TRASH_HINT, "Xcode", ("dev", "xcode")),
    Rule("Library/Developer/Xcode/Archives", CAUTION,
         "Xcode archives of shipped builds (needed to re-symbolicate crash logs)",
         "Keep archives of released versions, delete the rest", "Xcode", ("dev", "xcode")),
    Rule("Library/Developer/CoreSimulator/Caches", SAFE, "Simulator runtime cache",
         TRASH_HINT, "Simulator", ("dev", "xcode")),
    Rule("Library/Developer/CoreSimulator/Devices", CAUTION,
         "Simulator devices with their installed apps and data",
         "xcrun simctl delete unavailable   # then: xcrun simctl delete <udid>",
         "Simulator", ("dev", "xcode")),
    Rule("Library/Developer/CoreSimulator", CAUTION, "iOS Simulator data",
         "xcrun simctl delete unavailable", "Simulator", ("dev", "xcode")),
    Rule("Library/Developer/Xcode/UserData", KEEP,
         "Xcode key bindings, snippets, breakpoints", "", "", ("dev",)),

    # ------------------------------------------------------------ generic junk
    Rule("Library/Caches", SAFE,
         "The rest of the user cache root, no single app dominating it",
         "Clear per-app subfolders with the app closed, not the whole folder at once",
         "", ("cache",), descend=True),
    Rule("Library/Logs", SAFE, "User logs", TRASH_HINT, "", ("logs",)),
    Rule("Library/Application Support/CrashReporter", SAFE, "Crash report archive",
         TRASH_HINT, "", ("logs",)),
    Rule("Library/Saved Application State", SAFE,
         "Reopen-windows state per app", TRASH_HINT, "", ("cache",), descend=False),
    Rule(".Trash", SAFE, "Your Trash -- still occupying disk until emptied",
         "Finder -> Empty Trash (check the contents first)", "", ("trash",), descend=False),
    Rule("/Library/Caches", SAFE, "System-wide app cache (needs sudo)",
         'sudo mv "{path}"/<subfolder> ~/.Trash/', "", ("cache",), descend=True),
    Rule("/Library/Logs", SAFE, "System-wide logs (needs sudo)", "", "", ("logs",)),
    Rule("/private/var/log", SAFE, "System logs, rotated automatically",
         "Leave it; macOS rotates these", "", ("logs",)),

    # -------------------------------------------------- found on this machine
    Rule(".docker/scout", SAFE,
         "Docker Scout vulnerability and SBOM cache", TRASH_HINT, "", ("dev",)),
    Rule(".npm/_npx", SAFE,
         "npx one-off package installs, kept forever by npm", TRASH_HINT, "",
         ("dev", "pkg")),
    Rule("Library/Caches/com.oracle.java.JavaAppletPlugin", SAFE,
         "Java applet plugin cache", TRASH_HINT, "", ("cache",)),
    Rule("Library/Group Containers/*.ru.keepcoder.Telegram", CAUTION,
         "Telegram media cache plus its local message database",
         "Telegram -> Settings -> Data and Storage -> Storage Usage -> Clear Cache",
         "Telegram", ("messenger",), descend=False),
    Rule("Library/Containers/ru.keepcoder.Telegram", CAUTION,
         "Telegram sandbox data",
         "Clear from Telegram: Settings -> Data and Storage", "Telegram",
         ("messenger",)),
    Rule("Library/Application Support/MstyStudio", CAUTION,
         "Msty Studio data (local models, chats, Electron caches)",
         "Check its in-app storage settings before deleting anything", "Msty Studio",
         ("ai",)),
    Rule("Library/Application Support/Microsoft/Teams", CAUTION,
         "Teams profile and caches",
         "Quit Teams, then clear its Cache/ and Service Worker/ subfolders",
         "Microsoft Teams", ("electron",)),
    Rule("Library/Python", CAUTION, "pip --user installed packages",
         "pip list --user   # then: pip uninstall <package>", "", ("dev",)),
    Rule("/Applications/Xcode.app", CAUTION,
         "Xcode -- the largest single app on this disk",
         "Worth keeping only if you build Apple-platform apps; "
         "re-downloadable from developer.apple.com", "Xcode", ("dev", "apps"),
         descend=False),
    Rule("/Library/Application Support/Adobe", KEEP,
         "Adobe app support (Camera Raw, Creative Cloud)",
         "Remove through the Creative Cloud uninstaller, never by hand", "",
         ("apps",), descend=False),
    Rule("/Library/Application Support/Blackmagic Design", KEEP,
         "DaVinci Resolve support files",
         "Uninstall Resolve if you do not use it; do not prune by hand", "",
         ("apps",), descend=False),
    Rule("/Library/Application Support/Citrix Receiver", KEEP,
         "Citrix Workspace support files",
         "Uninstall Citrix Workspace if unused", "", ("apps",), descend=False),

    # ---------------------------------------------------------------- user data
    Rule("Library/Application Support/MobileSync/Backup", CAUTION,
         "iPhone/iPad local backups -- often several stale copies",
         "Finder -> device -> Manage Backups, delete old ones. "
         "Check dates before touching anything", "", ("backup",), descend=False),
    Rule("Library/Application Support/minecraft", KEEP, "Minecraft worlds and mods",
         "", "", ("games",)),
    Rule("Library/Application Support/Steam/steamapps", CAUTION,
         "Installed Steam games (re-downloadable)",
         "Uninstall from the Steam library UI", "Steam", ("games",)),
    Rule("Library/Application Support/AddressBook", KEEP, "Contacts database", "", "",
         ("data",)),
    Rule("Library/Application Support/Calendars", KEEP, "Calendar database", "", "",
         ("data",)),
    Rule("Library/Application Support/Knowledge", KEEP, "System usage database", "", "",
         ("data",)),
    Rule("Library/Application Support/com.apple.sharedfilelist", KEEP,
         "Recent items lists", "", "", ("data",)),
    Rule("Library/Application Support/obsidian", CAUTION,
         "Obsidian app data (workspace state + plugin cache; vaults live elsewhere)",
         "Safe to clear its Cache/ subfolders only", "Obsidian", ("notes",)),
    Rule("Library/Messages", KEEP, "iMessage history and attachments",
         "Messages -> Settings -> Keep messages: 1 year, if you want it smaller", "",
         ("data",), descend=False),
    Rule("Library/Mail", KEEP, "Apple Mail local store",
         "Reduce per-account sync window instead of deleting", "", ("mail",), descend=False),
    Rule("Library/Keychains", KEEP, "Keychain -- passwords and certificates", "", "",
         ("security",), descend=False),
    Rule("Library/Mobile Documents", KEEP, "iCloud Drive local copies",
         "Use Finder -> Remove Download to evict without losing the file", "",
         ("icloud",), descend=False),
    Rule("Library/Photos", KEEP, "Photos support data", "", "", ("media",)),
    Rule("Pictures/*.photoslibrary", KEEP, "Photos library",
         "Photos -> Settings -> iCloud -> Optimize Mac Storage", "", ("media",), descend=False),
    Rule("Music/Music", KEEP, "Music library", "", "", ("media",)),
    Rule("Downloads", CAUTION, "Downloads -- usually the cheapest real win",
         "Sort by size in Finder and review; almost all of it is re-downloadable", "",
         ("review",)),
    Rule("Documents", KEEP, "Documents", "", "", ("data",), descend=False),
    Rule("Desktop", KEEP, "Desktop", "", "", ("data",), descend=False),

    # --------------------------------------------------------------- system-ish
    Rule("/private/var/vm", KEEP, "Swap and sleep image, managed by the kernel",
         "Never delete manually", "", ("system",)),
    Rule("/private/var/folders", SAFE,
         "Per-user temporary and cache directories, cleaned on reboot",
         "Reboot instead of deleting by hand", "", ("system",)),
    Rule("/Library/Developer/CommandLineTools", KEEP, "Command Line Tools", "", "",
         ("dev",)),
    Rule("/Applications", KEEP, "Installed applications",
         "Uninstall what you do not use -- see the app list below", "",
         ("apps", "root"), descend=True),
    Rule("/Applications/*.app", KEEP, "Application bundle",
         "Uninstall from Finder or the vendor's uninstaller. Never delete files "
         "inside a bundle -- it breaks the code signature", "", ("apps", "bundle"),
         descend=False),
]

# Basename heuristics: catch caches in apps nobody wrote a rule for.
CACHE_BASENAMES = {
    "cache": "cache directory",
    "caches": "cache directory",
    "cachedata": "cached compiled bundles",
    "cache_data": "cache directory",
    "cachestorage": "service-worker cache",
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
}

_BY_SPECIFICITY = sorted(RULES, key=lambda r: r.specificity, reverse=True)


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

    `rel_path` is home-relative, or absolute for paths outside $HOME.
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
                    TRASH_HINT, "", ("heuristic", "cache"))
    return None
