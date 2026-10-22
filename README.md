# iOS Sandbox Explorer

### Overview and Workflow

The **iOS Sandbox Explorer** lets you create a custom DYLIB, inject it into any iOS app, and interact with the app's sandbox through a simple USB tunnel. 

Once created, the resulting IPA can be signed using an external signer and installed onto your device. 

After installing the app onto your device, you will have access to an interactive shell within the app's sandbox over a USB connection.

> [!TIP]
> There are many ways to sign your IPA for free without requiring a Mac or being jailbroken; some examples include:
> [Feather](https://github.com/claration/feather),  [ipasigner.com](https://www.ipasigner.com/), [Sideloadly](https://sideloadly.io/), [Zsign](https://github.com/zhlynn/zsign)

> [!WARNING]
> _This project does not provide support for Apple ID/GSA/anisette signing so you must use your own preferred method of signing._

## Workflow

The general workflow is as follows:

1. Create libShell.dylib - A TCP server written in Objective-C that includes many built-in commands that are safe to run within the sandbox (i.e., no popen/no exec).

2. Inject the DYLIB into any IPA, add network entitlements, update Info.plist, and produce a patched IPA ready to be signed.

3. Sign the patched IPA using an external tool of your choice.

4. Install the patched IPA onto your device (e.g., using ideviceinstaller or through your signer's installation process).

5. Connect to the device via USB tunnel and execute the DYLIB's built-in commands — no popen(), no exec() (safe from iOS entitlement restrictions).

dump the keychain, or download files directly from the app's sandbox.

## Repository layout

```
ise                   — short launcher for F# host tools (./ise …)
src/                  — libShell Objective-C sources
include/              — public headers
Makefile              — builds libShell.dylib (macOS + Xcode iphoneos SDK)
tools-fs/ise/         — F# host tooling project (client, patch, devices, install, tunnel, full)
.github/workflows/
  build-dylib.yml     — macOS CI: build dylib on xcode-27 (iOS 27 SDK); Releases on v*.*.* tags
  build-fs-tools.yml  — Linux CI: restore/build F# tools + self-tests
```

## Prerequisites

### Build `libShell.dylib` (macOS)

- Xcode with an **iphoneos** SDK (CI uses the **iOS 27** SDK on the `xcode-27` runner)
- Deployment target stays **iOS 14.0** (`IPHONEOS_DEPLOYMENT_TARGET`)

```bash
xcode-select --install   # if needed
make                     # → libShell.dylib
```

Optional hard gate (matches CI):

```bash
REQUIRE_IOS_SDK_MAJOR=1 IPHONEOS_SDK_MIN_MAJOR=27 make
```

### Host tooling (any OS with .NET 8)

```bash
# .NET 8 SDK: https://dotnet.microsoft.com/download
dotnet build tools-fs/ise.sln -c Release
chmod +x ./ise   # once, if needed
```

### Device USB (install / tunnel / list)

- A paired, trusted device
- **usbmuxd** (Linux/macOS) or Apple Mobile Device Support (Windows)
- F# device commands use [Netimobiledevice](https://github.com/artehe/Netimobiledevice)

## Building / obtaining `libShell.dylib`

`libShell.dylib` is **not** committed to git.

| Source | Notes |
|--------|--------|
| `make` on macOS | Builds with current iphoneos SDK; min OS **14.0** |
| [GitHub Releases](https://github.com/gemsloot-iOS/iOS-sandbox-explorer/releases) | Published only when a semver tag `v*.*.*` is pushed to a commit **on `main`** |
| [Actions](https://github.com/gemsloot-iOS/iOS-sandbox-explorer/actions) artifact `libShell-dylib` | From workflow **Build libShell.dylib** (every push/PR; not a Release) |

CI artifacts (`build-dylib.yml`):

- Runner: **`xcode-27`** (real iOS **27** SDK; fails if SDK major &lt; 27)
- Mach-O check: `minos 14.0` and `sdk 27.x`
- Releases: tag push `v*.*.*` only — CI never creates tags

## F# host tools

Day-to-day commands use the root launcher **`./ise`** (wraps `tools-fs/ise`).

```bash
# Shell client (TCP to libShell on device via tunnel)
./ise "ls"
./ise client "pwd" --host localhost --port 8080
./ise "scp -r Documents host:./downloads"

# Patch IPA (unsigned output)
./ise patch --ipa MyApp.ipa --dylib libShell.dylib
# → MyApp_patched.ipa

# Device helpers (Netimobiledevice)
./ise devices
./ise install --ipa MyApp_signed.ipa [--udid UDID]
./ise tunnel [--local-port 8080] [--remote-port 8080] [--udid UDID]

# Patch then optionally install (still unsigned unless you signed first)
./ise full --ipa MyApp.ipa --dylib libShell.dylib [--install] [--udid UDID]

# Offline self-tests (also run in CI)
./ise --self-test
./ise --self-test-patcher
./ise --self-test-devices
```

Optional (advanced): `dotnet run --project tools-fs/ise -- …` does the same without `./ise`.

`--use-lief` is accepted on `patch` / `full` for old-CLI compatibility; F# inject already reclaims `LC_CODE_SIGNATURE` space when needed (no Python `lief`).

## Sign externally, then install

```bash
# After patch — sign with feather / ipasigner / Sideloadly / zsign / etc.
# Then:
./ise install --ipa MyApp_signed.ipa
```

## Connect and use

1. Launch the patched app on the device (dylib starts a TCP server on **port 8080**, loopback on device).
2. Start a USB tunnel:

```bash
./ise tunnel --local-port 8080 --remote-port 8080
# foreground; Ctrl+C to stop
```

3. Run commands from the host (examples above).

## Available commands (dylib)

Implemented in-process via `Foundation/POSIX`

> [!TIP]
> Full list: run `help` on the device shell.

Highlights:

| Command | Description |
|---------|-------------|
| `ls [path]` | List directory |
| `pwd` | Current directory |
| `cd <path>` | Change directory |
| `id` | User and group IDs |
| `whoami` | Current username |
| `uname` | System information |
| `echo <text>` | Print text |
| `cat <file>` | Print file contents |
| `cp <src> <dst>` | Copy file/directory |
| `mv <src> <dst>` | Move file/directory |
| `rm <path>` | Remove file/directory |
| `mkdir <path>` | Create directory |
| `stat <path>` | File metadata |
| `find <path>` | Find files |
| `env` | Environment variables |
| `scp -r <src> host:<dst>` | Download to host (base64) |
| `keychain dump` | Dump all keychain items accessible to the app |
| `keychain dump --filter <str>` | Dump keychain items matching a string in any field |
| `keychain dump --filter self` | Dump keychain items matching the app's own bundle ID |
| `keychain dump --class <type>` | Filter by item class: `generic`, `internet`, `cert`, `key` |

> [!NOTE]
> Keychain access is limited to what this app’s entitlements allow.

## Troubleshooting

### `Connection refused` on port 8080

- Patched app must be running
- Tunnel must be up (`tunnel` or equivalent)
- Relaunch the app after install

### Install / device list fails

- Device unlocked, trusted, and paired
- usbmuxd / Apple Mobile Device Support running
- IPA must be **signed** for the target device before `install` succeeds

### App rejected (`ApplicationVerificationFailed`)

- Re-sign with a valid external cert / profile matching the device UDID

### `make` / iphoneos SDK errors

- Need macOS + Xcode with an iphoneos SDK
- CI requires SDK major ≥ 27; locally, older SDKs may still build but will warn

## Security notes

- For testing and research only
- Injected code runs inside the host app’s sandbox
- Shell TCP is bound to loopback on device; reach it over USB tunnel, not the LAN
