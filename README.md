# iOS Sandbox Explorer

Inject a custom DYLIB into any iOS app, sign it with a **free Apple ID** (no paid developer account), install it, and get interactive shell access to the app's sandbox over USB — on any device, jailbroken or not.

Built-in signing works the same way as **Sideloadly**: authenticates directly with Apple using SRP, obtains a free development certificate and provisioning profile, and signs your IPA — entirely from the command line. No Docker, no Xcode GUI.

## How It Works

1. **Build** `libShell.dylib` — an Objective-C TCP server with built-in sandbox-safe commands (no `popen`, no `exec`)
2. **Patch** any IPA — inject the DYLIB, add network entitlements, update `Info.plist`
3. **Sign** with a free Apple ID — no paid account, no Xcode GUI, works cross-platform
4. **Install** directly to device via `ideviceinstaller`
5. **Connect** via USB tunnel → run commands, dump keychain, download files from the app's sandbox

## Architecture

```
src/
  main.m              — DYLIB entry point, starts TCP server
  ShellServer.m       — TCP server (port 8080)
  ShellCommands.m     — Built-in commands (sandbox-safe, no popen)
include/
  ShellServer.h
  ShellCommands.h
tools/
  patcher.py          — Cross-platform IPA patcher (Windows / Linux / macOS)
  apple_account.py    — Apple ID auth & signing (like Sideloadly, no paid account)
  anisette_helper.m   — Native anisette provider for macOS (compiled on demand)
ios-patch/
  patch_ipa.sh        — Legacy macOS patching script
client.py             — Python client for remote command execution
Makefile              — Builds libShell.dylib (+ anisette_helper on macOS)
```

## Prerequisites

### Required

- Python 3.8+
- `pip install -r tools/requirements.txt`

### For USB install / tunneling

```bash
brew install libimobiledevice ideviceinstaller   # macOS
apt install libimobiledevice-utils ideviceinstaller  # Debian/Ubuntu
```

### For building the DYLIB (macOS only)

- Xcode Command Line Tools: `xcode-select --install`

## Anisette Data (Apple Authentication)

Apple requires "anisette" device-attestation headers for signing. This tool handles it **automatically** with no Docker required:

| Platform | Provider | Setup |
|---|---|---|
| macOS | `NativeAnisetteProvider` via `AOSKit.framework` | Zero setup — uses system framework |
| Linux (x86_64 / arm64 / armv7 / i686) | `LinuxAnisetteProvider` via `anisette-server` | Auto-downloads on first run (~87 MB, one-time) |
| Windows | HTTP fallback (`--anisette-url`) | Requires external anisette server |

**macOS:** Calls `AOSUtilities.retrieveOTPHeadersForDSID:` directly — no Docker, no entitlement tricks.

**Linux:** On first run, automatically downloads the [anisette-server](https://github.com/Dadoum/Provision) binary and extracts the required Apple libraries from the Apple Music APK. Everything is stored in `~/.config/cc-ios/anisette/`. Subsequent runs reuse the cached data.

**Windows (manual):** Run an external omnisette server and pass `--anisette-url http://localhost:6969`.

## Building the DYLIB

```bash
make
```

Creates `libShell.dylib` in the project root. On macOS, also builds `tools/anisette_helper` (the native anisette binary, compiled automatically on demand). You only need macOS for this step — use the pre-built binary from Releases on other platforms.

## Patching an IPA

```bash
python3 tools/patcher.py patch --ipa MyApp.ipa --dylib libShell.dylib
# → MyApp_patched.ipa
```

Works on Windows, Linux, and macOS. No Xcode or `insert_dylib` required.

## Signing with Apple ID

### One command: patch + sign + install

```bash
python3 tools/patcher.py full \
  --ipa MyApp.ipa \
  --dylib libShell.dylib \
  --install \
  --udid <device-udid>
```

### Sign only (already patched IPA)

```bash
python3 tools/apple_account.py sign \
  --ipa MyApp_patched.ipa \
  -o MyApp_signed.ipa \
  --udid <device-udid> \
  --install
```

You will be prompted for your Apple ID email and password. The password is **never saved to disk** — authentication uses Apple's SRP protocol.

**Free account limitations:**
- Apps expire in 7 days (re-sign weekly)
- Max 3 App IDs per week
- Max 10 sideloaded apps

**Note:** If the app's bundle ID is taken by another developer, the tool automatically renames it to `<TEAM_ID>.<bundle.id>` and patches `Info.plist` accordingly.

## Installing on Device

```bash
# Standalone install (after signing)
ideviceinstaller -u <device-udid> install MyApp_signed.ipa

# Or use --install flag during signing (see above)
```

## Connecting and Using

### 1. Launch the patched app on your device

### 2. Set up USB tunnel

```bash
iproxy 8080 8080
```

### 3. Run commands

```bash
python3 client.py "ls"
python3 client.py "pwd"
python3 client.py "id"
python3 client.py "uname"

# Download files / directories from sandbox to host
python3 client.py "scp -r Documents host:./downloads"
python3 client.py "scp -r Library host:./library"
```

## Available Commands

The DYLIB implements built-in commands — **no `popen()`, no `exec()`** (safe from iOS entitlement restrictions):

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

## Troubleshooting

### `Connection refused` on port 8080
- Verify the patched app is running on device
- Check `iproxy 8080 8080` is running
- Try relaunching the app

### Signing fails on Linux (first run is slow)
- The first run downloads `anisette-server` and extracts libs from the Apple Music APK (~87 MB total)
- This is a one-time setup stored in `~/.config/cc-ios/anisette/`
- To reset: `python3 -c "from tools.apple_account import LinuxAnisetteProvider; LinuxAnisetteProvider.reset()"`

### App rejected on install (`ApplicationVerificationFailed`)
- Certificate expired — re-run the sign command to get a fresh cert
- Make sure `--udid` matches the connected device

### `ideviceinstaller not found`
- macOS: `brew install ideviceinstaller`
- Linux: `apt install ideviceinstaller`
- Windows: [libimobiledevice-win32](https://github.com/libimobiledevice-win32/imobiledevice-net)

### `anisette_helper` build fails (macOS)
- Ensure Xcode Command Line Tools are installed: `xcode-select --install`
- The binary compiles automatically on first sign; or build manually: `make anisette_helper`

### Finding Signing Identity (legacy `patch_ipa.sh`)

Only needed if using the old `ios-patch/patch_ipa.sh` script directly:

```bash
security find-identity -p codesigning -v
# Look for "Apple Development: ..." identities
```

## Security Notes

- For testing and research purposes only
- Injected code runs entirely within the app's sandbox
- Network traffic is tunnelled over USB (never exposed to the network)
- Apple ID password is never written to disk; authentication uses SRP
