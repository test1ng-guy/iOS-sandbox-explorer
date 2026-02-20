# iOS DYLIB Injection Tool for Non-Jailbreak Devices

This project provides a complete solution for injecting a custom dynamic library (DYLIB) into iOS apps on non-jailbreak devices. The injected DYLIB runs a TCP server on port 8080, allowing remote shell-like commands and file downloads via USB tunneling.

## Features

- TCP server on port 8080 for remote command execution
- Shell-like commands: ls, pwd, id, uname, whoami, echo, cp
- Recursive file/directory download with automatic base64 encoding/decoding
- Works within app sandbox on non-jailbreak iOS devices
- USB tunneling via iproxy for secure connection

## Prerequisites

- macOS with Xcode Command Line Tools: `xcode-select --install`
- Python 3: `brew install python`
- Apple Developer Account with valid signing identity
- iOS device connected via USB
- iproxy for USB tunneling: `brew install libimobiledevice`

### Building insert_dylib

The patching script requires `insert_dylib` tool:

```bash
git clone https://github.com/Tyilo/insert_dylib.git insert_dylib_repo
cd insert_dylib_repo
xcodebuild -project insert_dylib.xcodeproj -configuration Release
```

The built binary will be at `insert_dylib_repo/build/Release/insert_dylib`.

## Building the DYLIB

```bash
make
```

This creates `libShell.dylib` in the project root.

## Patching an IPA

Use the provided script to inject the DYLIB into your IPA:

```bash
./ios-patch/patch_ipa.sh <ipa_path> <dylib_path> <insert_dylib_path> <signing_identity> [output_ipa]
```

### Finding Signing Identity

List available identities:

```bash
security find-identity -p codesigning -v
```

Look for "Apple Development" identities.

### Example

```bash
./ios-patch/patch_ipa.sh MyApp.ipa libShell.dylib insert_dylib_repo/build/Release/insert_dylib "Apple Development: Your Name (ABC123)" patched_MyApp.ipa
```

The script will:
- Unzip the IPA
- Copy `libShell.dylib` to `Payload/App.app/Frameworks/`
- Inject LC_LOAD_DYLIB into the app binary
- Update Info.plist for network permissions
- Create entitlements for network access
- Sign the DYLIB and resign the binary
- Repackage the IPA

## Installing on Device

Install the patched IPA using Sideloadly (recommended) or ios-deploy:

```bash
# Using Sideloadly (GUI tool)
# Open Sideloadly, select patched IPA, connect device, install

# Using ios-deploy (command line)
ios-deploy --bundle Payload/MyApp.app -W -d
```

## Connecting and Usage

1. Launch the patched app on your iOS device.

2. Set up USB tunneling:

```bash
iproxy 8080 8080
```

3. In another terminal, run commands:

```bash
# Basic commands
python3 client.py "ls"
python3 client.py "pwd"
python3 client.py "id"

# Download files/directories
python3 client.py "scp -r Documents host:./downloads"
```

The client automatically handles base64 decoding for downloads.

### Available Commands

- `ls [path]` - List directory contents
- `pwd` - Print working directory
- `id` - Print user and group IDs
- `uname` - Print system information
- `whoami` - Print current user name
- `echo <text>` - Echo text back
- `cp <src> <dst>` - Copy files locally within sandbox
- `scp -r <src> <dst>` - Download files/directories to host (use `host:./path`)

### Examples

```bash
# List root directory
python3 client.py "ls"

# Change directory and list
python3 client.py "cd Documents"
python3 client.py "ls"

# Download entire Documents directory
python3 client.py "scp -r Documents host:./my_downloads"

# Download specific subdirectory
python3 client.py "scp -r Documents/Subfolder host:./subfolder_download"
```

## Troubleshooting

### DYLIB Not Loading
- Check device logs via Xcode Console or `idevicesyslog`
- Look for "DYLIB loaded successfully" message
- Ensure signing identity is valid and not expired
- Try different signing identity

### Connection Refused
- Verify app is running on device
- Check USB connection: `iproxy 8080 8080` should show "waiting for connection"
- Ensure port 8080 is not blocked by firewall

### File Download Issues
- Check app sandbox permissions
- Verify destination path exists on host
- Large files may take time to transfer

### Patching Fails
- Ensure all paths are correct
- Check that insert_dylib is built and executable
- Verify IPA is not corrupted

## Security Notes

- This tool is for testing and development purposes only
- Respect app store policies and legal requirements
- The injected code runs with app's sandbox permissions
- Network traffic is tunneled via USB (secure)

## Cross-Platform Patcher (Windows / Linux / macOS)

A Python-based tool that replaces the macOS-only `patch_ipa.sh` script. Works on **any OS** — no Xcode or macOS required.

### Prerequisites

- Python 3.8+
- Pre-built `libShell.dylib` (compile once on macOS, or download from Releases)

### Installation

```bash
pip install -r tools/requirements.txt
```

### Quick Start

```bash
# Patch an IPA (inject dylib, modify plist)
python3 tools/patcher.py patch --ipa MyApp.ipa --dylib libShell.dylib

# Option A: Sign with Apple ID (free, cross-platform — like Sideloadly!)
python3 tools/patcher.py sign --ipa MyApp_patched.ipa --apple-id user@example.com

# Option B: Sign with Apple ID (dedicated command, more options)
python3 tools/patcher.py sign-apple --ipa MyApp_patched.ipa

# Option C: Skip signing, use Sideloadly instead (for paranoid users)
python3 tools/patcher.py sign-apple --ipa MyApp_patched.ipa --skip-sign

# Option D: Sign manually with .p12 certificate
python3 tools/patcher.py sign --ipa MyApp_patched.ipa --p12 cert.p12 -m profile.mobileprovision

# Install on device:
python3 tools/patcher.py install --ipa MyApp_patched_signed.ipa

# Full pipeline (patch + sign with Apple ID + install):
python3 tools/patcher.py full --ipa MyApp.ipa --dylib libShell.dylib --apple-id user@example.com --install

# Full pipeline (patch only, skip signing):
python3 tools/patcher.py full --ipa MyApp.ipa --dylib libShell.dylib --skip-sign

# List connected devices:
python3 tools/patcher.py devices

# Start USB tunnel:
python3 tools/patcher.py tunnel
```

### Apple ID Signing (Built-in, like Sideloadly)

The patcher can sign IPAs using your **free Apple ID** — no paid developer account needed. This works the same way Sideloadly does, directly on **Linux, Windows, and macOS**.

**Prerequisites:**
- [omnisette-server](https://github.com/SideStore/omnisette-server) running (provides anisette data)
  ```bash
  docker run -d --restart always --name omnisette \
    -p 6969:80 --volume omnisette_data:/opt/omnisette-server/lib \
    ghcr.io/sidestore/omnisette-server:latest
  ```
- Apple ID with 2FA enabled (standard for all accounts)

**Security:**
- Password is **never stored** to disk — only held in memory
- Authentication uses Apple's **SRP protocol** (server never sees plaintext password)
- 2FA is fully supported (trusted device push + SMS)
- Use `--skip-sign` if you don't trust CLI tools with your credentials

**Free account limitations:**
- Apps expire in **7 days** (must re-sign weekly)
- Max **3 app IDs** per week, **10 sideloaded apps** total
- Limited entitlements

### Recommended Workflow (No macOS needed)

1. Get a pre-built `libShell.dylib` (from Releases or CI)
2. Run: `python3 tools/patcher.py patch --ipa MyApp.ipa --dylib libShell.dylib`
3. Open **Sideloadly** (Windows/macOS) → select the patched IPA → install
4. On device, launch the app
5. `iproxy 8080 8080` then `python3 client.py "ls"`

### Signing Options

| Method | Platforms | Notes |
|--------|-----------|-------|
| **Apple ID** (`--apple-id`) | Win, Linux, macOS | Built-in, like Sideloadly. Free account. Requires omnisette-server |
| **Sideloadly** | Win, macOS | GUI tool — handles signing + install automatically |
| **zsign** + `.p12` | Win, Linux, macOS | CLI tool, needs certificate + provisioning profile |
| **ldid** | Win, Linux, macOS | Fakesign only (jailbreak devices) |
| **`--skip-sign`** | All | Skip signing — use Sideloadly or other tool later |

## Architecture

- `src/main.m` - DYLIB entry point, initializes server
- `src/ShellServer.m` - TCP server implementation
- `src/ShellCommands.m` - Command execution logic (38 built-in commands)
- `ios-patch/patch_ipa.sh` - IPA patching script (macOS only)
- `tools/patcher.py` - Cross-platform IPA patcher (Windows/Linux/macOS)
- `tools/apple_account.py` - Apple ID authentication & signing module
- `client.py` - Python client for remote commands
