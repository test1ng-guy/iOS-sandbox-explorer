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

## Architecture

- `src/main.m` - DYLIB entry point, initializes server
- `src/ShellServer.m` - TCP server implementation
- `src/ShellCommands.m` - Command execution logic
- `ios-patch/patch_ipa.sh` - IPA patching script
- `client.py` - Python client for remote commands
