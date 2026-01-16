#!/bin/bash

# Script to patch IPA with custom DYLIB for non-jailbreak devices
# Usage: ./patch_ipa.sh <ipa_path> <dylib_path> <insert_dylib_path> <signing_identity> [output_ipa]

set -e

IPA_PATH="$1"
DYLIB_PATH="$2"
INSERT_DYLIB_PATH="$3"
SIGNING_IDENTITY="$4"
OUTPUT_IPA="${5:-patched_app.ipa}"

if [ -z "$IPA_PATH" ] || [ -z "$DYLIB_PATH" ] || [ -z "$INSERT_DYLIB_PATH" ] || [ -z "$SIGNING_IDENTITY" ]; then
    echo "Usage: $0 <ipa_path> <dylib_path> <insert_dylib_path> <signing_identity> [output_ipa]"
    exit 1
fi

if [ ! -f "$IPA_PATH" ]; then
    echo "IPA file not found: $IPA_PATH"
    exit 1
fi

if [ ! -f "$DYLIB_PATH" ]; then
    echo "DYLIB file not found: $DYLIB_PATH"
    exit 1
fi

if [ ! -f "$INSERT_DYLIB_PATH" ]; then
    echo "insert_dylib not found: $INSERT_DYLIB_PATH"
    exit 1
fi

# Create temp directory
ORIGINAL_DIR=$(pwd)
TEMP_DIR=$(mktemp -d)
echo "Using temp dir: $TEMP_DIR"

# Unzip IPA
unzip -q "$IPA_PATH" -d "$TEMP_DIR"

# Find the app bundle
APP_BUNDLE=$(find "$TEMP_DIR/Payload" -name "*.app" -type d | head -1)
if [ -z "$APP_BUNDLE" ]; then
    echo "App bundle not found in IPA"
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo "Found app bundle: $APP_BUNDLE"

# Copy DYLIB to Frameworks
FRAMEWORKS_DIR="$APP_BUNDLE/Frameworks"
mkdir -p "$FRAMEWORKS_DIR"
DYLIB_NAME=$(basename "$DYLIB_PATH")
cp "$DYLIB_PATH" "$FRAMEWORKS_DIR/"

echo "Copied DYLIB to $FRAMEWORKS_DIR/$DYLIB_NAME"

# Update Info.plist to allow arbitrary loads
INFO_PLIST="$APP_BUNDLE/Info.plist"
if [ -f "$INFO_PLIST" ]; then
    # Add NSAppTransportSecurity if not present
    /usr/libexec/PlistBuddy -c "Add :NSAppTransportSecurity dict" "$INFO_PLIST" 2>/dev/null || true
    /usr/libexec/PlistBuddy -c "Add :NSAppTransportSecurity:NSAllowsArbitraryLoads bool true" "$INFO_PLIST" 2>/dev/null || true
    echo "Updated Info.plist for arbitrary loads"
fi

# Create entitlements file
ENTITLEMENTS_FILE="$TEMP_DIR/entitlements.plist"
/usr/libexec/PlistBuddy -c "Add :com.apple.security.network.server bool true" "$ENTITLEMENTS_FILE" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Add :com.apple.security.network.client bool true" "$ENTITLEMENTS_FILE" 2>/dev/null || true
/usr/libexec/PlistBuddy -c "Add :com.apple.security.get-task-allow bool true" "$ENTITLEMENTS_FILE" 2>/dev/null || true
echo "Created entitlements file"

# Find the main binary
APP_NAME=$(basename "$APP_BUNDLE" .app)
BINARY_PATH="$APP_BUNDLE/$APP_NAME"

if [ ! -f "$BINARY_PATH" ]; then
    echo "Main binary not found: $BINARY_PATH"
    rm -rf "$TEMP_DIR"
    exit 1
fi

# Inject DYLIB into binary
echo "Injecting DYLIB into binary..."
"$INSERT_DYLIB_PATH" --all-yes "@executable_path/Frameworks/$DYLIB_NAME" "$BINARY_PATH"

# Replace original binary with patched one
PATCHED_BINARY_PATH="${BINARY_PATH}_patched"
if [ -f "$PATCHED_BINARY_PATH" ]; then
    mv "$PATCHED_BINARY_PATH" "$BINARY_PATH"
    echo "Replaced binary with patched version"
fi

# Sign the DYLIB
echo "Signing DYLIB..."
codesign -f -s "$SIGNING_IDENTITY" "$FRAMEWORKS_DIR/$DYLIB_NAME"

# Resign the binary with entitlements
echo "Resigning binary with entitlements..."
codesign -f -s "$SIGNING_IDENTITY" --entitlements "$ENTITLEMENTS_FILE" "$BINARY_PATH"

# Repackage IPA
cd "$TEMP_DIR"
zip -q -r "$ORIGINAL_DIR/$OUTPUT_IPA" Payload

# Cleanup
cd "$ORIGINAL_DIR"
rm -rf "$TEMP_DIR"

echo "Patched IPA created: $OUTPUT_IPA"
echo "You can now install it using Sideloadly, ios-deploy, or similar tools."