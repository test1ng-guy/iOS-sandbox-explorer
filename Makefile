# Makefile for building DYLIB on macOS/iOS (requires Xcode iphoneos SDK)
#
# Deployment-target policy (Phase 11):
#   - IPHONEOS_DEPLOYMENT_TARGET stays 14.0 so the dylib can load on older iOS.
#   - Build against the host iphoneos SDK (prefer Xcode 27+ / iOS 27 SDK).
#   - Do not silently raise the min OS to match the SDK major.
#   - CI requires SDK major >= IPHONEOS_SDK_MIN_MAJOR (default 27) via
#     REQUIRE_IOS_SDK_MAJOR=1; local builds warn unless that flag is set.

CC = clang
IPHONEOS_DEPLOYMENT_TARGET ?= 14.0
IPHONEOS_SDK_MIN_MAJOR ?= 27
REQUIRE_IOS_SDK_MAJOR ?= 0

# Resolve SDK once; fail fast if xcrun/iphoneos SDK is unavailable
SDKROOT := $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
ifeq ($(strip $(SDKROOT)),)
$(error iphoneos SDK not found. Install Xcode (or CLT with iOS SDK) and ensure `xcrun --sdk iphoneos --show-sdk-path` works.)
endif

SDK_VERSION := $(shell xcrun --sdk iphoneos --show-sdk-version 2>/dev/null)
SDK_MAJOR := $(shell printf '%s' '$(SDK_VERSION)' | cut -d. -f1)

ifeq ($(REQUIRE_IOS_SDK_MAJOR),1)
ifeq ($(shell [ -n "$(SDK_MAJOR)" ] && [ "$(SDK_MAJOR)" -ge "$(IPHONEOS_SDK_MIN_MAJOR)" ] && echo ok),)
$(error iphoneos SDK $(SDK_VERSION) is below required major $(IPHONEOS_SDK_MIN_MAJOR). Use Xcode 27+ (e.g. GitHub Actions runs-on: xcode-27). Do not fake SDK versions.)
endif
endif

CFLAGS = -fobjc-arc -framework Foundation -framework Security -dynamiclib -arch arm64 \
	-isysroot $(SDKROOT) -miphoneos-version-min=$(IPHONEOS_DEPLOYMENT_TARGET) -Iinclude
LDFLAGS = -dynamiclib

TARGET = libShell.dylib
SOURCES = src/ShellServer.m src/ShellCommands.m src/main.m
HEADERS = include/ShellServer.h include/ShellCommands.h

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	@echo "[*] iphoneos SDK $(SDK_VERSION) at $(SDKROOT)"
	@echo "[*] deployment target $(IPHONEOS_DEPLOYMENT_TARGET) (min OS; not raised to SDK major)"
	@if [ -n "$(SDK_MAJOR)" ] && [ "$(SDK_MAJOR)" -lt "$(IPHONEOS_SDK_MIN_MAJOR)" ]; then \
		echo "[!] Warning: SDK major $(SDK_MAJOR) < $(IPHONEOS_SDK_MIN_MAJOR); prefer Xcode 27+ / iOS 27 SDK"; \
	fi
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)

clean:
	rm -f $(TARGET)

.PHONY: all clean
