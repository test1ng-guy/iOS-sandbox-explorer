# Makefile for building DYLIB on macOS/iOS

CC = clang
CFLAGS = -fobjc-arc -framework Foundation -framework Security -dynamiclib -arch arm64 -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -Iinclude
LDFLAGS = -dynamiclib

TARGET = libShell.dylib
SOURCES = src/ShellServer.m src/ShellCommands.m src/main.m
HEADERS = include/ShellServer.h include/ShellCommands.h

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)

# Native macOS anisette helper (no Docker required)
ANISETTE_SRC = tools/anisette_helper.m
ANISETTE_BIN = tools/anisette_helper
ANISETTE_FLAGS = -framework Foundation -fmodules -fobjc-arc

anisette_helper: $(ANISETTE_SRC)
	clang $(ANISETTE_SRC) -o $(ANISETTE_BIN) $(ANISETTE_FLAGS)
	@echo "[+] Built $(ANISETTE_BIN)"

clean:
	rm -f $(TARGET) $(ANISETTE_BIN)

.PHONY: all clean anisette_helper