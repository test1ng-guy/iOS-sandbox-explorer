# Makefile for building DYLIB on macOS/iOS

CC = clang
CFLAGS = -fobjc-arc -framework Foundation -dynamiclib -arch arm64 -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -Iinclude
LDFLAGS = -dynamiclib

TARGET = libShell.dylib
SOURCES = src/ShellServer.m src/ShellCommands.m src/main.m
HEADERS = include/ShellServer.h include/ShellCommands.h

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)

clean:
	rm -f $(TARGET)

.PHONY: all clean