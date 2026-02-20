// main.m - Entry point for DYLIB
// iOS Sandbox Explorer v2.0
#import <Foundation/Foundation.h>
#import "ShellServer.h"

__attribute__((constructor))
static void initialize(void) {
    NSOperatingSystemVersion ver = [[NSProcessInfo processInfo] operatingSystemVersion];
    NSLog(@"[SandboxExplorer] DYLIB loaded at %@", [NSDate date]);
    NSLog(@"[SandboxExplorer] iOS %ld.%ld.%ld",
          (long)ver.majorVersion, (long)ver.minorVersion, (long)ver.patchVersion);
    NSLog(@"[SandboxExplorer] Sandbox home: %@", NSHomeDirectory());
    
    // Start the shell server on loopback
    ShellServer *server = [[ShellServer alloc] init];
    [server startServerOnPort:8080];
    NSLog(@"[SandboxExplorer] Server started on 127.0.0.1:8080");
    NSLog(@"[SandboxExplorer] Connect via: iproxy 8080 8080 && python3 client.py help");
}