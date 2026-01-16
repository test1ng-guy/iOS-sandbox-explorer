// ShellServer.h
#import <Foundation/Foundation.h>

@interface ShellServer : NSObject

+ (instancetype)sharedInstance;
- (void)startServerOnPort:(NSUInteger)port;
- (void)stopServer;

@end