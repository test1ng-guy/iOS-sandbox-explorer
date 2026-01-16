// ShellCommands.h
#import <Foundation/Foundation.h>

@interface ShellCommands : NSObject

+ (NSString *)executeCommand:(NSString *)command inDirectory:(NSString *)directory;

@end