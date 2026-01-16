// ShellCommands.m
#import "ShellCommands.h"
#import <Foundation/Foundation.h>
#import <sys/utsname.h>

@implementation ShellCommands

+ (NSString *)executeCommand:(NSString *)command inDirectory:(NSString *)directory {
    // Handle basic commands without popen
    if ([command isEqualToString:@"ls"]) {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSError *error;
        NSArray *contents = [fm contentsOfDirectoryAtPath:directory error:&error];
        if (error) {
            return [NSString stringWithFormat:@"Error: %@", error.localizedDescription];
        }
        return [contents componentsJoinedByString:@"\n"];
    } else if ([command isEqualToString:@"pwd"]) {
        return directory;
    } else if ([command isEqualToString:@"id"]) {
        return [NSString stringWithFormat:@"uid=%d gid=%d", getuid(), getgid()];
    } else if ([command isEqualToString:@"uname"]) {
        struct utsname systemInfo;
        uname(&systemInfo);
        return [NSString stringWithFormat:@"%@ %@ %@ %@", 
                [NSString stringWithUTF8String:systemInfo.sysname],
                [NSString stringWithUTF8String:systemInfo.nodename],
                [NSString stringWithUTF8String:systemInfo.release],
                [NSString stringWithUTF8String:systemInfo.machine]];
    } else if ([command isEqualToString:@"whoami"]) {
        return NSUserName();
    } else if ([command hasPrefix:@"echo "]) {
        return [command substringFromIndex:5];
    } else if ([command hasPrefix:@"scp "]) {
        NSString *argsString = [command substringFromIndex:4];
        NSArray *args = [argsString componentsSeparatedByString:@" "];
        return [self executeScp:args inDirectory:directory];
    } else {
        FILE *fp = popen([command UTF8String], "r");
        if (fp == NULL) {
            return @"Error executing command\n";
        }
        
        char buffer[1024];
        NSMutableString *result = [NSMutableString string];
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            [result appendString:[NSString stringWithUTF8String:buffer]];
        }
        
        int status = pclose(fp);
        if (status != 0) {
            [result appendString:@"\nCommand exited with error\n"];
        }
        
        return result.length > 0 ? result : @"Command executed\n";
    }
}

+ (NSString *)executeScp:(NSArray *)args inDirectory:(NSString *)directory {
    if (args.count < 2) {
        return @"Usage: scp [-r] <source> <destination>";
    }
    
    BOOL recursive = NO;
    NSString *source;
    NSString *destination;
    
    if ([args[0] isEqualToString:@"-r"]) {
        if (args.count < 3) {
            return @"Usage: scp -r <source> <destination>";
        }
        recursive = YES;
        source = args[1];
        destination = args[2];
    } else {
        source = args[0];
        destination = args[1];
    }
    
    // Check if destination is host: for download
    if ([destination hasPrefix:@"host:"]) {
        if (!recursive) {
            return @"Error: host download requires -r flag";
        }
        NSString *hostPath = [destination substringFromIndex:5];
        NSString *fullSource = [directory stringByAppendingPathComponent:source];
        return [self encodeDirectoryForDownload:fullSource toHostPath:hostPath];
    }
    
    // Local copy
    NSString *fullSource = [directory stringByAppendingPathComponent:source];
    NSString *fullDestination = [directory stringByAppendingPathComponent:destination];
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSError *error;
    
    if (![fileManager copyItemAtPath:fullSource toPath:fullDestination error:&error]) {
        return [NSString stringWithFormat:@"Error copying: %@", error.localizedDescription];
    }
    
    return @"Copied successfully";
}

+ (NSString *)encodeDirectoryForDownload:(NSString *)srcPath toHostPath:(NSString *)hostPath {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *error;
    
    BOOL isDir;
    if (![fm fileExistsAtPath:srcPath isDirectory:&isDir]) {
        return @"Error: Source path does not exist";
    }
    if (!isDir) {
        return @"Error: Source must be a directory for -r";
    }
    
    NSArray *contents = [fm contentsOfDirectoryAtPath:srcPath error:&error];
    if (!contents) {
        return [NSString stringWithFormat:@"Error listing directory: %@", error.localizedDescription];
    }
    
    NSMutableString *result = [NSMutableString stringWithFormat:@"SCP:%@;", hostPath];
    
    [self addFilesFromDirectory:srcPath toResult:result basePath:srcPath hostBasePath:hostPath];
    
    return result;
}

+ (void)addFilesFromDirectory:(NSString *)currentPath toResult:(NSMutableString *)result basePath:(NSString *)basePath hostBasePath:(NSString *)hostBasePath {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *error;
    
    NSArray *contents = [fm contentsOfDirectoryAtPath:currentPath error:&error];
    if (!contents) {
        return;
    }
    
    for (NSString *item in contents) {
        NSString *fullPath = [currentPath stringByAppendingPathComponent:item];
        
        // Skip hidden files and system files
        if ([item hasPrefix:@"."]) {
            continue;
        }
        
        BOOL itemIsDir;
        if ([fm fileExistsAtPath:fullPath isDirectory:&itemIsDir]) {
            if (itemIsDir) {
                // Recursively add files from subdirectory
                [self addFilesFromDirectory:fullPath toResult:result basePath:basePath hostBasePath:hostBasePath];
            } else {
                // Encode file using fopen for better access
                FILE *file = fopen([fullPath UTF8String], "rb");
                if (file) {
                    NSMutableData *fileData = [NSMutableData data];
                    char buffer[4096];
                    size_t bytesRead;
                    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
                        [fileData appendBytes:buffer length:bytesRead];
                    }
                    fclose(file);
                    
                    NSString *b64Data = [fileData base64EncodedStringWithOptions:0];
                    
                    // Calculate relative path from basePath
                    NSString *relativePath = [fullPath substringFromIndex:[basePath length] + 1]; // +1 for /
                    
                    [result appendFormat:@"FILE;%@;%@\n", relativePath, b64Data];
                }
            }
        }
    }
}

@end