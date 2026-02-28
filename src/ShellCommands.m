// ShellCommands.m — Expanded command set for iOS sandbox exploration
// All commands implemented via Foundation/POSIX APIs — no popen(), no shell dependency
// Compatible with iOS 14–26 sandbox restrictions

#import "ShellCommands.h"
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <sys/statvfs.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <CommonCrypto/CommonDigest.h>
#import <dlfcn.h>
#import <pwd.h>
#import <grp.h>

// Maximum output size to prevent memory issues over TCP
#define MAX_OUTPUT_SIZE (4 * 1024 * 1024)  // 4 MB

#pragma mark - Helper: Command Parser

static NSArray<NSString *> *parseCommandLine(NSString *input) {
    // Quote-aware command line parser
    NSMutableArray *tokens = [NSMutableArray array];
    NSMutableString *current = [NSMutableString string];
    BOOL inSingleQuote = NO;
    BOOL inDoubleQuote = NO;
    BOOL escaped = NO;

    for (NSUInteger i = 0; i < input.length; i++) {
        unichar c = [input characterAtIndex:i];

        if (escaped) {
            [current appendFormat:@"%C", c];
            escaped = NO;
            continue;
        }

        if (c == '\\' && !inSingleQuote) {
            escaped = YES;
            continue;
        }

        if (c == '\'' && !inDoubleQuote) {
            inSingleQuote = !inSingleQuote;
            continue;
        }

        if (c == '"' && !inSingleQuote) {
            inDoubleQuote = !inDoubleQuote;
            continue;
        }

        if (c == ' ' && !inSingleQuote && !inDoubleQuote) {
            if (current.length > 0) {
                [tokens addObject:[current copy]];
                [current setString:@""];
            }
            continue;
        }

        [current appendFormat:@"%C", c];
    }

    if (current.length > 0) {
        [tokens addObject:[current copy]];
    }

    return tokens;
}

static NSString *resolvePath(NSString *path, NSString *directory) {
    if ([path hasPrefix:@"/"]) return path;
    if ([path hasPrefix:@"~"]) {
        return [NSHomeDirectory() stringByAppendingPathComponent:[path substringFromIndex:1]];
    }
    return [directory stringByAppendingPathComponent:path];
}

static NSString *formatFileSize(unsigned long long size) {
    if (size < 1024) return [NSString stringWithFormat:@"%llu B", size];
    if (size < 1024 * 1024) return [NSString stringWithFormat:@"%.1f KB", size / 1024.0];
    if (size < 1024 * 1024 * 1024) return [NSString stringWithFormat:@"%.1f MB", size / (1024.0 * 1024.0)];
    return [NSString stringWithFormat:@"%.1f GB", size / (1024.0 * 1024.0 * 1024.0)];
}

static NSString *permissionsString(NSUInteger posixPerms) {
    char perms[11];
    perms[0] = '-';  // will be overridden for dirs
    perms[1] = (posixPerms & S_IRUSR) ? 'r' : '-';
    perms[2] = (posixPerms & S_IWUSR) ? 'w' : '-';
    perms[3] = (posixPerms & S_IXUSR) ? 'x' : '-';
    perms[4] = (posixPerms & S_IRGRP) ? 'r' : '-';
    perms[5] = (posixPerms & S_IWGRP) ? 'w' : '-';
    perms[6] = (posixPerms & S_IXGRP) ? 'x' : '-';
    perms[7] = (posixPerms & S_IROTH) ? 'r' : '-';
    perms[8] = (posixPerms & S_IWOTH) ? 'w' : '-';
    perms[9] = (posixPerms & S_IXOTH) ? 'x' : '-';
    perms[10] = '\0';
    return [NSString stringWithUTF8String:perms];
}

#pragma mark - ShellCommands Implementation

@implementation ShellCommands

+ (NSString *)executeCommand:(NSString *)fullCommand inDirectory:(NSString *)directory {
    NSArray *tokens = parseCommandLine(fullCommand);
    if (tokens.count == 0) return @"";

    NSString *cmd = [tokens[0] lowercaseString];
    NSArray *args = tokens.count > 1 ? [tokens subarrayWithRange:NSMakeRange(1, tokens.count - 1)] : @[];

    // ─── Navigation ──────────────────────────────────────────────
    if ([cmd isEqualToString:@"ls"])       return [self cmd_ls:args dir:directory];
    if ([cmd isEqualToString:@"pwd"])      return directory;
    if ([cmd isEqualToString:@"tree"])     return [self cmd_tree:args dir:directory];

    // ─── File Reading ────────────────────────────────────────────
    if ([cmd isEqualToString:@"cat"])      return [self cmd_cat:args dir:directory];
    if ([cmd isEqualToString:@"head"])     return [self cmd_head:args dir:directory];
    if ([cmd isEqualToString:@"tail"])     return [self cmd_tail:args dir:directory];
    if ([cmd isEqualToString:@"hexdump"])  return [self cmd_hexdump:args dir:directory];
    if ([cmd isEqualToString:@"strings"])  return [self cmd_strings:args dir:directory];
    if ([cmd isEqualToString:@"base64"])   return [self cmd_base64:args dir:directory];

    // ─── File Operations ─────────────────────────────────────────
    if ([cmd isEqualToString:@"cp"])       return [self cmd_cp:args dir:directory];
    if ([cmd isEqualToString:@"mv"])       return [self cmd_mv:args dir:directory];
    if ([cmd isEqualToString:@"rm"])       return [self cmd_rm:args dir:directory];
    if ([cmd isEqualToString:@"mkdir"])    return [self cmd_mkdir:args dir:directory];
    if ([cmd isEqualToString:@"touch"])    return [self cmd_touch:args dir:directory];
    if ([cmd isEqualToString:@"chmod"])    return [self cmd_chmod:args dir:directory];

    // ─── File Info ───────────────────────────────────────────────
    if ([cmd isEqualToString:@"stat"])     return [self cmd_stat:args dir:directory];
    if ([cmd isEqualToString:@"file"])     return [self cmd_file:args dir:directory];
    if ([cmd isEqualToString:@"md5"])      return [self cmd_md5:args dir:directory];
    if ([cmd isEqualToString:@"sha256"])   return [self cmd_sha256:args dir:directory];
    if ([cmd isEqualToString:@"wc"])       return [self cmd_wc:args dir:directory];
    if ([cmd isEqualToString:@"du"])       return [self cmd_du:args dir:directory];
    if ([cmd isEqualToString:@"realpath"]) return [self cmd_realpath:args dir:directory];
    if ([cmd isEqualToString:@"readlink"]) return [self cmd_readlink:args dir:directory];

    // ─── Search ──────────────────────────────────────────────────
    if ([cmd isEqualToString:@"find"])     return [self cmd_find:args dir:directory];
    if ([cmd isEqualToString:@"grep"])     return [self cmd_grep:args dir:directory];

    // ─── System Info ─────────────────────────────────────────────
    if ([cmd isEqualToString:@"id"])       return [self cmd_id];
    if ([cmd isEqualToString:@"uname"])    return [self cmd_uname:args];
    if ([cmd isEqualToString:@"whoami"])   return NSUserName() ?: @"mobile";
    if ([cmd isEqualToString:@"env"])      return [self cmd_env:args];
    if ([cmd isEqualToString:@"date"])     return [[NSDate date] description];
    if ([cmd isEqualToString:@"df"])       return [self cmd_df:directory];
    if ([cmd isEqualToString:@"uptime"])   return [self cmd_uptime];
    if ([cmd isEqualToString:@"bundle"])   return [self cmd_bundle];
    if ([cmd isEqualToString:@"sandbox"])  return [self cmd_sandbox];
    if ([cmd isEqualToString:@"sysinfo"])  return [self cmd_sysinfo];
    if ([cmd isEqualToString:@"memory"])   return [self cmd_memory];

    // ─── Keychain ────────────────────────────────────────────────
    if ([cmd isEqualToString:@"keychain"]) return [self cmd_keychain:args];

    // ─── Transfer ────────────────────────────────────────────────
    if ([cmd isEqualToString:@"scp"])      return [self cmd_scp:args dir:directory];
    if ([cmd isEqualToString:@"download"]) return [self cmd_download:args dir:directory];

    // ─── Other ───────────────────────────────────────────────────
    if ([cmd isEqualToString:@"echo"])     return [self cmd_echo:args];
    if ([cmd isEqualToString:@"help"])     return [self cmd_help];
    if ([cmd isEqualToString:@"version"])  return [self cmd_version];

    return [NSString stringWithFormat:@"Unknown command: %@\nType 'help' for available commands.", cmd];
}


#pragma mark - Navigation Commands

+ (NSString *)cmd_ls:(NSArray *)args dir:(NSString *)directory {
    BOOL showAll = NO;
    BOOL longFormat = NO;
    NSString *targetPath = directory;

    for (NSString *arg in args) {
        if ([arg hasPrefix:@"-"]) {
            if ([arg containsString:@"a"]) showAll = YES;
            if ([arg containsString:@"l"]) longFormat = YES;
        } else {
            targetPath = resolvePath(arg, directory);
        }
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *error;
    NSArray *contents = [fm contentsOfDirectoryAtPath:targetPath error:&error];
    if (error) {
        return [NSString stringWithFormat:@"ls: %@", error.localizedDescription];
    }

    // Sort
    contents = [contents sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];

    // Filter hidden files
    if (!showAll) {
        contents = [contents filteredArrayUsingPredicate:
            [NSPredicate predicateWithBlock:^BOOL(NSString *name, NSDictionary *bindings) {
                return ![name hasPrefix:@"."];
            }]];
    }

    if (!longFormat) {
        return [contents componentsJoinedByString:@"\n"];
    }

    // Long format
    NSMutableString *result = [NSMutableString string];
    NSDateFormatter *dateFmt = [[NSDateFormatter alloc] init];
    dateFmt.dateFormat = @"MMM dd HH:mm";

    for (NSString *name in contents) {
        NSString *fullPath = [targetPath stringByAppendingPathComponent:name];
        NSDictionary *attrs = [fm attributesOfItemAtPath:fullPath error:nil];
        if (!attrs) continue;

        NSString *type = attrs[NSFileType];
        BOOL isDir = [type isEqualToString:NSFileTypeDirectory];
        BOOL isLink = [type isEqualToString:NSFileTypeSymbolicLink];

        NSUInteger perms = [attrs[NSFilePosixPermissions] unsignedIntegerValue];
        NSString *permStr = permissionsString(perms);
        NSMutableString *mPerm = [permStr mutableCopy];
        [mPerm replaceCharactersInRange:NSMakeRange(0, 1)
                             withString:isDir ? @"d" : (isLink ? @"l" : @"-")];

        unsigned long long size = [attrs[NSFileSize] unsignedLongLongValue];
        NSDate *modified = attrs[NSFileModificationDate];
        NSString *dateStr = modified ? [dateFmt stringFromDate:modified] : @"???";

        [result appendFormat:@"%@ %8llu %@ %@%@\n",
            mPerm, size, dateStr, name, isDir ? @"/" : (isLink ? @" -> ?" : @"")];
    }

    return result.length > 0 ? result : @"(empty directory)";
}

+ (NSString *)cmd_tree:(NSArray *)args dir:(NSString *)directory {
    NSString *targetPath = directory;
    NSInteger maxDepth = 4;

    for (NSUInteger i = 0; i < args.count; i++) {
        if ([args[i] isEqualToString:@"-d"] && i + 1 < args.count) {
            maxDepth = [args[i + 1] integerValue];
            i++;
        } else if (![args[i] hasPrefix:@"-"]) {
            targetPath = resolvePath(args[i], directory);
        }
    }

    NSMutableString *result = [NSMutableString stringWithFormat:@"%@\n", [targetPath lastPathComponent]];
    NSInteger fileCount = 0, dirCount = 0;
    [self buildTree:targetPath prefix:@"" result:result depth:0 maxDepth:maxDepth
         fileCount:&fileCount dirCount:&dirCount];
    [result appendFormat:@"\n%ld directories, %ld files", (long)dirCount, (long)fileCount];
    return result;
}

+ (void)buildTree:(NSString *)path prefix:(NSString *)prefix result:(NSMutableString *)result
            depth:(NSInteger)depth maxDepth:(NSInteger)maxDepth
        fileCount:(NSInteger *)fileCount dirCount:(NSInteger *)dirCount {

    if (depth >= maxDepth) return;
    if (result.length > MAX_OUTPUT_SIZE) return;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *contents = [[fm contentsOfDirectoryAtPath:path error:nil]
        filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSString *name, NSDictionary *b) {
            return ![name hasPrefix:@"."];
        }]];
    contents = [contents sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];

    for (NSUInteger i = 0; i < contents.count; i++) {
        NSString *name = contents[i];
        BOOL isLast = (i == contents.count - 1);
        NSString *connector = isLast ? @"└── " : @"├── ";
        NSString *childPrefix = isLast ? @"    " : @"│   ";

        NSString *fullPath = [path stringByAppendingPathComponent:name];
        BOOL isDir = NO;
        [fm fileExistsAtPath:fullPath isDirectory:&isDir];

        [result appendFormat:@"%@%@%@%@\n", prefix, connector, name, isDir ? @"/" : @""];

        if (isDir) {
            (*dirCount)++;
            [self buildTree:fullPath prefix:[prefix stringByAppendingString:childPrefix]
                     result:result depth:depth + 1 maxDepth:maxDepth
                  fileCount:fileCount dirCount:dirCount];
        } else {
            (*fileCount)++;
        }
    }
}


#pragma mark - File Reading Commands

+ (NSString *)cmd_cat:(NSArray *)args dir:(NSString *)directory {
    if (args.count == 0) return @"Usage: cat <file>";

    NSString *filePath = resolvePath([args lastObject], directory);
    NSError *error;
    NSString *content = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:&error];
    if (error) {
        // Try binary read and show as lossy UTF-8
        NSData *data = [NSData dataWithContentsOfFile:filePath options:0 error:&error];
        if (data) {
            return [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding]
                ?: @"(binary file — use 'hexdump' or 'base64')";
        }
        return [NSString stringWithFormat:@"cat: %@", error.localizedDescription];
    }
    return content;
}

+ (NSString *)cmd_head:(NSArray *)args dir:(NSString *)directory {
    NSInteger lines = 10;
    NSString *filePath = nil;

    for (NSUInteger i = 0; i < args.count; i++) {
        if ([args[i] isEqualToString:@"-n"] && i + 1 < args.count) {
            lines = [args[i + 1] integerValue];
            i++;
        } else if (![args[i] hasPrefix:@"-"]) {
            filePath = args[i];
        }
    }

    if (!filePath) return @"Usage: head [-n N] <file>";
    filePath = resolvePath(filePath, directory);

    NSString *content = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
    if (!content) return @"head: cannot read file";

    NSArray *allLines = [content componentsSeparatedByString:@"\n"];
    NSInteger count = MIN(lines, (NSInteger)allLines.count);
    return [[allLines subarrayWithRange:NSMakeRange(0, count)] componentsJoinedByString:@"\n"];
}

+ (NSString *)cmd_tail:(NSArray *)args dir:(NSString *)directory {
    NSInteger lines = 10;
    NSString *filePath = nil;

    for (NSUInteger i = 0; i < args.count; i++) {
        if ([args[i] isEqualToString:@"-n"] && i + 1 < args.count) {
            lines = [args[i + 1] integerValue];
            i++;
        } else if (![args[i] hasPrefix:@"-"]) {
            filePath = args[i];
        }
    }

    if (!filePath) return @"Usage: tail [-n N] <file>";
    filePath = resolvePath(filePath, directory);

    NSString *content = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
    if (!content) return @"tail: cannot read file";

    NSArray *allLines = [content componentsSeparatedByString:@"\n"];
    NSInteger start = MAX(0, (NSInteger)allLines.count - lines);
    return [[allLines subarrayWithRange:NSMakeRange(start, allLines.count - start)]
            componentsJoinedByString:@"\n"];
}

+ (NSString *)cmd_hexdump:(NSArray *)args dir:(NSString *)directory {
    NSInteger maxBytes = 256;
    NSString *filePath = nil;

    for (NSUInteger i = 0; i < args.count; i++) {
        if ([args[i] isEqualToString:@"-n"] && i + 1 < args.count) {
            maxBytes = [args[i + 1] integerValue];
            i++;
        } else if (![args[i] hasPrefix:@"-"]) {
            filePath = args[i];
        }
    }

    if (!filePath) return @"Usage: hexdump [-n bytes] <file>";
    filePath = resolvePath(filePath, directory);

    NSData *data = [NSData dataWithContentsOfFile:filePath];
    if (!data) return @"hexdump: cannot read file";

    NSUInteger length = MIN((NSUInteger)maxBytes, data.length);
    const uint8_t *bytes = data.bytes;
    NSMutableString *result = [NSMutableString string];

    for (NSUInteger offset = 0; offset < length; offset += 16) {
        [result appendFormat:@"%08lx  ", (unsigned long)offset];

        // Hex bytes
        for (NSUInteger j = 0; j < 16; j++) {
            if (offset + j < length) {
                [result appendFormat:@"%02x ", bytes[offset + j]];
            } else {
                [result appendString:@"   "];
            }
            if (j == 7) [result appendString:@" "];
        }

        [result appendString:@" |"];

        // ASCII
        for (NSUInteger j = 0; j < 16 && offset + j < length; j++) {
            uint8_t c = bytes[offset + j];
            [result appendFormat:@"%c", (c >= 32 && c < 127) ? c : '.'];
        }

        [result appendString:@"|\n"];
    }

    [result appendFormat:@"\n%lu bytes shown (total file size: %lu)",
        (unsigned long)length, (unsigned long)data.length];
    return result;
}

+ (NSString *)cmd_strings:(NSArray *)args dir:(NSString *)directory {
    NSInteger minLength = 4;
    NSString *filePath = nil;

    for (NSUInteger i = 0; i < args.count; i++) {
        if ([args[i] isEqualToString:@"-n"] && i + 1 < args.count) {
            minLength = [args[i + 1] integerValue];
            i++;
        } else if (![args[i] hasPrefix:@"-"]) {
            filePath = args[i];
        }
    }

    if (!filePath) return @"Usage: strings [-n min_length] <file>";
    filePath = resolvePath(filePath, directory);

    NSData *data = [NSData dataWithContentsOfFile:filePath];
    if (!data) return @"strings: cannot read file";

    const uint8_t *bytes = data.bytes;
    NSUInteger length = data.length;
    NSMutableString *result = [NSMutableString string];
    NSMutableString *current = [NSMutableString string];

    for (NSUInteger i = 0; i < length && result.length < MAX_OUTPUT_SIZE; i++) {
        uint8_t c = bytes[i];
        if (c >= 32 && c < 127) {
            [current appendFormat:@"%c", c];
        } else {
            if ((NSInteger)current.length >= minLength) {
                [result appendFormat:@"%@\n", current];
            }
            [current setString:@""];
        }
    }
    if ((NSInteger)current.length >= minLength) {
        [result appendFormat:@"%@\n", current];
    }

    return result.length > 0 ? result : @"(no printable strings found)";
}

+ (NSString *)cmd_base64:(NSArray *)args dir:(NSString *)directory {
    if (args.count == 0) return @"Usage: base64 <file>";

    NSString *filePath = resolvePath(args[0], directory);
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    if (!data) return @"base64: cannot read file";

    return [data base64EncodedStringWithOptions:NSDataBase64Encoding76CharacterLineLength];
}


#pragma mark - File Operations

+ (NSString *)cmd_cp:(NSArray *)args dir:(NSString *)directory {
    if (args.count < 2) return @"Usage: cp <source> <destination>";

    NSString *src = resolvePath(args[0], directory);
    NSString *dst = resolvePath(args[1], directory);
    NSError *error;

    if (![[NSFileManager defaultManager] copyItemAtPath:src toPath:dst error:&error]) {
        return [NSString stringWithFormat:@"cp: %@", error.localizedDescription];
    }
    return @"Copied successfully";
}

+ (NSString *)cmd_mv:(NSArray *)args dir:(NSString *)directory {
    if (args.count < 2) return @"Usage: mv <source> <destination>";

    NSString *src = resolvePath(args[0], directory);
    NSString *dst = resolvePath(args[1], directory);
    NSError *error;

    if (![[NSFileManager defaultManager] moveItemAtPath:src toPath:dst error:&error]) {
        return [NSString stringWithFormat:@"mv: %@", error.localizedDescription];
    }
    return @"Moved successfully";
}

+ (NSString *)cmd_rm:(NSArray *)args dir:(NSString *)directory {
    BOOL recursive = NO;
    NSString *targetPath = nil;

    for (NSString *arg in args) {
        if ([arg isEqualToString:@"-r"] || [arg isEqualToString:@"-rf"]) {
            recursive = YES;
        } else {
            targetPath = arg;
        }
    }

    if (!targetPath) return @"Usage: rm [-r] <path>";
    targetPath = resolvePath(targetPath, directory);

    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:targetPath isDirectory:&isDir]) {
        return @"rm: file not found";
    }

    if (isDir && !recursive) {
        return @"rm: is a directory (use -r to remove recursively)";
    }

    NSError *error;
    if (![fm removeItemAtPath:targetPath error:&error]) {
        return [NSString stringWithFormat:@"rm: %@", error.localizedDescription];
    }
    return @"Removed";
}

+ (NSString *)cmd_mkdir:(NSArray *)args dir:(NSString *)directory {
    BOOL createParents = NO;
    NSString *targetPath = nil;

    for (NSString *arg in args) {
        if ([arg isEqualToString:@"-p"]) {
            createParents = YES;
        } else {
            targetPath = arg;
        }
    }

    if (!targetPath) return @"Usage: mkdir [-p] <path>";
    targetPath = resolvePath(targetPath, directory);

    NSError *error;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:targetPath
                                   withIntermediateDirectories:createParents
                                                   attributes:nil error:&error]) {
        return [NSString stringWithFormat:@"mkdir: %@", error.localizedDescription];
    }
    return [NSString stringWithFormat:@"Created: %@", targetPath];
}

+ (NSString *)cmd_touch:(NSArray *)args dir:(NSString *)directory {
    if (args.count == 0) return @"Usage: touch <file>";

    NSString *filePath = resolvePath(args[0], directory);
    NSFileManager *fm = [NSFileManager defaultManager];

    if ([fm fileExistsAtPath:filePath]) {
        // Update modification date
        [fm setAttributes:@{NSFileModificationDate: [NSDate date]} ofItemAtPath:filePath error:nil];
        return @"Updated timestamp";
    }

    // Create empty file
    [fm createFileAtPath:filePath contents:[NSData data] attributes:nil];
    return [NSString stringWithFormat:@"Created: %@", filePath];
}

+ (NSString *)cmd_chmod:(NSArray *)args dir:(NSString *)directory {
    if (args.count < 2) return @"Usage: chmod <mode> <path> (e.g. chmod 755 file)";

    NSUInteger mode = strtoul([args[0] UTF8String], NULL, 8);
    NSString *targetPath = resolvePath(args[1], directory);

    NSError *error;
    if (![[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions: @(mode)}
                                          ofItemAtPath:targetPath error:&error]) {
        return [NSString stringWithFormat:@"chmod: %@", error.localizedDescription];
    }
    return [NSString stringWithFormat:@"Changed permissions to %03lo", (unsigned long)mode];
}


#pragma mark - File Info Commands

+ (NSString *)cmd_stat:(NSArray *)args dir:(NSString *)directory {
    if (args.count == 0) return @"Usage: stat <path>";

    NSString *targetPath = resolvePath(args[0], directory);
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *error;
    NSDictionary *attrs = [fm attributesOfItemAtPath:targetPath error:&error];
    if (!attrs) {
        return [NSString stringWithFormat:@"stat: %@", error.localizedDescription];
    }

    struct stat sb;
    if (stat([targetPath UTF8String], &sb) != 0) {
        return @"stat: cannot stat file";
    }

    NSMutableString *result = [NSMutableString string];
    [result appendFormat:@"  File: %@\n", targetPath];
    [result appendFormat:@"  Size: %llu\n", [attrs[NSFileSize] unsignedLongLongValue]];
    [result appendFormat:@"  Type: %@\n", attrs[NSFileType]];
    [result appendFormat:@" Perms: %@ (%lo)\n",
        permissionsString(sb.st_mode & 07777), (unsigned long)(sb.st_mode & 07777)];
    [result appendFormat:@" Owner: uid=%d gid=%d\n", sb.st_uid, sb.st_gid];
    [result appendFormat:@" Inode: %llu\n", (unsigned long long)sb.st_ino];
    [result appendFormat:@" Links: %u\n", sb.st_nlink];
    [result appendFormat:@"Access: %@\n", attrs[NSFileCreationDate]];
    [result appendFormat:@"Modify: %@\n", attrs[NSFileModificationDate]];
    [result appendFormat:@"Device: %d,%d\n", major(sb.st_dev), minor(sb.st_dev)];

    // Protection class (iOS data protection)
    NSString *protection = attrs[NSFileProtectionKey];
    if (protection) {
        [result appendFormat:@"Protect: %@\n", protection];
    }

    return result;
}

+ (NSString *)cmd_file:(NSArray *)args dir:(NSString *)directory {
    if (args.count == 0) return @"Usage: file <path>";

    NSString *filePath = resolvePath(args[0], directory);
    NSFileManager *fm = [NSFileManager defaultManager];

    BOOL isDir = NO;
    if (![fm fileExistsAtPath:filePath isDirectory:&isDir]) {
        return @"file: not found";
    }
    if (isDir) return [NSString stringWithFormat:@"%@: directory", args[0]];

    // Read first 16 bytes for magic
    NSData *header = [self readFileHead:filePath bytes:16];
    if (!header || header.length == 0) {
        return [NSString stringWithFormat:@"%@: empty file", args[0]];
    }

    const uint8_t *magic = header.bytes;
    NSUInteger len = header.length;

    // Detect file type by magic bytes
    NSString *type = @"data";

    if (len >= 4) {
        uint32_t m32 = (magic[0] << 24) | (magic[1] << 16) | (magic[2] << 8) | magic[3];

        if (m32 == 0xFEEDFACF) type = @"Mach-O 64-bit executable";
        else if (m32 == 0xFEEDFACE) type = @"Mach-O 32-bit executable";
        else if (m32 == 0xCFFAEDFE) type = @"Mach-O 64-bit (reversed)";
        else if (m32 == 0xCEFAEDFE) type = @"Mach-O 32-bit (reversed)";
        else if (m32 == 0xCAFEBABE) type = @"Mach-O universal binary (FAT)";
        else if (m32 == 0xBEBAFECA) type = @"Mach-O universal binary (FAT, reversed)";
        else if (magic[0] == 0x89 && magic[1] == 0x50 && magic[2] == 0x4E && magic[3] == 0x47)
            type = @"PNG image";
        else if (magic[0] == 0xFF && magic[1] == 0xD8 && magic[2] == 0xFF)
            type = @"JPEG image";
        else if (magic[0] == 0x47 && magic[1] == 0x49 && magic[2] == 0x46)
            type = @"GIF image";
        else if (magic[0] == 0x25 && magic[1] == 0x50 && magic[2] == 0x44 && magic[3] == 0x46)
            type = @"PDF document";
        else if (magic[0] == 0x50 && magic[1] == 0x4B && magic[2] == 0x03 && magic[3] == 0x04)
            type = @"ZIP archive";
        else if (len >= 6 && memcmp(magic, "bplist", 6) == 0)
            type = @"Apple binary property list";
        else if (len >= 15 && memcmp(magic, "SQLite format 3", 15) == 0)
            type = @"SQLite 3.x database";
        else if (magic[0] == 0x3C && magic[1] == 0x3F)
            type = @"XML document";
        else if (magic[0] == '{') type = @"JSON data";
        else if (magic[0] == '<') type = @"HTML/XML document";
    }

    // Check by extension if still unknown
    if ([type isEqualToString:@"data"] || [type isEqualToString:@"XML document"]) {
        NSString *ext = [filePath pathExtension];
        if ([ext isEqualToString:@"plist"]) type = @"Apple property list (XML)";
        else if ([ext isEqualToString:@"json"]) type = @"JSON data";
        else if ([ext isEqualToString:@"xml"]) type = @"XML document";
        else if ([ext isEqualToString:@"strings"]) type = @"Apple strings file";
        else if ([ext isEqualToString:@"car"]) type = @"Compiled Asset Catalog";
        else if ([ext isEqualToString:@"nib"] || [ext isEqualToString:@"storyboardc"])
            type = @"Compiled Interface Builder";
    }

    NSDictionary *attrs = [fm attributesOfItemAtPath:filePath error:nil];
    unsigned long long size = [attrs[NSFileSize] unsignedLongLongValue];

    return [NSString stringWithFormat:@"%@: %@ (%@)", args[0], type, formatFileSize(size)];
}

+ (NSData *)readFileHead:(NSString *)path bytes:(NSUInteger)count {
    FILE *f = fopen([path UTF8String], "rb");
    if (!f) return nil;

    uint8_t *buf = malloc(count);
    size_t read_count = fread(buf, 1, count, f);
    fclose(f);

    NSData *data = [NSData dataWithBytes:buf length:read_count];
    free(buf);
    return data;
}

+ (NSString *)cmd_md5:(NSArray *)args dir:(NSString *)directory {
    if (args.count == 0) return @"Usage: md5 <file>";

    NSString *filePath = resolvePath(args[0], directory);
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    if (!data) return @"md5: cannot read file";

    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(data.bytes, (CC_LONG)data.length, digest);

    NSMutableString *hash = [NSMutableString string];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", digest[i]];
    }
    return [NSString stringWithFormat:@"%@  %@", hash, args[0]];
}

+ (NSString *)cmd_sha256:(NSArray *)args dir:(NSString *)directory {
    if (args.count == 0) return @"Usage: sha256 <file>";

    NSString *filePath = resolvePath(args[0], directory);
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    if (!data) return @"sha256: cannot read file";

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);

    NSMutableString *hash = [NSMutableString string];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", digest[i]];
    }
    return [NSString stringWithFormat:@"%@  %@", hash, args[0]];
}

+ (NSString *)cmd_wc:(NSArray *)args dir:(NSString *)directory {
    if (args.count == 0) return @"Usage: wc <file>";

    NSString *filePath = resolvePath(args[0], directory);
    NSData *data = [NSData dataWithContentsOfFile:filePath];
    if (!data) return @"wc: cannot read file";

    NSString *content = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!content) {
        return [NSString stringWithFormat:@"  ?  ?  %lu %@",
            (unsigned long)data.length, args[0]];
    }

    NSUInteger lines = [[content componentsSeparatedByString:@"\n"] count];
    NSUInteger words = 0;
    NSScanner *scanner = [NSScanner scannerWithString:content];
    NSString *word;
    while ([scanner scanUpToCharactersFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]
                                   intoString:&word]) {
        words++;
    }

    return [NSString stringWithFormat:@"  %lu  %lu  %lu %@",
        (unsigned long)lines, (unsigned long)words, (unsigned long)data.length, args[0]];
}

+ (NSString *)cmd_du:(NSArray *)args dir:(NSString *)directory {
    NSString *targetPath = directory;

    for (NSString *arg in args) {
        if (![arg hasPrefix:@"-"]) targetPath = resolvePath(arg, directory);
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    unsigned long long totalSize = 0;

    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:targetPath];
    NSString *file;
    while ((file = [enumerator nextObject])) {
        NSString *fullPath = [targetPath stringByAppendingPathComponent:file];
        NSDictionary *attrs = [fm attributesOfItemAtPath:fullPath error:nil];
        totalSize += [attrs[NSFileSize] unsignedLongLongValue];
    }

    return [NSString stringWithFormat:@"%@\t%@",
        formatFileSize(totalSize), [targetPath lastPathComponent]];
}

+ (NSString *)cmd_realpath:(NSArray *)args dir:(NSString *)directory {
    if (args.count == 0) return @"Usage: realpath <path>";
    NSString *path = resolvePath(args[0], directory);
    return [path stringByResolvingSymlinksInPath];
}

+ (NSString *)cmd_readlink:(NSArray *)args dir:(NSString *)directory {
    if (args.count == 0) return @"Usage: readlink <path>";
    NSString *path = resolvePath(args[0], directory);
    NSError *error;
    NSString *dest = [[NSFileManager defaultManager]
        destinationOfSymbolicLinkAtPath:path error:&error];
    if (!dest) return [NSString stringWithFormat:@"readlink: %@", error.localizedDescription];
    return dest;
}


#pragma mark - Search Commands

+ (NSString *)cmd_find:(NSArray *)args dir:(NSString *)directory {
    NSString *searchPath = directory;
    NSString *namePattern = nil;
    NSString *typeFilter = nil;  // "f" for files, "d" for directories
    NSInteger maxDepth = 10;

    for (NSUInteger i = 0; i < args.count; i++) {
        if ([args[i] isEqualToString:@"-name"] && i + 1 < args.count) {
            namePattern = args[++i];
        } else if ([args[i] isEqualToString:@"-type"] && i + 1 < args.count) {
            typeFilter = args[++i];
        } else if ([args[i] isEqualToString:@"-maxdepth"] && i + 1 < args.count) {
            maxDepth = [args[++i] integerValue];
        } else if (![args[i] hasPrefix:@"-"]) {
            searchPath = resolvePath(args[i], directory);
        }
    }

    // Convert glob pattern to regex
    NSString *regexPattern = nil;
    if (namePattern) {
        NSString *escaped = [NSRegularExpression escapedPatternForString:namePattern];
        // Convert glob wildcards back to regex
        escaped = [escaped stringByReplacingOccurrencesOfString:@"\\*" withString:@".*"];
        escaped = [escaped stringByReplacingOccurrencesOfString:@"\\?" withString:@"."];
        regexPattern = [NSString stringWithFormat:@"^%@$", escaped];
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:searchPath];
    NSMutableString *result = [NSMutableString string];
    NSString *relativePath;
    NSUInteger count = 0;

    while ((relativePath = [enumerator nextObject]) && result.length < MAX_OUTPUT_SIZE) {
        // Check depth
        NSUInteger depth = [[relativePath componentsSeparatedByString:@"/"] count];
        if ((NSInteger)depth > maxDepth) {
            [enumerator skipDescendants];
            continue;
        }

        NSString *fullPath = [searchPath stringByAppendingPathComponent:relativePath];
        BOOL isDir = NO;
        [fm fileExistsAtPath:fullPath isDirectory:&isDir];

        // Type filter
        if (typeFilter) {
            if ([typeFilter isEqualToString:@"f"] && isDir) continue;
            if ([typeFilter isEqualToString:@"d"] && !isDir) continue;
        }

        // Name filter
        if (regexPattern) {
            NSString *name = [relativePath lastPathComponent];
            NSRange range = [name rangeOfString:regexPattern
                                        options:NSRegularExpressionSearch | NSCaseInsensitiveSearch];
            if (range.location == NSNotFound) continue;
        }

        [result appendFormat:@"%@/%@\n", searchPath, relativePath];
        count++;
    }

    [result appendFormat:@"\n(%lu results)", (unsigned long)count];
    return result;
}

+ (NSString *)cmd_grep:(NSArray *)args dir:(NSString *)directory {
    BOOL caseInsensitive = NO;
    BOOL recursive = NO;
    BOOL lineNumbers = YES;
    NSString *pattern = nil;
    NSString *targetPath = nil;

    for (NSUInteger i = 0; i < args.count; i++) {
        if ([args[i] isEqualToString:@"-i"]) caseInsensitive = YES;
        else if ([args[i] isEqualToString:@"-r"]) recursive = YES;
        else if ([args[i] isEqualToString:@"-n"]) lineNumbers = YES;
        else if (!pattern) pattern = args[i];
        else if (!targetPath) targetPath = args[i];
    }

    if (!pattern || !targetPath) return @"Usage: grep [-i] [-r] <pattern> <file|dir>";
    targetPath = resolvePath(targetPath, directory);

    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    [fm fileExistsAtPath:targetPath isDirectory:&isDir];

    NSMutableArray *files = [NSMutableArray array];
    if (isDir && recursive) {
        NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:targetPath];
        NSString *file;
        while ((file = [enumerator nextObject])) {
            NSString *full = [targetPath stringByAppendingPathComponent:file];
            BOOL subIsDir = NO;
            [fm fileExistsAtPath:full isDirectory:&subIsDir];
            if (!subIsDir) [files addObject:full];
        }
    } else if (!isDir) {
        [files addObject:targetPath];
    } else {
        return @"grep: is a directory (use -r for recursive search)";
    }

    NSStringCompareOptions options = NSRegularExpressionSearch;
    if (caseInsensitive) options |= NSCaseInsensitiveSearch;

    NSMutableString *result = [NSMutableString string];
    NSUInteger matchCount = 0;

    for (NSString *filePath in files) {
        if (result.length > MAX_OUTPUT_SIZE) break;

        NSString *content = [NSString stringWithContentsOfFile:filePath
                                                      encoding:NSUTF8StringEncoding error:nil];
        if (!content) continue;

        NSArray *lines = [content componentsSeparatedByString:@"\n"];
        for (NSUInteger lineNum = 0; lineNum < lines.count; lineNum++) {
            NSString *line = lines[lineNum];
            NSRange range = [line rangeOfString:pattern options:options];
            if (range.location != NSNotFound) {
                if (files.count > 1) {
                    [result appendFormat:@"%@:", [filePath lastPathComponent]];
                }
                if (lineNumbers) {
                    [result appendFormat:@"%lu:", (unsigned long)(lineNum + 1)];
                }
                [result appendFormat:@"%@\n", line];
                matchCount++;
            }
        }
    }

    if (matchCount == 0) return @"(no matches)";
    [result appendFormat:@"\n(%lu matches)", (unsigned long)matchCount];
    return result;
}


#pragma mark - System Info Commands

+ (NSString *)cmd_id {
    uid_t uid = getuid();
    gid_t gid = getgid();
    uid_t euid = geteuid();
    gid_t egid = getegid();

    NSMutableString *result = [NSMutableString string];
    [result appendFormat:@"uid=%d", uid];

    struct passwd *pw = getpwuid(uid);
    if (pw) [result appendFormat:@"(%s)", pw->pw_name];

    [result appendFormat:@" gid=%d", gid];

    struct group *gr = getgrgid(gid);
    if (gr) [result appendFormat:@"(%s)", gr->gr_name];

    if (euid != uid) [result appendFormat:@" euid=%d", euid];
    if (egid != gid) [result appendFormat:@" egid=%d", egid];

    return result;
}

+ (NSString *)cmd_uname:(NSArray *)args {
    struct utsname sys;
    uname(&sys);

    BOOL all = [args containsObject:@"-a"];

    if (all) {
        return [NSString stringWithFormat:@"%s %s %s %s %s",
                sys.sysname, sys.nodename, sys.release, sys.version, sys.machine];
    }

    return [NSString stringWithFormat:@"%s %s %s %s",
            sys.sysname, sys.nodename, sys.release, sys.machine];
}

+ (NSString *)cmd_env:(NSArray *)args {
    NSDictionary *env = [[NSProcessInfo processInfo] environment];

    if (args.count > 0) {
        // Print specific variable
        NSString *value = env[args[0]];
        return value ?: [NSString stringWithFormat:@"%@: not set", args[0]];
    }

    NSMutableString *result = [NSMutableString string];
    NSArray *sortedKeys = [env.allKeys sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *key in sortedKeys) {
        [result appendFormat:@"%@=%@\n", key, env[key]];
    }
    return result;
}

+ (NSString *)cmd_df:(NSString *)directory {
    NSError *error;
    NSDictionary *attrs = [[NSFileManager defaultManager]
        attributesOfFileSystemForPath:directory error:&error];
    if (!attrs) return [NSString stringWithFormat:@"df: %@", error.localizedDescription];

    unsigned long long total = [attrs[NSFileSystemSize] unsignedLongLongValue];
    unsigned long long free_space = [attrs[NSFileSystemFreeSize] unsignedLongLongValue];
    unsigned long long used = total - free_space;
    double usedPercent = (total > 0) ? (double)used / total * 100.0 : 0;

    NSMutableString *result = [NSMutableString string];
    [result appendFormat:@"Filesystem  Size       Used       Free       Use%%\n"];
    [result appendFormat:@"/           %-10s %-10s %-10s %.0f%%\n",
        [formatFileSize(total) UTF8String],
        [formatFileSize(used) UTF8String],
        [formatFileSize(free_space) UTF8String],
        usedPercent];
    [result appendFormat:@"\nNodes: %@", attrs[NSFileSystemNodes]];
    [result appendFormat:@"\nFree nodes: %@", attrs[NSFileSystemFreeNodes]];
    return result;
}

+ (NSString *)cmd_uptime {
    NSTimeInterval uptime = [[NSProcessInfo processInfo] systemUptime];
    NSInteger days = (NSInteger)(uptime / 86400);
    NSInteger hours = (NSInteger)((uptime - days * 86400) / 3600);
    NSInteger mins = (NSInteger)((uptime - days * 86400 - hours * 3600) / 60);

    return [NSString stringWithFormat:@"up %ld days, %ld:%02ld", (long)days, (long)hours, (long)mins];
}

+ (NSString *)cmd_bundle {
    NSBundle *mainBundle = [NSBundle mainBundle];
    NSDictionary *info = mainBundle.infoDictionary;

    NSMutableString *result = [NSMutableString string];
    [result appendFormat:@"Bundle ID:    %@\n", mainBundle.bundleIdentifier ?: @"N/A"];
    [result appendFormat:@"Display Name: %@\n",
        info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"] ?: @"N/A"];
    [result appendFormat:@"Version:      %@ (%@)\n",
        info[@"CFBundleShortVersionString"] ?: @"N/A",
        info[@"CFBundleVersion"] ?: @"N/A"];
    [result appendFormat:@"Executable:   %@\n", info[@"CFBundleExecutable"] ?: @"N/A"];
    [result appendFormat:@"Bundle Path:  %@\n", mainBundle.bundlePath];
    [result appendFormat:@"Min iOS:      %@\n", info[@"MinimumOSVersion"] ?: @"N/A"];
    [result appendFormat:@"SDK:          %@\n", info[@"DTSDKName"] ?: @"N/A"];
    [result appendFormat:@"Platform:     %@\n", info[@"DTPlatformName"] ?: @"N/A"];

    // List URL schemes
    NSArray *urlTypes = info[@"CFBundleURLTypes"];
    if (urlTypes.count > 0) {
        [result appendString:@"URL Schemes:  "];
        for (NSDictionary *urlType in urlTypes) {
            NSArray *schemes = urlType[@"CFBundleURLSchemes"];
            [result appendString:[schemes componentsJoinedByString:@", "]];
        }
        [result appendString:@"\n"];
    }

    // Transport security
    NSDictionary *ats = info[@"NSAppTransportSecurity"];
    if (ats) {
        BOOL allowsArbitrary = [ats[@"NSAllowsArbitraryLoads"] boolValue];
        [result appendFormat:@"ATS:          %@\n",
            allowsArbitrary ? @"Allows arbitrary loads" : @"Restricted"];
    }

    return result;
}

+ (NSString *)cmd_sandbox {
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"=== Sandbox Container Paths ===\n\n"];

    [result appendFormat:@"Home:        %@\n", NSHomeDirectory()];
    [result appendFormat:@"Tmp:         %@\n", NSTemporaryDirectory()];
    [result appendFormat:@"Bundle:      %@\n", [[NSBundle mainBundle] bundlePath]];

    // Standard directories
    NSArray *searchPaths = @[
        @[@(NSDocumentDirectory), @"Documents"],
        @[@(NSLibraryDirectory), @"Library"],
        @[@(NSCachesDirectory), @"Caches"],
        @[@(NSApplicationSupportDirectory), @"App Support"],
    ];

    for (NSArray *item in searchPaths) {
        NSSearchPathDirectory dir = (NSSearchPathDirectory)[item[0] integerValue];
        NSArray *paths = NSSearchPathForDirectoriesInDomains(dir, NSUserDomainMask, YES);
        if (paths.count > 0) {
            [result appendFormat:@"%-12s %@\n", [item[1] UTF8String], paths[0]];
        }
    }

    // Check what's accessible
    [result appendString:@"\n=== Access Test ===\n"];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *testPaths = @[
        NSHomeDirectory(),
        NSTemporaryDirectory(),
        @"/var/mobile",
        @"/var/root",
        @"/etc",
        @"/usr",
        @"/private/var",
        @"/System",
    ];

    for (NSString *path in testPaths) {
        BOOL readable = [fm isReadableFileAtPath:path];
        BOOL writable = [fm isWritableFileAtPath:path];
        [result appendFormat:@"  %@ %@ %@\n",
            readable ? @"R" : @"-",
            writable ? @"W" : @"-",
            path];
    }

    return result;
}

+ (NSString *)cmd_sysinfo {
    NSMutableString *result = [NSMutableString string];

    // Device model
    struct utsname sys;
    uname(&sys);
    [result appendFormat:@"Machine:     %s\n", sys.machine];
    [result appendFormat:@"System:      %s %s\n", sys.sysname, sys.release];

    // iOS version
    NSProcessInfo *procInfo = [NSProcessInfo processInfo];
    NSOperatingSystemVersion ver = procInfo.operatingSystemVersion;
    [result appendFormat:@"iOS:         %ld.%ld.%ld\n",
        (long)ver.majorVersion, (long)ver.minorVersion, (long)ver.patchVersion];
    [result appendFormat:@"Process:     %@\n", procInfo.processName];
    [result appendFormat:@"PID:         %d\n", procInfo.processIdentifier];
    [result appendFormat:@"Host:        %@\n", procInfo.hostName];

    // CPU count
    [result appendFormat:@"CPUs:        %lu (active: %lu)\n",
        (unsigned long)procInfo.processorCount,
        (unsigned long)procInfo.activeProcessorCount];

    // RAM
    [result appendFormat:@"Physical RAM: %@\n", formatFileSize(procInfo.physicalMemory)];

    // Thermal state
    NSString *thermal;
    switch (procInfo.thermalState) {
        case NSProcessInfoThermalStateNominal:  thermal = @"Nominal"; break;
        case NSProcessInfoThermalStateFair:     thermal = @"Fair"; break;
        case NSProcessInfoThermalStateSerious:  thermal = @"Serious"; break;
        case NSProcessInfoThermalStateCritical: thermal = @"Critical"; break;
        default: thermal = @"Unknown";
    }
    [result appendFormat:@"Thermal:     %@\n", thermal];

    // Low power mode
    if ([procInfo respondsToSelector:@selector(isLowPowerModeEnabled)]) {
        [result appendFormat:@"Low Power:   %@\n",
            procInfo.lowPowerModeEnabled ? @"YES" : @"NO"];
    }

    return result;
}

+ (NSString *)cmd_memory {
    struct mach_task_basic_info info;
    mach_msg_type_number_t size = MACH_TASK_BASIC_INFO_COUNT;
    kern_return_t kerr = task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                                   (task_info_t)&info, &size);

    if (kerr != KERN_SUCCESS) {
        return @"memory: cannot read task info";
    }

    NSMutableString *result = [NSMutableString string];
    [result appendFormat:@"Resident:     %@\n", formatFileSize(info.resident_size)];
    [result appendFormat:@"Virtual:      %@\n", formatFileSize(info.virtual_size)];
    [result appendFormat:@"Resident max: %@\n", formatFileSize(info.resident_size_max)];

    // System-wide memory
    NSProcessInfo *procInfo = [NSProcessInfo processInfo];
    [result appendFormat:@"\nSystem RAM:   %@\n", formatFileSize(procInfo.physicalMemory)];

    return result;
}


#pragma mark - Transfer Commands

+ (NSString *)cmd_scp:(NSArray *)args dir:(NSString *)directory {
    if (args.count < 2) {
        return @"Usage: scp [-r] <source> <destination>\n"
               @"       scp -r <path> host:./output";
    }

    BOOL recursive = NO;
    NSString *source = nil;
    NSString *destination = nil;

    for (NSString *arg in args) {
        if ([arg isEqualToString:@"-r"]) {
            recursive = YES;
        } else if (!source) {
            source = arg;
        } else {
            destination = arg;
        }
    }

    if (!source || !destination) {
        return @"Usage: scp [-r] <source> <destination>";
    }

    // Download to host
    if ([destination hasPrefix:@"host:"]) {
        if (!recursive) return @"Error: host download requires -r flag";
        NSString *hostPath = [destination substringFromIndex:5];
        NSString *fullSource = resolvePath(source, directory);
        return [self encodeForDownload:fullSource toHostPath:hostPath];
    }

    // Local copy
    return [self cmd_cp:@[source, destination] dir:directory];
}

+ (NSString *)cmd_download:(NSArray *)args dir:(NSString *)directory {
    if (args.count == 0) return @"Usage: download <path> [host_destination]";

    NSString *source = args[0];
    NSString *hostPath = args.count > 1 ? args[1] : @"./download";
    NSString *fullSource = resolvePath(source, directory);

    return [self encodeForDownload:fullSource toHostPath:hostPath];
}

+ (NSString *)encodeForDownload:(NSString *)srcPath toHostPath:(NSString *)hostPath {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;

    if (![fm fileExistsAtPath:srcPath isDirectory:&isDir]) {
        return @"Error: source path does not exist";
    }

    NSMutableString *result = [NSMutableString stringWithFormat:@"SCP:%@;", hostPath];

    if (isDir) {
        [self addFilesFromDirectory:srcPath toResult:result
                           basePath:srcPath hostBasePath:hostPath];
    } else {
        // Single file download
        NSData *data = [NSData dataWithContentsOfFile:srcPath];
        if (data) {
            NSString *b64 = [data base64EncodedStringWithOptions:0];
            NSString *fileName = [srcPath lastPathComponent];
            [result appendFormat:@"FILE;%@;%@\n", fileName, b64];
        } else {
            return @"Error: cannot read file";
        }
    }

    return result;
}

+ (void)addFilesFromDirectory:(NSString *)currentPath toResult:(NSMutableString *)result
                     basePath:(NSString *)basePath hostBasePath:(NSString *)hostBasePath {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *contents = [fm contentsOfDirectoryAtPath:currentPath error:nil];
    if (!contents) return;

    for (NSString *item in contents) {
        if (result.length > MAX_OUTPUT_SIZE) return;
        if ([item hasPrefix:@"."]) continue;

        NSString *fullPath = [currentPath stringByAppendingPathComponent:item];
        BOOL isDir = NO;
        [fm fileExistsAtPath:fullPath isDirectory:&isDir];

        if (isDir) {
            [self addFilesFromDirectory:fullPath toResult:result
                               basePath:basePath hostBasePath:hostBasePath];
        } else {
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
                NSString *relativePath = [fullPath substringFromIndex:[basePath length] + 1];
                [result appendFormat:@"FILE;%@;%@\n", relativePath, b64Data];
            }
        }
    }
}


#pragma mark - Keychain Commands

+ (NSString *)cmd_keychain:(NSArray *)args {
    // Parse subcommand and options
    // Usage:
    //   keychain dump                    — all accessible items
    //   keychain dump --class generic    — GenericPassword only
    //   keychain dump --class internet   — InternetPassword only
    //   keychain dump --class cert       — Certificates
    //   keychain dump --class key        — Crypto keys
    //   keychain groups                  — list known access groups from env

    NSString *subcmd = args.count > 0 ? [args[0] lowercaseString] : @"dump";

    if ([subcmd isEqualToString:@"groups"]) {
        return [self keychain_groups];
    }

    // Determine which classes to dump
    NSArray *classFilter = nil;
    for (NSUInteger i = 0; i < args.count; i++) {
        if ([args[i] isEqualToString:@"--class"] && i + 1 < args.count) {
            NSString *cls = [args[i + 1] lowercaseString];
            if ([cls isEqualToString:@"generic"])  classFilter = @[(__bridge id)kSecClassGenericPassword];
            else if ([cls isEqualToString:@"internet"]) classFilter = @[(__bridge id)kSecClassInternetPassword];
            else if ([cls isEqualToString:@"cert"])    classFilter = @[(__bridge id)kSecClassCertificate];
            else if ([cls isEqualToString:@"key"])     classFilter = @[(__bridge id)kSecClassKey];
            else return [NSString stringWithFormat:@"keychain: unknown class '%@'\nUse: generic, internet, cert, key", args[i+1]];
            break;
        }
    }

    if (!classFilter) {
        classFilter = @[
            (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecClassInternetPassword,
            (__bridge id)kSecClassCertificate,
            (__bridge id)kSecClassKey,
        ];
    }

    NSMutableString *output = [NSMutableString string];
    NSInteger totalItems = 0;

    NSDictionary *classNames = @{
        (__bridge id)kSecClassGenericPassword:  @"GenericPassword",
        (__bridge id)kSecClassInternetPassword: @"InternetPassword",
        (__bridge id)kSecClassCertificate:       @"Certificate",
        (__bridge id)kSecClassKey:               @"Key",
    };

    for (id secClass in classFilter) {
        NSString *className = classNames[secClass] ?: @"Unknown";

        NSMutableDictionary *query = [NSMutableDictionary dictionary];
        query[(__bridge id)kSecClass]            = secClass;
        query[(__bridge id)kSecMatchLimit]       = (__bridge id)kSecMatchLimitAll;
        query[(__bridge id)kSecReturnAttributes] = @YES;
        query[(__bridge id)kSecReturnData]       = @YES;

        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

        if (status == errSecItemNotFound) continue;

        if (status != errSecSuccess) {
            [output appendFormat:@"[%@] SecItemCopyMatching error: %d\n", className, (int)status];
            continue;
        }

        NSArray *items = (__bridge_transfer NSArray *)result;
        if (!items || items.count == 0) continue;

        [output appendFormat:@"\n═══ %@ (%lu items) ═══\n", className, (unsigned long)items.count];
        totalItems += items.count;

        NSInteger idx = 0;
        for (NSDictionary *item in items) {
            if (output.length > MAX_OUTPUT_SIZE - 4096) {
                [output appendString:@"\n[... output truncated — use --class to filter ...]\n"];
                break;
            }

            [output appendFormat:@"\n  [%ld]\n", (long)idx++];

            // Account / service
            NSString *account = item[(__bridge id)kSecAttrAccount];
            NSString *service = item[(__bridge id)kSecAttrService];
            NSString *label   = item[(__bridge id)kSecAttrLabel];
            NSString *server  = item[(__bridge id)kSecAttrServer];
            NSString *group   = item[(__bridge id)kSecAttrAccessGroup];
            id creationDate   = item[(__bridge id)kSecAttrCreationDate];
            id modDate        = item[(__bridge id)kSecAttrModificationDate];
            NSString *comment = item[(__bridge id)kSecAttrComment];
            NSString *description = item[(__bridge id)kSecAttrDescription];

            if (label.length)       [output appendFormat:@"    label:        %@\n", label];
            if (account.length)     [output appendFormat:@"    account:      %@\n", account];
            if (service.length)     [output appendFormat:@"    service:      %@\n", service];
            if (server.length)      [output appendFormat:@"    server:       %@\n", server];
            if (group.length)       [output appendFormat:@"    access_group: %@\n", group];
            if (description.length) [output appendFormat:@"    description:  %@\n", description];
            if (comment.length)     [output appendFormat:@"    comment:      %@\n", comment];
            if (creationDate)       [output appendFormat:@"    created:      %@\n", creationDate];
            if (modDate)            [output appendFormat:@"    modified:     %@\n", modDate];

            // Decode value
            NSData *valueData = item[(__bridge id)kSecValueData];
            if (valueData && valueData.length > 0) {
                // Try UTF-8 string first
                NSString *strVal = [[NSString alloc] initWithData:valueData encoding:NSUTF8StringEncoding];
                if (strVal) {
                    // Truncate very long values
                    if (strVal.length > 512) {
                        strVal = [[strVal substringToIndex:512] stringByAppendingString:@"...(truncated)"];
                    }
                    [output appendFormat:@"    value:        %@\n", strVal];
                } else {
                    // Binary data — hex dump first 64 bytes
                    NSUInteger dumpLen = MIN(valueData.length, 64);
                    const uint8_t *bytes = (const uint8_t *)valueData.bytes;
                    NSMutableString *hex = [NSMutableString string];
                    for (NSUInteger i = 0; i < dumpLen; i++) {
                        [hex appendFormat:@"%02x ", bytes[i]];
                    }
                    if (valueData.length > dumpLen) [hex appendString:@"..."];
                    [output appendFormat:@"    value (hex):  %@\n", hex];
                    [output appendFormat:@"    value (b64):  %@\n",
                        [valueData base64EncodedStringWithOptions:0]];
                }
            } else {
                [output appendString:@"    value:        <not accessible or empty>\n"];
            }
        }
    }

    if (totalItems == 0) {
        return @"keychain: no accessible items found\n"
               @"Note: only items in the app's access groups are readable.\n"
               @"Use 'keychain groups' to see what groups this app has access to.";
    }

    NSString *header = [NSString stringWithFormat:
        @"Keychain Dump — %ld item(s) found\n"
        @"Access limited to this app's entitlement groups (re-sign with --jailbreak to expand)\n",
        (long)totalItems];

    return [header stringByAppendingString:output];
}

+ (NSString *)keychain_groups {
    // Check what access groups this process has by reading the task_info / environment
    // The access group is derivable from the bundle ID and team ID in provisioning profile
    NSBundle *main = [NSBundle mainBundle];
    NSString *bundleID = main.bundleIdentifier ?: @"unknown";

    NSMutableString *out = [NSMutableString string];
    [out appendString:@"Keychain Access Groups for this process:\n\n"];

    // Probe by attempting a query with kSecAttrAccessGroup = * (returns error -25243 if not entitled)
    // Instead, enumerate items and collect unique groups seen
    NSArray *classes = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
    ];
    NSMutableSet *seenGroups = [NSMutableSet set];

    for (id secClass in classes) {
        NSMutableDictionary *query = [NSMutableDictionary dictionary];
        query[(__bridge id)kSecClass]            = secClass;
        query[(__bridge id)kSecMatchLimit]       = (__bridge id)kSecMatchLimitAll;
        query[(__bridge id)kSecReturnAttributes] = @YES;

        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (status == errSecSuccess && result) {
            NSArray *items = (__bridge_transfer NSArray *)result;
            for (NSDictionary *item in items) {
                NSString *grp = item[(__bridge id)kSecAttrAccessGroup];
                if (grp) [seenGroups addObject:grp];
            }
        }
    }

    [out appendFormat:@"  Bundle ID:    %@\n", bundleID];
    [out appendString:@"  Seen access groups in readable items:\n"];
    if (seenGroups.count == 0) {
        [out appendString:@"    (none — no readable items yet)\n"];
    } else {
        for (NSString *g in [seenGroups allObjects]) {
            [out appendFormat:@"    %@\n", g];
        }
    }

    [out appendString:
        @"\nNote: to dump items from OTHER app's groups on jailbreak,\n"
        @"re-patch with --jailbreak flag (adds original keychain-access-groups to entitlements)\n"];

    return out;
}

#pragma mark - Other Commands

+ (NSString *)cmd_echo:(NSArray *)args {
    return [args componentsJoinedByString:@" "];
}

+ (NSString *)cmd_version {
    return @"iOS Sandbox Explorer v2.0\n"
           @"Shell server with built-in commands\n"
           @"Compatible: iOS 14-26 (no popen/shell dependency)";
}

+ (NSString *)cmd_help {
    return
    @"=== iOS Sandbox Explorer — Available Commands ===\n"
    @"\n"
    @"NAVIGATION:\n"
    @"  ls [-la] [path]        List directory contents\n"
    @"  cd <path>              Change directory\n"
    @"  pwd                    Print working directory\n"
    @"  tree [path] [-d N]     Directory tree (max depth N)\n"
    @"\n"
    @"FILE READING:\n"
    @"  cat <file>             Print file contents\n"
    @"  head [-n N] <file>     First N lines (default 10)\n"
    @"  tail [-n N] <file>     Last N lines (default 10)\n"
    @"  hexdump [-n N] <file>  Hex dump (N bytes, default 256)\n"
    @"  strings [-n N] <file>  Printable strings (min length N)\n"
    @"  base64 <file>          Base64 encode file\n"
    @"\n"
    @"FILE OPERATIONS:\n"
    @"  cp <src> <dst>         Copy file\n"
    @"  mv <src> <dst>         Move/rename file\n"
    @"  rm [-r] <path>         Remove file or directory\n"
    @"  mkdir [-p] <path>      Create directory\n"
    @"  touch <file>           Create file / update timestamp\n"
    @"  chmod <mode> <path>    Change permissions (octal)\n"
    @"\n"
    @"FILE INFO:\n"
    @"  stat <path>            Detailed file information\n"
    @"  file <path>            Detect file type (magic bytes)\n"
    @"  md5 <file>             MD5 checksum\n"
    @"  sha256 <file>          SHA-256 checksum\n"
    @"  wc <file>              Line/word/byte count\n"
    @"  du [-s] [path]         Disk usage\n"
    @"  realpath <path>        Resolve to absolute path\n"
    @"  readlink <path>        Read symlink target\n"
    @"\n"
    @"SEARCH:\n"
    @"  find <path> [-name pattern] [-type f|d] [-maxdepth N]\n"
    @"  grep [-i] [-r] <pattern> <file|dir>\n"
    @"\n"
    @"SYSTEM INFO:\n"
    @"  id                     User/group IDs\n"
    @"  uname [-a]             System information\n"
    @"  whoami                 Current user name\n"
    @"  env [VARNAME]          Environment variables\n"
    @"  date                   Current date/time\n"
    @"  df                     Disk space\n"
    @"  uptime                 System uptime\n"
    @"  bundle                 App bundle info\n"
    @"  sandbox                Sandbox container paths + access test\n"
    @"  sysinfo                Device & iOS version details\n"
    @"  memory                 Process memory usage\n"
    @"\n"
    @"KEYCHAIN:\n"
    @"  keychain dump              Dump all accessible keychain items\n"
    @"  keychain dump --class X    Filter: generic|internet|cert|key\n"
    @"  keychain groups            Show this app's keychain access groups\n"
    @"\n"
    @"TRANSFER:\n"
    @"  scp -r <src> host:<dst>  Download directory to host\n"
    @"  download <path> [dst]    Download file or directory\n"
    @"\n"
    @"OTHER:\n"
    @"  echo <text>            Echo text\n"
    @"  help                   Show this help\n"
    @"  version                Show version info\n";
}

@end
