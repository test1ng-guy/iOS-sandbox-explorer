// ShellServer.m — TCP server for remote command execution
// Binds to 127.0.0.1 (loopback only) for security
// Compatible with iOS 14–26 sandbox

#import "ShellServer.h"
#import "ShellCommands.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <errno.h>

@interface ShellServer ()

@property (nonatomic, assign) int serverSocket;
@property (nonatomic, assign) BOOL isRunning;
@property (nonatomic, strong) NSString *currentDirectory;
@property (nonatomic, strong) dispatch_queue_t stateQueue;

@end

@implementation ShellServer

+ (instancetype)sharedInstance {
    static ShellServer *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _serverSocket = -1;
        _isRunning = NO;
        _currentDirectory = NSHomeDirectory();
        _stateQueue = dispatch_queue_create("com.sandboxexplorer.shellserver.state",
                                           DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)startServerOnPort:(NSUInteger)port {
    if (self.isRunning) return;

    self.serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (self.serverSocket < 0) {
        NSLog(@"[ShellServer] socket() failed: %s (errno=%d)", strerror(errno), errno);
        self.serverSocket = -1;
        return;
    }

    // Allow port reuse — prevents "Address already in use" after restart
    int optval = 1;
    setsockopt(self.serverSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");  // Loopback only — safe in sandbox
    serverAddr.sin_port = htons(port);

    if (bind(self.serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        NSLog(@"[ShellServer] bind() failed on port %lu: %s (errno=%d)",
              (unsigned long)port, strerror(errno), errno);
        close(self.serverSocket);
        self.serverSocket = -1;
        return;
    }

    if (listen(self.serverSocket, 5) < 0) {
        NSLog(@"[ShellServer] listen() failed: %s (errno=%d)", strerror(errno), errno);
        close(self.serverSocket);
        self.serverSocket = -1;
        return;
    }

    self.isRunning = YES;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self acceptConnections];
    });

    NSLog(@"Server started on port %lu", (unsigned long)port);
}

- (void)acceptConnections {
    while (self.isRunning) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSocket = accept(self.serverSocket, (struct sockaddr *)&clientAddr, &clientLen);
        if (clientSocket < 0) continue;

        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [self handleClient:clientSocket];
        });
    }
}

- (void)handleClient:(int)clientSocket {
    char buffer[4096];
    ssize_t bytesRead;

    NSLog(@"[ShellServer] Client connected");

    // Read command (accumulate until newline or EOF)
    NSMutableData *commandData = [NSMutableData data];
    while ((bytesRead = read(clientSocket, buffer, sizeof(buffer) - 1)) > 0) {
        [commandData appendBytes:buffer length:bytesRead];
        // Stop at newline
        if (memchr(buffer, '\n', bytesRead)) break;
    }

    if (commandData.length == 0) {
        close(clientSocket);
        return;
    }

    NSString *command = [[NSString alloc] initWithData:commandData encoding:NSUTF8StringEncoding];
    command = [command stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

    NSLog(@"[ShellServer] Command: %@", command);

    NSString *response = [self responseForCommand:command];

    // Send response
    const char *responseBytes = [response UTF8String];
    NSUInteger responseLen = [response lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    NSUInteger totalWritten = 0;

    while (totalWritten < responseLen) {
        ssize_t written = write(clientSocket, responseBytes + totalWritten,
                                responseLen - totalWritten);
        if (written < 0) {
            NSLog(@"[ShellServer] write() error: %s", strerror(errno));
            break;
        }
        totalWritten += written;
    }

    close(clientSocket);
    NSLog(@"[ShellServer] Response sent (%lu bytes)", (unsigned long)totalWritten);
}

/// Serialize cwd mutations; snapshot cwd for other commands so long work does not hold the lock.
- (NSString *)responseForCommand:(NSString *)command {
    if ([command isEqualToString:@"cd"] || [command isEqualToString:@"cd ~"]) {
        __block NSString *response = nil;
        dispatch_sync(self.stateQueue, ^{
            self.currentDirectory = NSHomeDirectory();
            response = [NSString stringWithFormat:@"Changed directory to %@", self.currentDirectory];
        });
        return response;
    }

    if ([command hasPrefix:@"cd "]) {
        __block NSString *response = nil;
        dispatch_sync(self.stateQueue, ^{
            NSString *target = [command substringFromIndex:3];
            target = [target stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

            NSString *fullPath;
            if ([target hasPrefix:@"/"]) {
                fullPath = target;
            } else if ([target hasPrefix:@"~"]) {
                fullPath = [NSHomeDirectory() stringByAppendingPathComponent:[target substringFromIndex:1]];
            } else if ([target isEqualToString:@".."]) {
                fullPath = [self.currentDirectory stringByDeletingLastPathComponent];
            } else if ([target hasPrefix:@"../"]) {
                fullPath = [[self.currentDirectory stringByDeletingLastPathComponent]
                            stringByAppendingPathComponent:[target substringFromIndex:3]];
            } else {
                fullPath = [self.currentDirectory stringByAppendingPathComponent:target];
            }

            fullPath = [fullPath stringByStandardizingPath];

            BOOL isDir = NO;
            if ([[NSFileManager defaultManager] fileExistsAtPath:fullPath isDirectory:&isDir] && isDir) {
                self.currentDirectory = fullPath;
                response = [NSString stringWithFormat:@"Changed directory to %@", self.currentDirectory];
            } else {
                response = [NSString stringWithFormat:@"cd: %@: No such directory", target];
            }
        });
        return response;
    }

    __block NSString *directory = nil;
    dispatch_sync(self.stateQueue, ^{
        directory = [self.currentDirectory copy];
    });
    return [ShellCommands executeCommand:command inDirectory:directory];
}

- (void)stopServer {
    self.isRunning = NO;
    if (self.serverSocket >= 0) {
        close(self.serverSocket);
        self.serverSocket = -1;
    }
    NSLog(@"[ShellServer] Server stopped");
}

@end
