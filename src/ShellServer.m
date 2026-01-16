// ShellServer.m
#import "ShellServer.h"
#import "ShellCommands.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>

@interface ShellServer ()

@property (nonatomic, assign) int serverSocket;
@property (nonatomic, assign) BOOL isRunning;
@property (nonatomic, strong) NSString *currentDirectory;

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
        self.currentDirectory = NSHomeDirectory();
    }
    return self;
}

- (void)startServerOnPort:(NSUInteger)port {
    if (self.isRunning) return;
    
    self.serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (self.serverSocket < 0) {
        return;
    }
    
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(port);
    
    if (bind(self.serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        close(self.serverSocket);
        return;
    }
    
    if (listen(self.serverSocket, 5) < 0) {
        close(self.serverSocket);
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
    char buffer[1024];
    ssize_t bytesRead;
    
    NSLog(@"New client connected");
    
    bytesRead = read(clientSocket, buffer, sizeof(buffer) - 1);
    if (bytesRead > 0) {
        buffer[bytesRead] = '\0';
        NSString *command = [NSString stringWithUTF8String:buffer];
        command = [command stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        
        NSLog(@"Received command: %@", command);
        
        NSString *response = [ShellCommands executeCommand:command inDirectory:self.currentDirectory];
        
        if ([command hasPrefix:@"cd "]) {
            NSArray *parts = [command componentsSeparatedByString:@" "];
            if (parts.count > 1) {
                NSString *newDir = parts[1];
                NSString *fullPath = [self.currentDirectory stringByAppendingPathComponent:newDir];
                if ([[NSFileManager defaultManager] fileExistsAtPath:fullPath]) {
                    self.currentDirectory = fullPath;
                    response = [NSString stringWithFormat:@"Changed directory to %@", self.currentDirectory];
                } else {
                    response = @"Directory not found";
                }
            }
        }
        
        write(clientSocket, [response UTF8String], [response length]);
        NSLog(@"Sent response: %@", response);
    }
    
    close(clientSocket);
    NSLog(@"Client disconnected");
}

- (void)stopServer {
    self.isRunning = NO;
    close(self.serverSocket);
}

@end