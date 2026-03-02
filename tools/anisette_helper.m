/*
 * anisette_helper.m
 *
 * Native macOS anisette data generator.
 * Uses AOSKit.framework (AOSUtilities) and AuthKit.framework (AKDevice)
 * to generate X-Apple-I-MD (OTP) and X-Apple-I-MD-M (machine ID)
 * without Docker, without special entitlements, even with SIP enabled.
 *
 * Outputs JSON to stdout.
 *
 * Build:
 *   clang anisette_helper.m -o anisette_helper \
 *     -framework Foundation -fmodules -fobjc-arc
 *
 * Tested: macOS 26 (Tahoe), arm64
 */

@import Foundation;
#import <dlfcn.h>
#import <objc/message.h>

int main(void) {
    @autoreleasepool {
        // Load private frameworks
        void *h1 = dlopen("/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit", RTLD_NOW);
        void *h2 = dlopen("/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit", RTLD_NOW);

        if (!h1) {
            fprintf(stderr, "[anisette_helper] Error: failed to load AOSKit: %s\n", dlerror());
            return 1;
        }
        (void)h2;  // AuthKit loaded for AKDevice

        Class aosUtils = NSClassFromString(@"AOSUtilities");
        if (!aosUtils) {
            fprintf(stderr, "[anisette_helper] Error: AOSUtilities class not found\n");
            return 1;
        }

        // Typed objc_msgSend helpers
        typedef id (*MsgId )(id, SEL, id);
        typedef id (*MsgId0)(id, SEL);
        MsgId  send1 = (MsgId )objc_msgSend;
        MsgId0 send0 = (MsgId0)objc_msgSend;

        // [AOSUtilities retrieveOTPHeadersForDSID:@"-2"]
        SEL otpSel = NSSelectorFromString(@"retrieveOTPHeadersForDSID:");
        id otpRaw = send1((id)aosUtils, otpSel, @"-2");

        if (!otpRaw || ![otpRaw isKindOfClass:[NSDictionary class]]) {
            fprintf(stderr, "[anisette_helper] Error: retrieveOTPHeadersForDSID: returned nil/unexpected\n");
            return 1;
        }

        NSDictionary *otpDict = (NSDictionary *)otpRaw;
        NSMutableDictionary *out = [NSMutableDictionary dictionary];

        // Map X-Apple-MD → X-Apple-I-MD  and  X-Apple-MD-M → X-Apple-I-MD-M
        NSString *otp = otpDict[@"X-Apple-MD"];
        NSString *mid = otpDict[@"X-Apple-MD-M"];

        if (!otp || !mid) {
            fprintf(stderr, "[anisette_helper] Error: OTP dict missing keys: %s\n",
                    otpDict.description.UTF8String);
            return 1;
        }

        out[@"X-Apple-I-MD"]   = otp;
        out[@"X-Apple-I-MD-M"] = mid;

        // Get supplementary device info from AKDevice
        Class akDevice = NSClassFromString(@"AKDevice");
        if (akDevice) {
            id device = send0((id)akDevice, NSSelectorFromString(@"currentDevice"));
            if (device) {
                id lu  = send0(device, NSSelectorFromString(@"localUserUUID"));
                id uid = send0(device, NSSelectorFromString(@"uniqueDeviceIdentifier"));
                id sfd = send0(device, NSSelectorFromString(@"serverFriendlyDescription"));

                if (lu)  out[@"X-Apple-I-MD-LU"]      = lu;
                if (uid) out[@"X-Mme-Device-Id"]       = uid;
                if (sfd) out[@"X-Mme-Client-Info"]     = sfd;
            }
        }

        // Machine serial number
        id srl = send0((id)aosUtils, NSSelectorFromString(@"machineSerialNumber"));
        if (srl) out[@"X-Apple-SRL-NO"] = srl;

        // Serialize to JSON
        NSError *jsonErr = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:out
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&jsonErr];
        if (jsonErr || !json) {
            fprintf(stderr, "[anisette_helper] JSON error: %s\n",
                    jsonErr.localizedDescription.UTF8String);
            return 1;
        }

        fwrite(json.bytes, 1, json.length, stdout);
        printf("\n");
    }
    return 0;
}
