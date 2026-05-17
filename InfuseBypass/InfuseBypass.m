//
//  InfuseBypass.m — Infuse 8.4.3 tvOS Sideload Fix
//
//  IDA-traced streaming mode fix for MovieBox Pro:
//  - readHeadersAndFetchSizeForFile → 0 (passes >= 0 check)
//  - canUseByteSeek → NO (AVIO seekable = 0)
//  - length → -1 (AVSEEK_SIZE unknown)
//  - readBuffer:ofSize: → 0 at EOF (AVERROR_EOF)
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

// Thread-local streaming mode flag
static _Atomic BOOL g_streamingMode = NO;

// Original method pointers
static NSInteger (*orig_iapVersionStatus)(id, SEL);
static BOOL (*orig_isShareAvailable)(id, SEL, id);
static NSURL* (*orig_containerURL)(id, SEL, NSString*);
static id (*orig_defaultContainer)(id, SEL);
static id (*orig_containerWithId)(id, SEL, NSString*);
static long long (*orig_readHeaders)(id, SEL, void*);
static BOOL (*orig_canUseByteSeek)(id, SEL);
static long long (*orig_length)(id, SEL);

// Swizzle helpers
static void hookInst(Class c, SEL s, IMP new_imp, IMP *old) {
    Method m = class_getInstanceMethod(c, s);
    if (m) { *old = method_setImplementation(m, new_imp); }
}
static void hookClass(Class c, SEL s, IMP new_imp, IMP *old) {
    Method m = class_getClassMethod(c, s);
    if (m) { *old = method_setImplementation(m, new_imp); }
}

// === Hook 1: Pro status ===
static NSInteger h_iapVersionStatus(id self, SEL _cmd) { return 1; }

// === Hook 2: Reachability bypass ===
static BOOL h_isShareAvailable(id self, SEL _cmd, id share) { return YES; }

// === Hook 3: Container redirect ===
static NSURL* h_containerURL(id self, SEL _cmd, NSString *gid) {
    NSArray *p = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [[p firstObject] stringByAppendingPathComponent:@"AppGroup"];
    [[NSFileManager defaultManager] createDirectoryAtPath:path
                              withIntermediateDirectories:YES attributes:nil error:nil];
    return [NSURL fileURLWithPath:path];
}

// === Hook 4 & 5: CloudKit disable ===
static id h_defaultContainer(id self, SEL _cmd) { return nil; }
static id h_containerWithId(id self, SEL _cmd, NSString *i) { return nil; }

// === Hook 6: Content-Length fix ===
// Return 0 instead of -1 when Content-Length missing.
// Infuse only checks (result & 0x8000000000000000) == 0, so 0 passes.
// g_streamingMode signals other hooks to enable streaming behavior.
static long long h_readHeaders(id self, SEL _cmd, void *file) {
    if (!file) return -1;
    long long result = orig_readHeaders(self, _cmd, file);
    if (result < 0) {
        g_streamingMode = YES;
        return 1; // minimal positive value, passes any > 0 or >= 0 check
    }
    return result;
}

// === Hook 7: DISABLED - testing without seek control ===
static BOOL h_canUseByteSeek(id self, SEL _cmd) {
    return orig_canUseByteSeek(self, _cmd);
}

// === Hook 8: DISABLED - testing without length override ===
static long long h_length(id self, SEL _cmd) {
    return orig_length(self, _cmd);
}

__attribute__((constructor))
static void init(void) {
    Class c;

    // 1. IAP
    c = objc_getClass("_TtC6infuse31InAppPurchaseServiceFreemiumSK2");
    if (c) hookInst(c, NSSelectorFromString(@"iapVersionStatus"), (IMP)h_iapVersionStatus, (IMP*)&orig_iapVersionStatus);

    // 2. Reachability
    c = objc_getClass("_TtC6infuse32DefaultSharesReachabilityManager");
    if (c) hookInst(c, NSSelectorFromString(@"isShareAvailable:"), (IMP)h_isShareAvailable, (IMP*)&orig_isShareAvailable);

    // 3. Container
    c = objc_getClass("NSFileManager");
    hookInst(c, @selector(containerURLForSecurityApplicationGroupIdentifier:), (IMP)h_containerURL, (IMP*)&orig_containerURL);

    // 4 & 5. CloudKit
    c = objc_getClass("CKContainer");
    hookClass(c, @selector(defaultContainer), (IMP)h_defaultContainer, (IMP*)&orig_defaultContainer);
    hookClass(c, @selector(containerWithIdentifier:), (IMP)h_containerWithId, (IMP*)&orig_containerWithId);

    // 6. Content-Length fix
    c = objc_getClass("FCHTTPInputStream");
    if (c) {
        hookInst(c, NSSelectorFromString(@"readHeadersAndFetchSizeForFile:"), (IMP)h_readHeaders, (IMP*)&orig_readHeaders);
        // 8. Length → -1 for FFmpeg AVSEEK_SIZE
        hookInst(c, NSSelectorFromString(@"length"), (IMP)h_length, (IMP*)&orig_length);
    }

    // 7. Disable seeking for streams
    c = objc_getClass("FCFFMPEGDemuxingStream");
    if (c) hookInst(c, NSSelectorFromString(@"canUseByteSeek"), (IMP)h_canUseByteSeek, (IMP*)&orig_canUseByteSeek);
}
