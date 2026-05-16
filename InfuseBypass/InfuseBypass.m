//
//  InfuseBypass.m — Infuse 8.4.3 tvOS Sideload Fix
//
//  Proven hooks + Content-Length fix for MovieBox Pro streams
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

// Original method pointers
static NSInteger (*orig_iapVersionStatus)(id, SEL);
static BOOL (*orig_isShareAvailable)(id, SEL, id);
static NSURL* (*orig_containerURL)(id, SEL, NSString*);
static id (*orig_defaultContainer)(id, SEL);
static id (*orig_containerWithId)(id, SEL, NSString*);
static long long (*orig_readHeaders)(id, SEL, void*);

// Swizzle helpers
static void hookInst(Class c, SEL s, IMP new, IMP *old) {
    Method m = class_getInstanceMethod(c, s);
    if (m) *old = method_setImplementation(m, new);
}
static void hookClass(Class c, SEL s, IMP new, IMP *old) {
    Method m = class_getClassMethod(c, s);
    if (m) *old = method_setImplementation(m, new);
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

// === Hook 6: Content-Length fix (MovieBox Pro) ===
// MovieBox CDN doesn't send Content-Length headers.
// VLC streams until EOF, Infuse returns -1 and fails.
// Fix: return fake size so stream opens, Infuse reads until EOF.
static long long h_readHeaders(id self, SEL _cmd, void *file) {
    if (!file) return -1;
    long long result = orig_readHeaders(self, _cmd, file);
    if (result < 0) return 10737418240LL; // 10GB fake
    return result;
}

__attribute__((constructor))
static void init(void) {
    // 1. IAP
    Class c = objc_getClass("_TtC6infuse31InAppPurchaseServiceFreemiumSK2");
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
    if (c) hookInst(c, NSSelectorFromString(@"readHeadersAndFetchSizeForFile:"), (IMP)h_readHeaders, (IMP*)&orig_readHeaders);
}
