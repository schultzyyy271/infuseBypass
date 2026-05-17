//
//  InfuseBypass.m — Infuse 8.4.3 tvOS Sideload Bypass
//
//  Proven hooks + User-Agent/Range header fix for MovieBox Pro streams
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

// Original pointer for header hook
static id (*orig_initHeaders)(id, SEL, id, BOOL);

@interface InfuseBypass : NSObject
@end

@implementation InfuseBypass

+ (void)load {
    Class H = InfuseBypass.class;

    // 1. Pro unlock
    Class iap = objc_getClass("_TtC6infuse31InAppPurchaseServiceFreemiumSK2");
    if (iap) {
        Method o = class_getInstanceMethod(iap, NSSelectorFromString(@"iapVersionStatus"));
        Method s = class_getInstanceMethod(H, @selector(h_iapVersionStatus));
        if (o && s) method_exchangeImplementations(o, s);
    }

    // 2. Reachability bypass
    Class reach = objc_getClass("_TtC6infuse32DefaultSharesReachabilityManager");
    if (reach) {
        Method o = class_getInstanceMethod(reach, NSSelectorFromString(@"isShareAvailable:"));
        Method s = class_getInstanceMethod(H, @selector(h_isShareAvailable:));
        if (o && s) method_exchangeImplementations(o, s);
    }

    // 3. Container redirect
    Class fm = objc_getClass("NSFileManager");
    Method o3 = class_getInstanceMethod(fm, @selector(containerURLForSecurityApplicationGroupIdentifier:));
    Method s3 = class_getInstanceMethod(H, @selector(h_containerURL:));
    if (o3 && s3) method_exchangeImplementations(o3, s3);

    // 4 & 5. CloudKit disable
    Class ck = objc_getClass("CKContainer");
    Method o4 = class_getClassMethod(ck, @selector(defaultContainer));
    Method s4 = class_getClassMethod(H, @selector(h_defaultContainer));
    if (o4 && s4) method_exchangeImplementations(o4, s4);
    Method o5 = class_getClassMethod(ck, @selector(containerWithIdentifier:));
    Method s5 = class_getClassMethod(H, @selector(h_containerWithId:));
    if (o5 && s5) method_exchangeImplementations(o5, s5);

    // 6. HTTP headers fix — change User-Agent + remove Range header
    //    MovieBox CDN may omit Content-Length when it sees Infuse's User-Agent
    //    or when it sees Range header (switches to chunked transfer)
    Class hdr = objc_getClass("FCHTTPHeadersHandler");
    if (hdr) {
        Method m = class_getInstanceMethod(hdr, NSSelectorFromString(@"initWithRequestHeaders:dropHost:"));
        if (m) {
            orig_initHeaders = (id(*)(id, SEL, id, BOOL))method_getImplementation(m);
            method_setImplementation(m, (IMP)hook_initHeaders);
        }
    }
}

// Hook 6 — Modify HTTP headers
static id hook_initHeaders(id self, SEL _cmd, id headers, BOOL dropHost) {
    if (headers && [headers isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *mod = [headers mutableCopy];

        // Swap User-Agent to browser-like string
        mod[@"User-Agent"] = @"Mozilla/5.0 (AppleTV; U; CPU OS 18_0 like Mac OS X) "
                             @"AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";

        // Remove Range header on initial request — some CDNs skip
        // Content-Length when they see Range and use chunked instead
        [mod removeObjectForKey:@"Range"];

        return orig_initHeaders(self, _cmd, mod, dropHost);
    }
    return orig_initHeaders(self, _cmd, headers, dropHost);
}

- (NSInteger)h_iapVersionStatus { return 1; }
- (BOOL)h_isShareAvailable:(id)share { return YES; }

- (NSURL *)h_containerURL:(NSString *)gid {
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/ApplicationGroupContainers"];
    NSURL *base = [NSURL fileURLWithPath:path isDirectory:YES];
    NSURL *url = [base URLByAppendingPathComponent:gid ?: @"default"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:[url path]]) {
        [fm createDirectoryAtURL:url withIntermediateDirectories:YES attributes:nil error:nil];
        for (NSString *sub in @[@"Library/Application Support", @"Library/Caches", @"Library/Preferences"])
            [fm createDirectoryAtURL:[url URLByAppendingPathComponent:sub] withIntermediateDirectories:YES attributes:nil error:nil];
    }
    return url;
}

+ (id)h_defaultContainer { return nil; }
+ (id)h_containerWithId:(NSString *)i { return nil; }

@end
