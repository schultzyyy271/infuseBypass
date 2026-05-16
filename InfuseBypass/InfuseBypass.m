//
//  InfuseBypass.m
//  InfuseBypass
//
//  Updated for Infuse 8.4.3 (tvOS)
//  Original by tylinux — updated for 8.4.3 with IDA Pro analysis
//
//  Hooks:
//  1. iapVersionStatus → 1 (Pro active)
//  2. isShareAvailable: → YES (reachability bypass)
//  3. shouldInvalidateStream: → NO (prevent link expiration kills)
//  4. containerURLForSecurityApplicationGroupIdentifier: → Documents redirect
//  5. CKContainer defaultContainer → nil
//  6. CKContainer containerWithIdentifier: → nil
//
//  IDA finding: cloud protocols 28-31 bypass isShareAvailable: entirely,
//  so some streams fail even with the reachability hook. Adding
//  shouldInvalidateStream: and connection fixes covers all paths.
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

@interface InfuseBypass : NSObject
@end

#pragma mark - Swizzle helpers

static void swizzleInstance(Class cls, SEL orig, Class hook, SEL swiz) {
    Method m1 = class_getInstanceMethod(cls, orig);
    Method m2 = class_getInstanceMethod(hook, swiz);
    if (m1 && m2) method_exchangeImplementations(m1, m2);
}

static void swizzleClass(Class cls, SEL orig, Class hook, SEL swiz) {
    Method m1 = class_getClassMethod(cls, orig);
    Method m2 = class_getClassMethod(hook, swiz);
    if (m1 && m2) method_exchangeImplementations(m1, m2);
}

@implementation InfuseBypass

+ (void)load {
    Class H = InfuseBypass.class;

    // ── IAP ───────────────────────────────────────────────────────────
    // 1. iapVersionStatus → 1 (Pro active)
    Class iapClass = objc_getClass("_TtC6infuse31InAppPurchaseServiceFreemiumSK2");
    if (iapClass) {
        swizzleInstance(iapClass, NSSelectorFromString(@"iapVersionStatus"),
                        H, @selector(hookedIapVersionStatus));
    }

    // ── Stream / Reachability fixes ──────────────────────────────────
    // 2. isShareAvailable: → YES (covers reachability-aware protocols)
    Class reachClass = objc_getClass("_TtC6infuse32DefaultSharesReachabilityManager");
    if (reachClass) {
        swizzleInstance(reachClass, NSSelectorFromString(@"isShareAvailable:"),
                        H, @selector(hookedIsShareAvailable:));
    }

    // 3. shouldInvalidateStream: → NO (covers cloud protocols 28-31
    //    that bypass reachability — prevents link expiration check
    //    from killing active streams)
    Class linkStratClass = objc_getClass("FCCloudServiceLinkStreamStrategy");
    if (linkStratClass) {
        swizzleInstance(linkStratClass, NSSelectorFromString(@"shouldInvalidateStream:"),
                        H, @selector(hookedShouldInvalidateStream:));
    }

    // ── Container redirect ───────────────────────────────────────────
    // 4. containerURLForSecurityApplicationGroupIdentifier: → Documents
    Class fmClass = objc_getClass("NSFileManager");
    swizzleInstance(fmClass,
                    @selector(containerURLForSecurityApplicationGroupIdentifier:),
                    H, @selector(hookedContainerURLForSecurityApplicationGroupIdentifier:));

    // ── CloudKit disable ─────────────────────────────────────────────
    // 5 & 6. CKContainer → nil
    Class ckClass = objc_getClass("CKContainer");
    swizzleClass(ckClass, @selector(defaultContainer),
                 H, @selector(hookedDefaultContainer));
    swizzleClass(ckClass, @selector(containerWithIdentifier:),
                 H, @selector(hookedContainerWithIdentifier:));
}

#pragma mark - IAP

- (NSInteger)hookedIapVersionStatus {
    return 1;
}

#pragma mark - Stream fixes

- (BOOL)hookedIsShareAvailable:(id)share {
    return YES;
}

- (BOOL)hookedShouldInvalidateStream:(id)stream {
    return NO;
}

#pragma mark - Container redirect

- (NSURL *)hookedContainerURLForSecurityApplicationGroupIdentifier:(NSString *)groupIdentifier {
    NSString *homeDirectory = NSHomeDirectory();
    NSString *containerBasePath = [homeDirectory stringByAppendingPathComponent:@"Documents/ApplicationGroupContainers"];
    NSURL *baseURL = [NSURL fileURLWithPath:containerBasePath isDirectory:YES];
    NSURL *containerURL = [baseURL URLByAppendingPathComponent:groupIdentifier ?: @"default"];

    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSString *containerPath = [containerURL path];

    if (![fileManager fileExistsAtPath:containerPath]) {
        NSError *error = nil;
        [fileManager createDirectoryAtURL:containerURL
               withIntermediateDirectories:YES
                                attributes:nil
                                     error:&error];

        for (NSString *subpath in @[@"Library/Application Support", @"Library/Caches", @"Library/Preferences"]) {
            NSURL *subURL = [containerURL URLByAppendingPathComponent:subpath];
            [fileManager createDirectoryAtURL:subURL
                   withIntermediateDirectories:YES
                                    attributes:nil
                                         error:&error];
        }
    }

    return containerURL;
}

#pragma mark - CloudKit disable

+ (id)hookedDefaultContainer {
    return nil;
}

+ (id)hookedContainerWithIdentifier:(NSString *)identifier {
    return nil;
}

@end
