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
//  3. shouldInvalidateStream: → YES (force fresh URL each time)
//  4. containerURLForSecurityApplicationGroupIdentifier: → Documents redirect
//  5. CKContainer defaultContainer → nil
//  6. CKContainer containerWithIdentifier: → nil
//
//  DEBUG: NSLog tagged [InfuseBypass] — check Console/syslog for output
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

@interface InfuseBypass : NSObject
@end

#pragma mark - Swizzle helpers

static void swizzleInstance(Class cls, SEL orig, Class hook, SEL swiz) {
    Method m1 = class_getInstanceMethod(cls, orig);
    Method m2 = class_getInstanceMethod(hook, swiz);
    if (m1 && m2) {
        method_exchangeImplementations(m1, m2);
        NSLog(@"[InfuseBypass] Hooked %@.%@", NSStringFromClass(cls), NSStringFromSelector(orig));
    } else {
        NSLog(@"[InfuseBypass] FAILED to hook %@.%@ (m1=%p m2=%p)",
              NSStringFromClass(cls), NSStringFromSelector(orig), m1, m2);
    }
}

static void swizzleClass(Class cls, SEL orig, Class hook, SEL swiz) {
    Method m1 = class_getClassMethod(cls, orig);
    Method m2 = class_getClassMethod(hook, swiz);
    if (m1 && m2) {
        method_exchangeImplementations(m1, m2);
        NSLog(@"[InfuseBypass] Hooked +%@.%@", NSStringFromClass(cls), NSStringFromSelector(orig));
    } else {
        NSLog(@"[InfuseBypass] FAILED to hook +%@.%@ (m1=%p m2=%p)",
              NSStringFromClass(cls), NSStringFromSelector(orig), m1, m2);
    }
}

@implementation InfuseBypass

+ (void)load {
    NSLog(@"[InfuseBypass] +load starting");
    Class H = InfuseBypass.class;

    // ── IAP ───────────────────────────────────────────────────────────
    Class iapClass = objc_getClass("_TtC6infuse31InAppPurchaseServiceFreemiumSK2");
    if (iapClass) {
        swizzleInstance(iapClass, NSSelectorFromString(@"iapVersionStatus"),
                        H, @selector(hookedIapVersionStatus));
    } else {
        NSLog(@"[InfuseBypass] FreemiumSK2 class NOT FOUND");
    }

    // ── Reachability ─────────────────────────────────────────────────
    Class reachClass = objc_getClass("_TtC6infuse32DefaultSharesReachabilityManager");
    if (reachClass) {
        swizzleInstance(reachClass, NSSelectorFromString(@"isShareAvailable:"),
                        H, @selector(hookedIsShareAvailable:));
    } else {
        NSLog(@"[InfuseBypass] ReachabilityManager class NOT FOUND");
    }

    // ── Stream invalidation ──────────────────────────────────────────
    // Try both ObjC and potential Swift-mangled names
    Class linkStratClass = objc_getClass("FCCloudServiceLinkStreamStrategy");
    if (!linkStratClass) {
        // Try Swift mangled name
        linkStratClass = objc_getClass("_TtC6infuse37FCCloudServiceLinkStreamStrategy");
        if (!linkStratClass) {
            // Scan for any class containing "LinkStreamStrategy"
            unsigned int classCount = 0;
            Class *classes = objc_copyClassList(&classCount);
            for (unsigned int i = 0; i < classCount; i++) {
                const char *name = class_getName(classes[i]);
                if (name && strstr(name, "LinkStream")) {
                    NSLog(@"[InfuseBypass] Found LinkStream class: %s", name);
                    linkStratClass = classes[i];
                }
                if (name && strstr(name, "StreamStrategy")) {
                    NSLog(@"[InfuseBypass] Found StreamStrategy class: %s", name);
                }
            }
            free(classes);
        }
    }
    if (linkStratClass) {
        swizzleInstance(linkStratClass, NSSelectorFromString(@"shouldInvalidateStream:"),
                        H, @selector(hookedShouldInvalidateStream:));
    } else {
        NSLog(@"[InfuseBypass] LinkStreamStrategy class NOT FOUND");
    }

    // ── Container redirect ───────────────────────────────────────────
    Class fmClass = objc_getClass("NSFileManager");
    swizzleInstance(fmClass,
                    @selector(containerURLForSecurityApplicationGroupIdentifier:),
                    H, @selector(hookedContainerURLForSecurityApplicationGroupIdentifier:));

    // ── CloudKit disable ─────────────────────────────────────────────
    Class ckClass = objc_getClass("CKContainer");
    swizzleClass(ckClass, @selector(defaultContainer),
                 H, @selector(hookedDefaultContainer));
    swizzleClass(ckClass, @selector(containerWithIdentifier:),
                 H, @selector(hookedContainerWithIdentifier:));

    NSLog(@"[InfuseBypass] +load complete");
}

#pragma mark - IAP

- (NSInteger)hookedIapVersionStatus {
    NSLog(@"[InfuseBypass] iapVersionStatus called → 1");
    return 1;
}

#pragma mark - Stream fixes

- (BOOL)hookedIsShareAvailable:(id)share {
    NSLog(@"[InfuseBypass] isShareAvailable: called → YES (share=%@)", share);
    return YES;
}

- (BOOL)hookedShouldInvalidateStream:(id)stream {
    NSLog(@"[InfuseBypass] shouldInvalidateStream: called → YES (force refresh)");
    return YES;
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
