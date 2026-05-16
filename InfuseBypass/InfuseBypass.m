//
//  InfuseBypass.m
//  InfuseBypass
//
//  Updated for Infuse 8.4.3 (tvOS)
//  Original by tylinux — updated for 8.4.3 with IDA Pro analysis
//
//  Hooks:
//  1. iapVersionStatus → 1 (Pro active)
//  2. isShareAvailable: → YES (fixes playback — reachability check
//     kills connections for sideloaded apps)
//  3. containerURLForSecurityApplicationGroupIdentifier: → Documents redirect
//  4. CKContainer defaultContainer → nil
//  5. CKContainer containerWithIdentifier: → nil
//
//  Root cause of playback failure:
//  FCCurlConnection.connect evaluates a connectionCheck block at 0x100018ca4
//  which calls SharesReachabilityManager.isShareAvailable: — returns false
//  for sideloaded apps, killing the stream before FFmpeg even opens.
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

@interface InfuseBypass : NSObject
@end

@implementation InfuseBypass

+ (void)load {
    Class HookClass = InfuseBypass.class;

    // ── IAP ───────────────────────────────────────────────────────────
    // 1. iapVersionStatus → 1 (Pro active)
    Class iapClass = objc_getClass("_TtC6infuse31InAppPurchaseServiceFreemiumSK2");
    if (iapClass) {
        Method originalIapMethod = class_getInstanceMethod(iapClass, NSSelectorFromString(@"iapVersionStatus"));
        Method swizzledIapMethod = class_getInstanceMethod(HookClass, @selector(hookedIapVersionStatus));
        if (originalIapMethod && swizzledIapMethod) {
            method_exchangeImplementations(originalIapMethod, swizzledIapMethod);
        }
    }

    // ── Reachability (PLAYBACK FIX) ──────────────────────────────────
    // 2. SharesReachabilityManager.isShareAvailable: → YES
    //    Without this, connectionCheck block returns 0 and the curl
    //    connection aborts before even attempting the HTTP request.
    Class reachClass = objc_getClass("_TtC6infuse32DefaultSharesReachabilityManager");
    if (reachClass) {
        Method originalReachMethod = class_getInstanceMethod(reachClass, NSSelectorFromString(@"isShareAvailable:"));
        Method swizzledReachMethod = class_getInstanceMethod(HookClass, @selector(hookedIsShareAvailable:));
        if (originalReachMethod && swizzledReachMethod) {
            method_exchangeImplementations(originalReachMethod, swizzledReachMethod);
        }
    }

    // ── Container redirect ───────────────────────────────────────────
    // 3. containerURLForSecurityApplicationGroupIdentifier: → Documents
    Class fileManagerClass = objc_getClass("NSFileManager");
    Method originalFMMethod = class_getInstanceMethod(fileManagerClass, @selector(containerURLForSecurityApplicationGroupIdentifier:));
    Method swizzledFMMethod = class_getInstanceMethod(HookClass, @selector(hookedContainerURLForSecurityApplicationGroupIdentifier:));
    if (originalFMMethod && swizzledFMMethod) {
        method_exchangeImplementations(originalFMMethod, swizzledFMMethod);
    }

    // ── CloudKit disable ─────────────────────────────────────────────
    // 4 & 5. CKContainer → nil
    Class cloudKitClass = objc_getClass("CKContainer");
    Method originalDefaultMethod = class_getClassMethod(cloudKitClass, @selector(defaultContainer));
    Method swizzledDefaultMethod = class_getClassMethod(HookClass, @selector(hookedDefaultContainer));
    if (originalDefaultMethod && swizzledDefaultMethod) {
        method_exchangeImplementations(originalDefaultMethod, swizzledDefaultMethod);
    }

    Method originalIdentifierMethod = class_getClassMethod(cloudKitClass, @selector(containerWithIdentifier:));
    Method swizzledIdentifierMethod = class_getClassMethod(HookClass, @selector(hookedContainerWithIdentifier:));
    if (originalIdentifierMethod && swizzledIdentifierMethod) {
        method_exchangeImplementations(originalIdentifierMethod, swizzledIdentifierMethod);
    }
}

#pragma mark - IAP

// Hook 1 — return 1 (FCIAPVersionStatus pro active)
- (NSInteger)hookedIapVersionStatus {
    return 1;
}

#pragma mark - Reachability (playback fix)

// Hook 2 — force all shares as reachable
- (BOOL)hookedIsShareAvailable:(id)share {
    return YES;
}

#pragma mark - Container redirect

// Hook 3 — redirect group container to Documents
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

// Hook 4
+ (id)hookedDefaultContainer {
    return nil;
}

// Hook 5
+ (id)hookedContainerWithIdentifier:(NSString *)identifier {
    return nil;
}

@end
