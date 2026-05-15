//
//  InfuseBypass.m
//  InfuseBypass
//
//  Updated for Infuse 8.4.3 (tvOS)
//  Original by tylinux — updated for 8.4.3 with IDA Pro analysis
//
//  Hooks:
//  1. iapVersionStatus → 1 (Enterprise)
//  2. isFeaturePurchased:tillDate: → YES (unlocks all codecs/stream types)
//  3. iapProSource → 2 (Enterprise source value)
//  4. productsAreLoading → NO
//  5. canMakePayments → YES
//  6. isSubscriptionTrialUsed → YES
//  7. gracePeriodEndDate → nil
//  8. FCEnvironment iapConfig → 3 (force Enterprise IAP service path)
//  9. containerURLForSecurityApplicationGroupIdentifier: → Documents redirect
// 10. CKContainer defaultContainer → nil
// 11. CKContainer containerWithIdentifier: → nil
//
//  IDA findings: the demux error "Failed to open input in demuxing stream" at
//  -[FCFFMPEGDemuxingStream open] (0x1000922d0) is gated by isFeaturePurchased:
//  which validates subscriptions via StoreKit 2. iapVersionStatus alone only
//  controls UI/analytics — isFeaturePurchased: is the actual feature gate.
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

// Forward-declare for FCEnvironment hook
@interface InfuseBypass : NSObject
@end

#pragma mark - Swizzle helper

static void swizzleInstance(Class targetClass, SEL originalSel, Class hookClass, SEL swizzledSel) {
    Method orig = class_getInstanceMethod(targetClass, originalSel);
    Method swiz = class_getInstanceMethod(hookClass, swizzledSel);
    if (orig && swiz) method_exchangeImplementations(orig, swiz);
}

static void swizzleClass(Class targetClass, SEL originalSel, Class hookClass, SEL swizzledSel) {
    Method orig = class_getClassMethod(targetClass, originalSel);
    Method swiz = class_getClassMethod(hookClass, swizzledSel);
    if (orig && swiz) method_exchangeImplementations(orig, swiz);
}

@implementation InfuseBypass

+ (void)load {
    Class HookClass = InfuseBypass.class;

    // ── IAP hooks on FreemiumSK2 ──────────────────────────────────────
    Class iapClass = objc_getClass("_TtC6infuse31InAppPurchaseServiceFreemiumSK2");
    if (iapClass) {
        // 1. iapVersionStatus → 1 (Enterprise)
        swizzleInstance(iapClass, NSSelectorFromString(@"iapVersionStatus"),
                        HookClass, @selector(hookedIapVersionStatus));

        // 2. isFeaturePurchased:tillDate: → YES (CRITICAL — actual feature gate)
        //    Without this, codecs/stream types are blocked at the demuxer level
        swizzleInstance(iapClass, NSSelectorFromString(@"isFeaturePurchased:tillDate:"),
                        HookClass, @selector(hookedIsFeaturePurchased:tillDate:));

        // 3. iapProSource → 2 (Enterprise source)
        swizzleInstance(iapClass, NSSelectorFromString(@"iapProSource"),
                        HookClass, @selector(hookedIapProSource));

        // 4-7. Belt & suspenders — match Enterprise behavior exactly
        swizzleInstance(iapClass, NSSelectorFromString(@"productsAreLoading"),
                        HookClass, @selector(hookedProductsAreLoading));
        swizzleInstance(iapClass, NSSelectorFromString(@"canMakePayments"),
                        HookClass, @selector(hookedCanMakePayments));
        swizzleInstance(iapClass, NSSelectorFromString(@"isSubscriptionTrialUsed"),
                        HookClass, @selector(hookedIsSubscriptionTrialUsed));
        swizzleInstance(iapClass, NSSelectorFromString(@"gracePeriodEndDate"),
                        HookClass, @selector(hookedGracePeriodEndDate));
    }

    // ── FCEnvironment — force Enterprise IAP config ───────────────────
    // 4. iapConfig → 3 makes the factory use InAppPurchaseServiceEnterprise
    //    which always returns true for all features (belt-and-suspenders)
    Class envClass = objc_getClass("FCEnvironment");
    if (envClass) {
        swizzleClass(envClass, NSSelectorFromString(@"iapConfig"),
                     HookClass, @selector(hookedIapConfig));
    }

    // ── Container / CloudKit hooks ────────────────────────────────────
    // 5. Redirect group container to Documents (prevents nil URL crash)
    Class fileManagerClass = objc_getClass("NSFileManager");
    swizzleInstance(fileManagerClass,
                    @selector(containerURLForSecurityApplicationGroupIdentifier:),
                    HookClass,
                    @selector(hookedContainerURLForSecurityApplicationGroupIdentifier:));

    // 6 & 7. Disable CloudKit (no valid entitlements when sideloaded)
    Class cloudKitClass = objc_getClass("CKContainer");
    swizzleClass(cloudKitClass, @selector(defaultContainer),
                 HookClass, @selector(hookedDefaultContainer));
    swizzleClass(cloudKitClass, @selector(containerWithIdentifier:),
                 HookClass, @selector(hookedContainerWithIdentifier:));
}

#pragma mark - IAP Hooks

// Hook 1 — FCIAPVersionStatus: 1 = Enterprise/Pro active
- (NSInteger)hookedIapVersionStatus {
    return 1;
}

// Hook 2 — The actual feature gate. IDA: FreemiumSK2's isFeaturePurchased:tillDate:
// at 0x1007ad0a0 calls sub_1007ACED0 which validates via StoreKit 2.
// Enterprise version at 0x1003e6654 always returns YES. We match that.
- (BOOL)hookedIsFeaturePurchased:(long long)feature tillDate:(id *)date {
    if (date) *date = nil;  // No expiration
    return YES;
}

// Hook 3 — Enterprise returns 2 for iapProSource
- (NSInteger)hookedIapProSource {
    return 2;
}

// Hook 4 — Enterprise returns NO (products already "loaded")
- (BOOL)hookedProductsAreLoading {
    return NO;
}

// Hook 5 — Enterprise returns YES
- (BOOL)hookedCanMakePayments {
    return YES;
}

// Hook 6 — Enterprise returns YES (trial already used, skip trial flow)
- (BOOL)hookedIsSubscriptionTrialUsed {
    return YES;
}

// Hook 7 — Enterprise returns nil (no grace period)
- (id)hookedGracePeriodEndDate {
    return nil;
}

#pragma mark - Environment Hook

// Hook 4 — Force Enterprise IAP service: 3 = Enterprise config
+ (NSUInteger)hookedIapConfig {
    return 3;
}

#pragma mark - Container Hooks

// Hook 5 — Redirect group container to a valid writable path
- (NSURL *)hookedContainerURLForSecurityApplicationGroupIdentifier:(NSString *)groupIdentifier {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docsPath = [paths firstObject];
    NSString *containerPath = [docsPath stringByAppendingPathComponent:@"SharedContainer"];

    if (groupIdentifier.length > 0) {
        containerPath = [containerPath stringByAppendingPathComponent:groupIdentifier];
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:containerPath]) {
        [fm createDirectoryAtPath:containerPath
      withIntermediateDirectories:YES
                       attributes:nil
                            error:nil];

        // Create standard Library subdirectories
        for (NSString *sub in @[@"Library/Application Support", @"Library/Caches", @"Library/Preferences"]) {
            NSString *subPath = [containerPath stringByAppendingPathComponent:sub];
            [fm createDirectoryAtPath:subPath
          withIntermediateDirectories:YES
                           attributes:nil
                                error:nil];
        }
    }

    return [NSURL fileURLWithPath:containerPath isDirectory:YES];
}

// Hook 6
+ (id)hookedDefaultContainer {
    return nil;
}

// Hook 7
+ (id)hookedContainerWithIdentifier:(NSString *)identifier {
    return nil;
}

@end
