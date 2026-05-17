//  InfuseBypass.m — Infuse 8.4.3 tvOS Sideload Bypass

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

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
