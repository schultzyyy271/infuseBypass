//
//  InfuseBypass.m
//  InfuseBypass
//
//  Updated for Infuse 8.4.3 (tvOS)
//  Original by tylinux — updated for 8.4.3 by AI
//
//  Changes from 8.1.9:
//  - FCInAppPurchaseServiceFreemium (ObjC) renamed to
//    _TtC6infuse31InAppPurchaseServiceFreemiumSK2 (Swift/SK2)
//  - iapVersionStatus now returns NSInteger (FCIAPVersionStatus enum), not BOOL
//  - Hooks 2/3/4 (containerURL, CKContainer) unchanged
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

@interface InfuseBypass : NSObject
@end

@implementation InfuseBypass

+ (void)load {
    Class HookClass = InfuseBypass.class;

    // 1. Hook iapVersionStatus on the SK2 Swift class (renamed in 8.4.3)
    //    Swift mangled: _TtC6infuse31InAppPurchaseServiceFreemiumSK2
    //    iapVersionStatus returns NSInteger (FCIAPVersionStatus enum)
    //    Return 1 = pro active
    Class iapClass = objc_getClass("_TtC6infuse31InAppPurchaseServiceFreemiumSK2");
    if (iapClass) {
        Method originalIapMethod = class_getInstanceMethod(iapClass, NSSelectorFromString(@"iapVersionStatus"));
        Method swizzledIapMethod = class_getInstanceMethod(HookClass, @selector(hookedIapVersionStatus));
        if (originalIapMethod && swizzledIapMethod) {
            method_exchangeImplementations(originalIapMethod, swizzledIapMethod);
        }
    }

    // 2. Hook NSFileManager containerURLForSecurityApplicationGroupIdentifier:
    //    Redirects group container lookups to app's own Documents directory.
    //    Prevents nil URL crash on launch when sideloaded without real app groups.
    Class fileManagerClass = objc_getClass("NSFileManager");
    Method originalFMMethod = class_getInstanceMethod(fileManagerClass, @selector(containerURLForSecurityApplicationGroupIdentifier:));
    Method swizzledFMMethod = class_getInstanceMethod(HookClass, @selector(containerURLForSecurityApplicationGroupIdentifier:));
    if (originalFMMethod && swizzledFMMethod) {
        method_exchangeImplementations(originalFMMethod, swizzledFMMethod);
    }

    // 3. Hook CKContainer defaultContainer — return nil to disable CloudKit
    Class cloudKitClass = objc_getClass("CKContainer");
    Method originalDefaultMethod = class_getClassMethod(cloudKitClass, @selector(defaultContainer));
    Method swizzledDefaultMethod = class_getClassMethod(HookClass, @selector(defaultContainer));
    if (originalDefaultMethod && swizzledDefaultMethod) {
        method_exchangeImplementations(originalDefaultMethod, swizzledDefaultMethod);
    }

    // 4. Hook CKContainer containerWithIdentifier: — return nil to disable CloudKit
    Method originalIdentifierMethod = class_getClassMethod(cloudKitClass, @selector(containerWithIdentifier:));
    Method swizzledIdentifierMethod = class_getClassMethod(HookClass, @selector(containerWithIdentifier:));
    if (originalIdentifierMethod && swizzledIdentifierMethod) {
        method_exchangeImplementations(originalIdentifierMethod, swizzledIdentifierMethod);
    }
}

// Hook 1 — return 1 (FCIAPVersionStatus pro active)
- (NSInteger)hookedIapVersionStatus {
    return 1;
}

// Hook 2 — redirect group container to Documents/ApplicationGroupContainers/<group>
- (NSURL *)containerURLForSecurityApplicationGroupIdentifier:(NSString *)groupIdentifier {
    NSString *homeDirectory = NSHomeDirectory();
    NSString *containerBasePath = [homeDirectory stringByAppendingPathComponent:@"Documents/ApplicationGroupContainers"];
    NSURL *baseURL = [NSURL fileURLWithPath:containerBasePath isDirectory:YES];
    NSURL *containerURL = [baseURL URLByAppendingPathComponent:groupIdentifier];

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

// Hook 3
+ (id)defaultContainer {
    return nil;
}

// Hook 4
+ (id)containerWithIdentifier:(NSString *)identifier {
    return nil;
}

@end
