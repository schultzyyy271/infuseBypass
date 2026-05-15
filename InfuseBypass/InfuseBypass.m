//
//  InfuseBypass.m
//  InfuseBypass
//
//  Updated for Infuse 8.4.3 (tvOS)
//  Original by tylinux — updated for 8.4.3 with IDA Pro analysis
//
//  Hooks (runtime swizzle):
//  1. iapVersionStatus → 1 (Pro active)
//  2. containerURLForSecurityApplicationGroupIdentifier: → Documents redirect
//  3. CKContainer defaultContainer → nil
//  4. CKContainer containerWithIdentifier: → nil
//
//  Binary patch:
//  - hasPro at 0x10021991c → MOV W0, #1; RET (always returns YES)
//    Bypasses Swift dispatch issues with isFeaturePurchased:tillDate:
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>

@interface InfuseBypass : NSObject
@end

#pragma mark - Binary patch helper

static void patchMemory(void *addr, const void *data, size_t size) {
    kern_return_t kr;
    kr = vm_protect(mach_task_self(), (vm_address_t)addr, size,
                    false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) return;
    memcpy(addr, data, size);
    vm_protect(mach_task_self(), (vm_address_t)addr, size,
               false, VM_PROT_READ | VM_PROT_EXECUTE);
}

@implementation InfuseBypass

+ (void)load {
    Class HookClass = InfuseBypass.class;

    // ── Binary patch: hasPro → always YES ──────────────────────────────
    // IDA: hasPro at 0x10021991c calls iapVersionStatus then checks > 0
    // Swizzling isFeaturePurchased:tillDate: doesn't work (Swift dispatch)
    // so we patch hasPro directly: MOV W0, #1; RET
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    uint8_t hasProPatch[] = {0x20, 0x00, 0x80, 0x52,   // MOV W0, #1
                             0xC0, 0x03, 0x5F, 0xD6};   // RET
    patchMemory((void *)(0x10021991c + slide), hasProPatch, 8);

    // 1. Hook iapVersionStatus → 1 (Pro active, for UI/analytics)
    Class iapClass = objc_getClass("_TtC6infuse31InAppPurchaseServiceFreemiumSK2");
    if (iapClass) {
        Method originalIapMethod = class_getInstanceMethod(iapClass, NSSelectorFromString(@"iapVersionStatus"));
        Method swizzledIapMethod = class_getInstanceMethod(HookClass, @selector(hookedIapVersionStatus));
        if (originalIapMethod && swizzledIapMethod) {
            method_exchangeImplementations(originalIapMethod, swizzledIapMethod);
        }
    }

    // 2. Hook NSFileManager containerURLForSecurityApplicationGroupIdentifier:
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
