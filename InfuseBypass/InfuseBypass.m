/*
 * InfuseBypass.m - Complete Infuse 8.4.3 tvOS Sideload Fix
 *
 * Compile as a dynamic framework and inject via DYLD_INSERT_LIBRARIES
 * or use a jailbreak tweak loader.
 *
 * Build command (Theos or manual):
 *   clang -arch arm64 -shared -framework Foundation -framework UIKit \
 *         -o InfuseBypass.dylib InfuseBypass.m
 */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

// ============================================================================
// MARK: - Logging (writes to Documents/infuse_bypass.log + NSLog)
// ============================================================================

static NSString *_bypassLogPath = nil;

static void _initLog(void) {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    _bypassLogPath = [[paths firstObject] stringByAppendingPathComponent:@"infuse_bypass.log"];
    [@"" writeToFile:_bypassLogPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

static void _writeLog(NSString *msg) {
    NSLog(@"[InfuseBypass] %@", msg);
    if (!_bypassLogPath) return;
    NSString *line = [NSString stringWithFormat:@"%@ %@\n",
        [NSDateFormatter localizedStringFromDate:[NSDate date] dateStyle:NSDateFormatterNoStyle timeStyle:NSDateFormatterMediumStyle],
        msg];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:_bypassLogPath];
    if (fh) { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
}

#define BYPASS_LOG(fmt, ...) _writeLog([NSString stringWithFormat:@"" fmt, ##__VA_ARGS__])

// ============================================================================
// MARK: - Method Swizzling Helpers
// ============================================================================

static void swizzleInstanceMethod(Class cls, SEL original, IMP replacement, IMP *outOriginal) {
    Method method = class_getInstanceMethod(cls, original);
    if (method) {
        *outOriginal = method_setImplementation(method, replacement);
        BYPASS_LOG(@"Hooked -[%@ %@]", NSStringFromClass(cls), NSStringFromSelector(original));
    } else {
        BYPASS_LOG(@"FAILED to hook -[%@ %@] - method not found", NSStringFromClass(cls), NSStringFromSelector(original));
    }
}

static void swizzleClassMethod(Class cls, SEL original, IMP replacement, IMP *outOriginal) {
    Method method = class_getClassMethod(cls, original);
    if (method) {
        *outOriginal = method_setImplementation(method, replacement);
        BYPASS_LOG(@"Hooked +[%@ %@]", NSStringFromClass(cls), NSStringFromSelector(original));
    } else {
        BYPASS_LOG(@"FAILED to hook +[%@ %@] - method not found", NSStringFromClass(cls), NSStringFromSelector(original));
    }
}

// ============================================================================
// MARK: - Original Method Pointers
// ============================================================================

// IAP
static NSInteger (*orig_iapConfig)(id self, SEL _cmd);
static NSInteger (*orig_iapVersionStatus)(id self, SEL _cmd);

// Reachability
static BOOL (*orig_isShareAvailable)(id self, SEL _cmd, id share);

// Connection Manager
static NSInteger (*orig_maxConnections)(id self, SEL _cmd);

// Stream Strategy
static BOOL (*orig_shouldInvalidateStream)(id self, SEL _cmd, id stream);
static BOOL (*orig_shouldInvalidateStream_GDrive)(id self, SEL _cmd, id stream);
static BOOL (*orig_shouldInvalidateStream_Mega)(id self, SEL _cmd, id stream);

// Container URL
static NSURL* (*orig_containerURLForSecurityApplicationGroupIdentifier)(id self, SEL _cmd, NSString *groupId);

// CloudKit
static id (*orig_CKContainer_defaultContainer)(id self, SEL _cmd);
static id (*orig_CKContainer_containerWithIdentifier)(id self, SEL _cmd, NSString *identifier);

// HTTP Stream debugging
static long long (*orig_readHeadersAndFetchSizeForFile)(id self, SEL _cmd, void *file);
static long long (*orig_httpStatusCode)(id self, SEL _cmd);

// OAuth Token
static BOOL (*orig_isAboutToExpire)(id self, SEL _cmd);

// Cloud Stream - API call monitoring
static id (*orig_createStreamOutError)(id self, SEL _cmd, id *outError);

// FCCloudInputStream monitoring
static BOOL (*orig_checkHTTPStreamIsValidAndSeek)(id self, SEL _cmd, BOOL seek);

// FCOperation success monitoring
static BOOL (*orig_FCOperation_isSuccessful)(id self, SEL _cmd);
static id (*orig_FCOperation_operationError)(id self, SEL _cmd);

// ============================================================================
// MARK: - Hook Implementations
// ============================================================================

#pragma mark - IAP Bypass

// FCEnvironment.iapConfig → 3 (Enterprise - bypasses all IAP checks)
static NSInteger hook_iapConfig(id self, SEL _cmd) {
    return 3; // 0=Free, 1=FreemiumSK2, 2=FreemiumAppStore, 3=Enterprise
}

// Return Pro status
static NSInteger hook_iapVersionStatus(id self, SEL _cmd) {
    return 1; // Pro
}

#pragma mark - Reachability Bypass

// DefaultSharesReachabilityManager.isShareAvailable: → YES
// This fixes the connection check in FCCurlConnection.connect:
static BOOL hook_isShareAvailable(id self, SEL _cmd, id share) {
    return YES;
}

#pragma mark - Connection Pool Fix

// FCConnectionManager.maxConnections → 20
// Prevents connection eviction that causes stream failures
static NSInteger hook_maxConnections(id self, SEL _cmd) {
    return 20; // Default is 3, which causes eviction issues
}

#pragma mark - Stream Invalidation Fix

// FCCloudServiceLinkStreamStrategy.shouldInvalidateStream: → NO
// Prevents constant stream recreation that fails on sideloaded apps
static BOOL hook_shouldInvalidateStream(id self, SEL _cmd, id stream) {
    // Check if link exists and is not expired
    id link = ((id(*)(id, SEL))objc_msgSend)(self, sel_registerName("link"));
    if (!link) {
        // No link yet, allow creation
        return YES;
    }

    // Check expiration
    id expirationDate = ((id(*)(id, SEL))objc_msgSend)(link, sel_registerName("expirationDate"));
    if (expirationDate) {
        NSDate *now = [NSDate date];
        NSComparisonResult cmp = [(NSDate *)expirationDate compare:now];
        if (cmp == NSOrderedAscending) {
            // Expired - allow refresh
            BYPASS_LOG(@"Link expired, allowing refresh");
            return YES;
        }
    }

    // Not expired, don't invalidate
    return NO;
}

// Google Drive strategy - always return NO
static BOOL hook_shouldInvalidateStream_GDrive(id self, SEL _cmd, id stream) {
    return NO;
}

// Mega strategy - always return NO
static BOOL hook_shouldInvalidateStream_Mega(id self, SEL _cmd, id stream) {
    return NO;
}

#pragma mark - Container URL Redirect

// Redirect app group container to Documents folder
static NSURL* hook_containerURLForSecurityApplicationGroupIdentifier(id self, SEL _cmd, NSString *groupId) {
    // Sideloaded apps don't have app group entitlements
    // Redirect to Documents directory
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsPath = [paths firstObject];
    NSString *fakePath = [documentsPath stringByAppendingPathComponent:@"AppGroup"];

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:fakePath]) {
        [fm createDirectoryAtPath:fakePath withIntermediateDirectories:YES attributes:nil error:nil];
    }

    BYPASS_LOG(@"Redirected container %@ to %@", groupId, fakePath);
    return [NSURL fileURLWithPath:fakePath];
}

#pragma mark - CloudKit Bypass

// Return nil for CloudKit containers (sideloaded apps can't use CloudKit)
static id hook_CKContainer_defaultContainer(id self, SEL _cmd) {
    BYPASS_LOG(@"CKContainer.defaultContainer → nil");
    return nil;
}

static id hook_CKContainer_containerWithIdentifier(id self, SEL _cmd, NSString *identifier) {
    BYPASS_LOG(@"CKContainer.containerWithIdentifier:%@ → nil", identifier);
    return nil;
}

#pragma mark - HTTP Stream Debugging

// Monitor HTTP status codes for debugging
static long long hook_readHeadersAndFetchSizeForFile(id self, SEL _cmd, void *file) {
    long long result = orig_readHeadersAndFetchSizeForFile(self, _cmd, file);

    if (result < 0) {
        // Get HTTP status code
        long long status = ((long long(*)(id, SEL))objc_msgSend)(self, sel_registerName("httpStatusCode"));
        BYPASS_LOG(@"readHeadersAndFetchSizeForFile FAILED: result=%lld, HTTP status=%lld", result, status);

        // If it's a 403 (Forbidden), the download URL might be expired or rate-limited
        if (status == 403 || status == 401) {
            BYPASS_LOG(@"HTTP %lld detected - likely expired URL or rate limit", status);
        }
    }

    return result;
}

#pragma mark - Cloud Stream API Monitoring

// Monitor createStreamOutError: for API failures
static id hook_createStreamOutError(id self, SEL _cmd, id *outError) {
    BYPASS_LOG(@"createStreamOutError: called on %@", [self class]);

    id result = orig_createStreamOutError(self, _cmd, outError);

    if (!result) {
        BYPASS_LOG(@"createStreamOutError: FAILED!");
        if (outError && *outError) {
            BYPASS_LOG(@"Error: %@", *outError);
        }
    } else {
        BYPASS_LOG(@"createStreamOutError: SUCCESS - stream created");
    }

    return result;
}

// Monitor checkHTTPStreamIsValidAndSeek: - this is the entry point for stream validation
static BOOL hook_checkHTTPStreamIsValidAndSeek(id self, SEL _cmd, BOOL seek) {
    BOOL result = orig_checkHTTPStreamIsValidAndSeek(self, _cmd, seek);

    if (!result) {
        BYPASS_LOG(@"checkHTTPStreamIsValidAndSeek: FAILED for %@", self);
        // Get the last error
        id lastError = ((id(*)(id, SEL))objc_msgSend)(self, sel_registerName("lastError"));
        if (lastError) {
            BYPASS_LOG(@"Last error: %@", lastError);
        }
    }

    return result;
}

// Monitor FCOperation.isSuccessful to catch API failures
static BOOL hook_FCOperation_isSuccessful(id self, SEL _cmd) {
    BOOL result = orig_FCOperation_isSuccessful(self, _cmd);

    if (!result) {
        // Only log for OAuth-related operations
        NSString *className = NSStringFromClass([self class]);
        if ([className containsString:@"OAuth"] || [className containsString:@"Cloud"] ||
            [className containsString:@"Link"] || [className containsString:@"API"]) {
            BYPASS_LOG(@"FCOperation FAILED: %@ (class: %@)", self, className);
            id error = ((id(*)(id, SEL))objc_msgSend)(self, sel_registerName("operationError"));
            if (error) {
                BYPASS_LOG(@"Operation error: %@", error);
            }
        }
    }

    return result;
}

#pragma mark - OAuth Token Fix

// Prevent token from being considered "about to expire"
// This stops unnecessary token refresh attempts that may fail on sideloaded apps
static BOOL hook_isAboutToExpire(id self, SEL _cmd) {
    id expirationDate = ((id(*)(id, SEL))objc_msgSend)(self, sel_registerName("expirationDate"));
    if (!expirationDate) {
        return NO; // No expiration = never expires
    }

    // Only consider expired if ACTUALLY expired, not "about to expire"
    NSTimeInterval remaining = [(NSDate *)expirationDate timeIntervalSinceNow];
    if (remaining < 0) {
        return YES; // Actually expired
    }

    return NO; // Not expired yet, don't refresh
}

// ============================================================================
// MARK: - Initialization
// ============================================================================

__attribute__((constructor))
static void InfuseBypassInit(void) {
    _initLog();
    BYPASS_LOG(@"Initializing Infuse 8.4.3 tvOS Sideload Bypass...");

    @autoreleasepool {

        // ====================================================================
        // IAP Bypass
        // ====================================================================

        Class FCEnvironmentClass = objc_getClass("FCEnvironment");
        if (FCEnvironmentClass) {
            swizzleClassMethod(FCEnvironmentClass,
                sel_registerName("iapConfig"),
                (IMP)hook_iapConfig,
                (IMP*)&orig_iapConfig);
        }

        // Try multiple possible class names for IAP status
        Class IAPServiceClass = objc_getClass("_TtC6infuse20IAPVersioningService");
        if (!IAPServiceClass) IAPServiceClass = objc_getClass("IAPVersioningService");
        if (IAPServiceClass) {
            swizzleInstanceMethod(IAPServiceClass,
                sel_registerName("iapVersionStatus"),
                (IMP)hook_iapVersionStatus,
                (IMP*)&orig_iapVersionStatus);
        }

        // ====================================================================
        // Reachability Bypass (CRITICAL)
        // ====================================================================

        Class ReachabilityManagerClass = objc_getClass("_TtC6infuse32DefaultSharesReachabilityManager");
        if (ReachabilityManagerClass) {
            swizzleInstanceMethod(ReachabilityManagerClass,
                sel_registerName("isShareAvailable:"),
                (IMP)hook_isShareAvailable,
                (IMP*)&orig_isShareAvailable);
        }

        // ====================================================================
        // Connection Pool Fix
        // ====================================================================

        Class FCConnectionManagerClass = objc_getClass("FCConnectionManager");
        if (FCConnectionManagerClass) {
            swizzleInstanceMethod(FCConnectionManagerClass,
                sel_registerName("maxConnections"),
                (IMP)hook_maxConnections,
                (IMP*)&orig_maxConnections);
        }

        // ====================================================================
        // Stream Invalidation Fix
        // ====================================================================

        Class LinkStrategyClass = objc_getClass("FCCloudServiceLinkStreamStrategy");
        if (LinkStrategyClass) {
            swizzleInstanceMethod(LinkStrategyClass,
                sel_registerName("shouldInvalidateStream:"),
                (IMP)hook_shouldInvalidateStream,
                (IMP*)&orig_shouldInvalidateStream);
        }

        Class GDriveStrategyClass = objc_getClass("FCGoogleDriveStreamStrategy");
        if (GDriveStrategyClass) {
            swizzleInstanceMethod(GDriveStrategyClass,
                sel_registerName("shouldInvalidateStream:"),
                (IMP)hook_shouldInvalidateStream_GDrive,
                (IMP*)&orig_shouldInvalidateStream_GDrive);
        }

        Class MegaStrategyClass = objc_getClass("FCMeganzStreamStrategy");
        if (MegaStrategyClass) {
            swizzleInstanceMethod(MegaStrategyClass,
                sel_registerName("shouldInvalidateStream:"),
                (IMP)hook_shouldInvalidateStream_Mega,
                (IMP*)&orig_shouldInvalidateStream_Mega);
        }

        // ====================================================================
        // Container URL Redirect
        // ====================================================================

        Class NSFileManagerClass = objc_getClass("NSFileManager");
        if (NSFileManagerClass) {
            swizzleInstanceMethod(NSFileManagerClass,
                sel_registerName("containerURLForSecurityApplicationGroupIdentifier:"),
                (IMP)hook_containerURLForSecurityApplicationGroupIdentifier,
                (IMP*)&orig_containerURLForSecurityApplicationGroupIdentifier);
        }

        // ====================================================================
        // CloudKit Bypass
        // ====================================================================

        Class CKContainerClass = objc_getClass("CKContainer");
        if (CKContainerClass) {
            swizzleClassMethod(CKContainerClass,
                sel_registerName("defaultContainer"),
                (IMP)hook_CKContainer_defaultContainer,
                (IMP*)&orig_CKContainer_defaultContainer);

            swizzleClassMethod(CKContainerClass,
                sel_registerName("containerWithIdentifier:"),
                (IMP)hook_CKContainer_containerWithIdentifier,
                (IMP*)&orig_CKContainer_containerWithIdentifier);
        }

        // ====================================================================
        // HTTP Stream Debugging
        // ====================================================================

        Class FCHTTPInputStreamClass = objc_getClass("FCHTTPInputStream");
        if (FCHTTPInputStreamClass) {
            swizzleInstanceMethod(FCHTTPInputStreamClass,
                sel_registerName("readHeadersAndFetchSizeForFile:"),
                (IMP)hook_readHeadersAndFetchSizeForFile,
                (IMP*)&orig_readHeadersAndFetchSizeForFile);
        }

        // ====================================================================
        // OAuth Token Fix
        // ====================================================================

        Class FCOAuthTokenClass = objc_getClass("FCOAuthToken");
        if (FCOAuthTokenClass) {
            swizzleInstanceMethod(FCOAuthTokenClass,
                sel_registerName("isAboutToExpire"),
                (IMP)hook_isAboutToExpire,
                (IMP*)&orig_isAboutToExpire);
        }

        // ====================================================================
        // Cloud Stream API Monitoring (DIAGNOSTIC)
        // ====================================================================

        // Monitor createStreamOutError: on all strategies
        if (LinkStrategyClass) {
            swizzleInstanceMethod(LinkStrategyClass,
                sel_registerName("createStreamOutError:"),
                (IMP)hook_createStreamOutError,
                (IMP*)&orig_createStreamOutError);
        }

        Class FCCloudInputStreamClass = objc_getClass("FCCloudInputStream");
        if (FCCloudInputStreamClass) {
            swizzleInstanceMethod(FCCloudInputStreamClass,
                sel_registerName("checkHTTPStreamIsValidAndSeek:"),
                (IMP)hook_checkHTTPStreamIsValidAndSeek,
                (IMP*)&orig_checkHTTPStreamIsValidAndSeek);
        }

        // Monitor FCOperation for API failures
        Class FCOperationClass = objc_getClass("FCOperation");
        if (FCOperationClass) {
            swizzleInstanceMethod(FCOperationClass,
                sel_registerName("isSuccessful"),
                (IMP)hook_FCOperation_isSuccessful,
                (IMP*)&orig_FCOperation_isSuccessful);
        }

        BYPASS_LOG(@"Initialization complete!");
    }
}
