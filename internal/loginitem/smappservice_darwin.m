#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>

// Register/unregister/status for the bundled LaunchAgent plist via SMAppService
// (macOS 13+). plistName is the file name under Contents/Library/LaunchAgents in
// avd's own .app bundle. On error we copy NSError.localizedDescription into *err
// (caller frees with free()); status returns the raw SMAppServiceStatus.

int av_loginitem_register(const char *plistName, char **err) {
    @autoreleasepool {
        SMAppService *svc = [SMAppService agentServiceWithPlistName:@(plistName)];
        NSError *e = nil;
        if (![svc registerAndReturnError:&e]) {
            if (err && e) *err = strdup([[e localizedDescription] UTF8String]);
            return 1;
        }
        return 0;
    }
}

int av_loginitem_unregister(const char *plistName, char **err) {
    @autoreleasepool {
        SMAppService *svc = [SMAppService agentServiceWithPlistName:@(plistName)];
        NSError *e = nil;
        if (![svc unregisterAndReturnError:&e]) {
            if (err && e) *err = strdup([[e localizedDescription] UTF8String]);
            return 1;
        }
        return 0;
    }
}

// Returns SMAppServiceStatus: 0 NotRegistered, 1 Enabled, 2 RequiresApproval, 3 NotFound.
int av_loginitem_status(const char *plistName) {
    @autoreleasepool {
        SMAppService *svc = [SMAppService agentServiceWithPlistName:@(plistName)];
        return (int)svc.status;
    }
}
