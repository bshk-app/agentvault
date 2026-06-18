// touchid_darwin.m implements the native LocalAuthentication bridge for the
// Touch ID presence check. cgo compiles .m files in this package automatically
// on darwin (the matching extern declaration lives in presence_darwin.go's cgo
// preamble). This file is NOT a Go file and carries no build tags; it is only
// reachable from the darwin && cgo build of the package.

#import <LocalAuthentication/LocalAuthentication.h>
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

// av_touchid_prompt runs a synchronous (blocking) presence check and returns:
//   0 = success (user authenticated)
//   1 = user cancel / authentication failure (maps to ErrDenied)
//   2 = policy unavailable / system error (maps to ErrLocked)
//
// Policy choice: we prefer LAPolicyDeviceOwnerAuthenticationWithBiometrics
// (Touch ID only). If biometrics are unavailable (no sensor, not enrolled,
// locked out after too many failures), we fall back to
// LAPolicyDeviceOwnerAuthentication, which additionally allows the device
// passcode. A daemon guarding secrets wants a *fresh* human presence signal;
// passcode fallback keeps the daemon usable on Macs without a Touch ID sensor
// while still requiring an interactive owner-presence confirmation. If even
// that policy cannot be evaluated, we report 2 (treated as locked) rather than
// silently granting access.
int av_touchid_prompt(const char *reason) {
    @autoreleasepool {
        if (reason == NULL) {
            return 2;
        }

        LAContext *ctx = [[LAContext alloc] init];
        NSError *policyErr = nil;
        LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;

        if (![ctx canEvaluatePolicy:policy error:&policyErr]) {
            // Biometrics unavailable: fall back to owner authentication
            // (Touch ID or device passcode).
            policy = LAPolicyDeviceOwnerAuthentication;
            if (![ctx canEvaluatePolicy:policy error:&policyErr]) {
                return 2;
            }
        }

        NSString *r = [NSString stringWithUTF8String:reason];
        if (r == nil) {
            return 2;
        }

        __block int result = 1; // default to "denied" until proven otherwise
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        [ctx evaluatePolicy:policy
            localizedReason:r
                      reply:^(BOOL success, NSError *error) {
                          (void)error;
                          result = success ? 0 : 1;
                          dispatch_semaphore_signal(sem);
                      }];

        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        return result;
    }
}
