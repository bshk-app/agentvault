// touchid_darwin.m implements the native LocalAuthentication bridge for the
// Touch ID presence check. cgo compiles .m files in this package automatically
// on darwin (the matching extern declaration lives in presence_darwin.go's cgo
// preamble). This file is NOT a Go file and carries no build tags; it is only
// reachable from the darwin && cgo build of the package.

#import <LocalAuthentication/LocalAuthentication.h>
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

// av_touchid_prompt_timeout_secs bounds how long we wait for the user to answer
// the biometric prompt. A never-answered prompt must NOT park the resolving
// goroutine forever, so we wait at most this long and then fail closed (return
// "denied"). 60s is generous for a human reaching for the sensor while still
// guaranteeing the goroutine is released.
//
// MANUAL-verify: the timeout FIRING cannot be exercised in CI (we can't trigger a
// real unanswered biometric prompt), but the bound itself is now compiled in.
#define av_touchid_prompt_timeout_secs 60

// av_touchid_prompt runs a presence check with a bounded wait and returns:
//   0 = success (user authenticated)
//   1 = user cancel / authentication failure / TIMEOUT (maps to ErrDenied)
//   2 = policy unavailable / system error (maps to ErrLocked)
//
// FAIL-CLOSED: a timed-out prompt returns 1 (ErrDenied) — a prompt nobody answered
// is a denial, never a grant.
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

        // USE-AFTER-FREE GUARD (the subtle correctness point of the bounded wait):
        // when the timeout fires we RETURN, but the reply block may STILL run later
        // (the user finally touches the sensor). If the block wrote to a `__block int`
        // on this stack frame, that late write would land in a dead frame — a
        // use-after-free. So the shared state is HEAP-allocated in an NSMutableData
        // and the block captures `shared`, which ARC RETAINS for the block's whole
        // lifetime. A late write therefore lands in still-live heap memory, and the
        // NSMutableData is freed only when BOTH this function's local reference and the
        // block's captured reference are gone — never while the block can still run.
        //
        // The semaphore is likewise ARC-managed and captured by the block, so a late
        // dispatch_semaphore_signal on a semaphore no one waits on is harmless and
        // never touches freed memory.
        //
        // We read the result into a plain local BEFORE returning so the C return value
        // is always taken from live memory we own, regardless of when (or whether) the
        // block runs.
        NSMutableData *shared = [NSMutableData dataWithLength:sizeof(int)];
        int *resultp = (int *)[shared mutableBytes];
        *resultp = 1; // default to "denied" until proven otherwise
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        [ctx evaluatePolicy:policy
            localizedReason:r
                      reply:^(BOOL success, NSError *error) {
                          (void)error;
                          // shared is retained by this block (ARC); safe even if this
                          // runs AFTER the bounded wait below already timed out and
                          // the function returned.
                          int *p = (int *)[shared mutableBytes];
                          *p = success ? 0 : 1;
                          dispatch_semaphore_signal(sem);
                      }];

        dispatch_time_t deadline =
            dispatch_time(DISPATCH_TIME_NOW,
                          (int64_t)av_touchid_prompt_timeout_secs * NSEC_PER_SEC);
        if (dispatch_semaphore_wait(sem, deadline) != 0) {
            // Timed out: the user never answered. Fail closed (ErrDenied). `shared`
            // and `sem` stay alive for any late reply block via the block's retained
            // captures; we read nothing from them here.
            return 1;
        }
        return *resultp;
    }
}
