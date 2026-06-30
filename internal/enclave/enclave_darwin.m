// enclave_darwin.m implements the native Secure Enclave bridge that wraps/unwraps
// the age identity. cgo compiles .m files in this package automatically on darwin
// (the matching extern declarations live in enclave_darwin.go's cgo preamble).
// This file is NOT a Go file and carries no build tags; it is only reachable from
// the darwin && cgo build of the package.
//
// CRYPTO: a P-256 key is generated INSIDE the Secure Enclave with a user-presence
// ACL. Wrap = ECIES-encrypt the age identity to that key's PUBLIC key (no Touch
// ID). Unwrap = SecKeyCreateDecryptedData with the PRIVATE key (Touch ID, enforced
// by the ACL). See enclave_darwin.go for the full design rationale.
//
// SECURITY / FAIL-CLOSED: every function returns 0 ONLY on a fully successful
// Security.framework round trip; any error returns a nonzero code and leaves the
// output blob zeroed. No function logs or returns plaintext/key material — only an
// integer status crosses the cgo boundary.
//
// COMPILE-VERIFIED ONLY: the real round trip needs Apple hardware with a Secure
// Enclave and the keychain entitlement; CI cannot exercise it.

#import <Foundation/Foundation.h>
#import <Security/Security.h>

// av_enclave_blob mirrors the C struct declared in enclave_darwin.go: a
// heap-allocated buffer the Go side copies out and frees. Keep the layout in sync.
typedef struct {
    unsigned char *data;
    int            len;
} av_enclave_blob;

// kAVEnclaveKeyTag is the stable application tag the Enclave key is persisted
// under. MUST match keyTag in enclave_darwin.go so create and load address the
// same key across boots.
static NSString *const kAVEnclaveKeyTag = @"app.bshk.agentvault.age-wrap";

// The ECIES algorithm used for both wrap (public-key encrypt) and unwrap
// (private-key decrypt). X9.63 KDF + SHA-256 + AES-GCM is the standard hybrid
// scheme SecKey supports for EC keys and is appropriate for a P-256 Enclave key.
//
// This is a #define, not a `static const SecKeyAlgorithm`: the underlying
// kSecKeyAlgorithm... symbol is a CFStringRef global resolved at load time, not a
// compile-time constant, so it cannot initialize a file-scope const. The macro
// expands at each use site (inside functions) where that is fine.
#define kAVWrapAlgorithm kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM

// av_enclave_tag_data returns the application tag as NSData (the keychain stores
// kSecAttrApplicationTag as raw bytes).
static NSData *av_enclave_tag_data(void) {
    return [kAVEnclaveKeyTag dataUsingEncoding:NSUTF8StringEncoding];
}

// av_enclave_load_private_key copies the persisted Enclave private SecKey for our
// tag, or NULL if none exists / on error. Caller must CFRelease a non-NULL result.
// No user presence is required to obtain the REFERENCE; presence is enforced only
// when the private key is USED to decrypt.
static SecKeyRef av_enclave_load_private_key(void) {
    NSDictionary *query = @{
        (id)kSecClass:              (id)kSecClassKey,
        (id)kSecAttrApplicationTag: av_enclave_tag_data(),
        (id)kSecAttrKeyType:        (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecReturnRef:          @YES,
    };
    SecKeyRef key = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)query,
                                      (CFTypeRef *)&key);
    if (st != errSecSuccess) {
        return NULL;
    }
    return key;
}

// av_enclave_create_private_key generates a fresh P-256 key INSIDE the Secure
// Enclave, gated by a user-presence ACL, and persists it under our tag. Returns
// the private SecKey (caller CFReleases) or NULL on error; *outStatus carries the
// OSStatus-ish failure code. The private key never leaves the Enclave.
static SecKeyRef av_enclave_create_private_key(OSStatus *outStatus) {
    CFErrorRef acErr = NULL;
    // kSecAccessControlPrivateKeyUsage: the key may be used for sign/decrypt ops.
    // kSecAccessControlUserPresence: each such use requires a fresh Touch ID (or
    // device-passcode fallback) — this is what forces live presence on Unwrap.
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence,
        &acErr);
    if (access == NULL) {
        if (acErr) {
            if (outStatus) *outStatus = (OSStatus)CFErrorGetCode(acErr);
            CFRelease(acErr);
        } else if (outStatus) {
            *outStatus = errSecParam;
        }
        return NULL;
    }

    NSDictionary *privKeyAttrs = @{
        (id)kSecAttrIsPermanent:    @YES,
        (id)kSecAttrApplicationTag: av_enclave_tag_data(),
        (id)kSecAttrAccessControl:  (__bridge id)access,
    };
    NSDictionary *attrs = @{
        (id)kSecAttrKeyType:        (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrKeySizeInBits:  @256,
        // kSecAttrTokenIDSecureEnclave forces generation on the Enclave token: the
        // private key is created and lives only inside the Secure Enclave.
        (id)kSecAttrTokenID:        (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecPrivateKeyAttrs:    privKeyAttrs,
    };

    CFErrorRef genErr = NULL;
    SecKeyRef priv = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &genErr);
    CFRelease(access);
    if (priv == NULL) {
        if (genErr) {
            if (outStatus) *outStatus = (OSStatus)CFErrorGetCode(genErr);
            CFRelease(genErr);
        } else if (outStatus) {
            *outStatus = errSecParam;
        }
        return NULL;
    }
    if (outStatus) *outStatus = errSecSuccess;
    return priv;
}

// av_enclave_ensure_key creates-or-loads the Enclave key. 0 on success.
int av_enclave_ensure_key(void) {
    @autoreleasepool {
        SecKeyRef existing = av_enclave_load_private_key();
        if (existing != NULL) {
            CFRelease(existing);
            return 0;
        }
        OSStatus st = errSecSuccess;
        SecKeyRef created = av_enclave_create_private_key(&st);
        if (created == NULL) {
            // Normalize a success-looking status to a generic failure so callers
            // never see 0 without an actual key (fail-closed).
            return st != errSecSuccess ? (int)st : (int)errSecParam;
        }
        CFRelease(created);
        return 0;
    }
}

// av_enclave_wrap ECIES-encrypts in/in_len to the Enclave key's PUBLIC key. No
// Touch ID. 0 on success with *out filled; nonzero on failure with *out zeroed.
int av_enclave_wrap(const unsigned char *in, int in_len, av_enclave_blob *out) {
    @autoreleasepool {
        if (out == NULL || in == NULL || in_len <= 0) {
            return (int)errSecParam;
        }
        out->data = NULL;
        out->len = 0;

        SecKeyRef priv = av_enclave_load_private_key();
        if (priv == NULL) {
            return (int)errSecItemNotFound;
        }
        SecKeyRef pub = SecKeyCopyPublicKey(priv);
        CFRelease(priv);
        if (pub == NULL) {
            return (int)errSecParam;
        }
        if (!SecKeyIsAlgorithmSupported(pub, kSecKeyOperationTypeEncrypt,
                                        kAVWrapAlgorithm)) {
            CFRelease(pub);
            return (int)errSecParam;
        }

        NSData *plain = [NSData dataWithBytes:in length:(NSUInteger)in_len];
        CFErrorRef encErr = NULL;
        CFDataRef cipher = SecKeyCreateEncryptedData(
            pub, kAVWrapAlgorithm, (__bridge CFDataRef)plain, &encErr);
        CFRelease(pub);
        if (cipher == NULL) {
            int rc = (int)errSecParam;
            if (encErr) {
                rc = (int)CFErrorGetCode(encErr);
                CFRelease(encErr);
            }
            return rc;
        }

        CFIndex n = CFDataGetLength(cipher);
        if (n <= 0) {
            CFRelease(cipher);
            return (int)errSecParam;
        }
        unsigned char *buf = (unsigned char *)malloc((size_t)n);
        if (buf == NULL) {
            CFRelease(cipher);
            return (int)errSecAllocate;
        }
        memcpy(buf, CFDataGetBytePtr(cipher), (size_t)n);
        CFRelease(cipher);
        out->data = buf;
        out->len = (int)n;
        return 0;
    }
}

// av_enclave_unwrap decrypts in/in_len with the Enclave PRIVATE key. This triggers
// the user-presence ACL -> Touch ID. 0 on success with *out filled; nonzero on
// failure (incl. user cancel/timeout) with *out zeroed.
int av_enclave_unwrap(const unsigned char *in, int in_len, av_enclave_blob *out) {
    @autoreleasepool {
        if (out == NULL || in == NULL || in_len <= 0) {
            return (int)errSecParam;
        }
        out->data = NULL;
        out->len = 0;

        SecKeyRef priv = av_enclave_load_private_key();
        if (priv == NULL) {
            return (int)errSecItemNotFound;
        }
        if (!SecKeyIsAlgorithmSupported(priv, kSecKeyOperationTypeDecrypt,
                                        kAVWrapAlgorithm)) {
            CFRelease(priv);
            return (int)errSecParam;
        }

        NSData *cipher = [NSData dataWithBytes:in length:(NSUInteger)in_len];
        CFErrorRef decErr = NULL;
        // SecKeyCreateDecryptedData drives the Enclave: the user-presence ACL makes
        // the system present Touch ID here. A cancel/timeout surfaces as a CFError.
        CFDataRef plain = SecKeyCreateDecryptedData(
            priv, kAVWrapAlgorithm, (__bridge CFDataRef)cipher, &decErr);
        CFRelease(priv);
        if (plain == NULL) {
            int rc = (int)errSecParam;
            if (decErr) {
                rc = (int)CFErrorGetCode(decErr);
                CFRelease(decErr);
            }
            return rc;
        }

        CFIndex n = CFDataGetLength(plain);
        if (n <= 0) {
            CFRelease(plain);
            return (int)errSecParam;
        }
        unsigned char *buf = (unsigned char *)malloc((size_t)n);
        if (buf == NULL) {
            CFRelease(plain);
            return (int)errSecAllocate;
        }
        memcpy(buf, CFDataGetBytePtr(plain), (size_t)n);
        CFRelease(plain);
        out->data = buf;
        out->len = (int)n;
        return 0;
    }
}
