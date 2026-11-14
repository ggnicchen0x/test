//  Framework: UIKit, Security, Foundation
//  Build:     xcrun -sdk iphoneos clang -fobjc-arc -arch arm64 -dynamiclib \
//                 AuthGate.m -framework UIKit -framework Foundation \
//                 -framework Security -o AuthGate.dylib \
//                 -install_name @executable_path/Frameworks/AuthGate.dylib \
//                 -Xlinker -mios-version-min=15.0
//

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <CommonCrypto/CommonCrypto.h>

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

static NSString * const kAuthBaseURL   = @"http://95.216.12.48:25808";
static NSString * const kActivatePath  = @"/v1/activations";
static NSString * const kVerifyPath    = @"/v1/verifications";
static NSString * const kHeartbeatPath = @"/v1/device-check";
static NSString * const kKeychainAccount = @"com.yangjiii.3105.authgate.v1";
static NSString * const kKeychainService = @"3105.authgate";
static NSString * const kKeychainAccount    = @"com.yangjiii.3105.authgate.v1";
static NSString * const kKeychainKeyAccount = @"com.yangjiii.3105.authgate.lastkey.v1";
static NSString * const kKeychainService    = @"3105.authgate";
static NSTimeInterval const kHeartbeatInterval = 300.0;

// Indigo / Dark theme
@@ -75,25 +76,26 @@
// Keychain token persistence
// ---------------------------------------------------------------------------

static NSMutableDictionary *AGBaseQuery(void) {
static NSMutableDictionary *AGQueryFor(NSString *account) {
return [@{
(__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
(__bridge id)kSecAttrService: kKeychainService,
        (__bridge id)kSecAttrAccount: kKeychainAccount,
        (__bridge id)kSecAttrAccount: account,
} mutableCopy];
}

static void AGSaveToken(NSString *token) {
    if (!token) return;
    NSMutableDictionary *q = AGBaseQuery();
static void AGWrite(NSString *account, NSString *value) {
    if (!account.length) return;
    NSMutableDictionary *q = AGQueryFor(account);
SecItemDelete((__bridge CFDictionaryRef)q);
    q[(__bridge id)kSecValueData] = [token dataUsingEncoding:NSUTF8StringEncoding];
    if (!value.length) return;
    q[(__bridge id)kSecValueData]      = [value dataUsingEncoding:NSUTF8StringEncoding];
q[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
SecItemAdd((__bridge CFDictionaryRef)q, NULL);
}

static NSString *AGLoadToken(void) {
    NSMutableDictionary *q = AGBaseQuery();
static NSString *AGRead(NSString *account) {
    NSMutableDictionary *q = AGQueryFor(account);
q[(__bridge id)kSecReturnData]  = @YES;
q[(__bridge id)kSecMatchLimit]  = (__bridge id)kSecMatchLimitOne;
CFTypeRef out = NULL;
@@ -103,9 +105,11 @@
return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static void AGClearToken(void) {
    SecItemDelete((__bridge CFDictionaryRef)AGBaseQuery());
}
static void AGSaveToken(NSString *token)   { AGWrite(kKeychainAccount, token); }
static NSString *AGLoadToken(void)         { return AGRead(kKeychainAccount); }
static void AGClearToken(void)             { AGWrite(kKeychainAccount, nil); }
static void AGSaveLastKey(NSString *key)   { AGWrite(kKeychainKeyAccount, key); }
static NSString *AGLoadLastKey(void)       { return AGRead(kKeychainKeyAccount); }

// Forward decl — defined near the NSURLSession swizzle below.
static void AGMarkAuthorized(NSString *token);
@@ -336,10 +340,12 @@

UILabel *brand = [UILabel new];
brand.translatesAutoresizingMaskIntoConstraints = NO;
    brand.text = @"3105";
    brand.font = [UIFont systemFontOfSize:28 weight:UIFontWeightBlack];
    brand.text = @"BYTE EXTERNAL";
    brand.font = [UIFont systemFontOfSize:24 weight:UIFontWeightBlack];
brand.textColor = THEME_FG;
brand.textAlignment = NSTextAlignmentCenter;
    brand.adjustsFontSizeToFitWidth = YES;
    brand.minimumScaleFactor = 0.7;
[card addSubview:brand];

UILabel *title = [UILabel new];
@@ -361,11 +367,15 @@

self.keyField = [UITextField new];
self.keyField.translatesAutoresizingMaskIntoConstraints = NO;
    self.keyField.placeholder = @"XXXX-XXXX-XXXX-XXXX";
    NSString *lastKey = AGLoadLastKey();
    NSString *placeholder = lastKey.length ? lastKey : @"XXXX-XXXX-XXXX-XXXX";
    self.keyField.placeholder = placeholder;
self.keyField.attributedPlaceholder = [[NSAttributedString alloc]
        initWithString:@"XXXX-XXXX-XXXX-XXXX"
        initWithString:placeholder
attributes:@{NSForegroundColorAttributeName: [THEME_MUTED colorWithAlphaComponent:0.6],
NSFontAttributeName:[UIFont monospacedSystemFontOfSize:15 weight:UIFontWeightMedium]}];
    // Pre-fill the field so the user can simply tap Activate.
    if (lastKey.length) self.keyField.text = lastKey;
self.keyField.backgroundColor = THEME_INPUT_BG;
self.keyField.textColor = THEME_FG;
self.keyField.tintColor = THEME_ACCENT;
@@ -411,7 +421,7 @@

UILabel *footer = [UILabel new];
footer.translatesAutoresizingMaskIntoConstraints = NO;
    footer.text = @"Secured by indigo gateway · HWID-bound · 1 key = 1 device";
    footer.text = @"Secured by Byte_Ios · Developer: @nxvoid12";
footer.font = [UIFont systemFontOfSize:11 weight:UIFontWeightRegular];
footer.textColor = [THEME_MUTED colorWithAlphaComponent:0.7];
footer.textAlignment = NSTextAlignmentCenter;
@@ -501,6 +511,7 @@
[self setBusy:NO];
if (ok && token.length) {
AGSaveToken(token);
            AGSaveLastKey(key);
// Install the interceptor BEFORE any further Swift code runs so
// the Swift app's own license requests are short-circuited.
AGMarkAuthorized(token);
@@ -600,20 +611,11 @@
}

+ (void)bootstrap {
    NSString *token = AGLoadToken();
    if (token.length) {
        AGHeartbeat(token, ^(BOOL ok, NSString *_t, NSString *detail) {
            if (ok) {
                AGMarkAuthorized(token);
                [self startHeartbeatWith:token];
            } else {
                AGClearToken();
                [self presentGate];
            }
        });
    } else {
        [self presentGate];
    }
    // Policy: ask for the key on EVERY launch. The previously-used key is
    // pre-filled into the field (and surfaced as placeholder), so the user
    // just taps Activate — but the server is still contacted every time,
    // which keeps the HWID binding + revocation path honest.
    [self presentGate];
}

@end