//
//  AuthGate.m — indigo/dark license gate for the 3105 iOS client.
//
//  Injected at launch via LC_LOAD_DYLIB. Hooks UIApplication's initial
//  window to present a full-screen activation modal before anything else
//  draws. On success, stores the issued device key in the keychain and
//  dismisses. On failure, blocks.
//
//  Targets:   iOS 15+
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
static NSString * const kKeychainAccount    = @"com.yangjiii.3105.authgate.v1";
static NSString * const kKeychainKeyAccount = @"com.yangjiii.3105.authgate.lastkey.v1";
static NSString * const kKeychainService    = @"3105.authgate";
static NSTimeInterval const kHeartbeatInterval = 300.0;

// Indigo / Dark theme
#define THEME_BG          [UIColor colorWithRed:0.031 green:0.027 blue:0.047 alpha:1.0]
#define THEME_CARD        [UIColor colorWithRed:0.059 green:0.055 blue:0.098 alpha:1.0]
#define THEME_BORDER      [UIColor colorWithRed:0.161 green:0.145 blue:0.267 alpha:1.0]
#define THEME_FG          [UIColor colorWithRed:0.922 green:0.918 blue:0.957 alpha:1.0]
#define THEME_MUTED       [UIColor colorWithRed:0.561 green:0.549 blue:0.671 alpha:1.0]
#define THEME_ACCENT      [UIColor colorWithRed:0.545 green:0.361 blue:0.965 alpha:1.0]
#define THEME_ACCENT_HI   [UIColor colorWithRed:0.639 green:0.471 blue:0.984 alpha:1.0]
#define THEME_DANGER      [UIColor colorWithRed:0.937 green:0.267 blue:0.267 alpha:1.0]
#define THEME_INPUT_BG    [UIColor colorWithRed:0.024 green:0.020 blue:0.039 alpha:1.0]

// ---------------------------------------------------------------------------
// Device fingerprint (IDFV + model + os + salt) — SHA256 hex
// ---------------------------------------------------------------------------

static NSString *AGDeviceHash(void) {
    NSString *idfv = [UIDevice currentDevice].identifierForVendor.UUIDString ?: @"no-idfv";
    struct utsname u; uname(&u);
    NSString *model = [NSString stringWithUTF8String:u.machine];
    NSString *sys   = [[UIDevice currentDevice] systemVersion];
    NSString *salt  = @"3105-SALT-6f7a9c";
    NSString *raw   = [NSString stringWithFormat:@"%@|%@|%@|%@", idfv, model, sys, salt];

    const char *cstr = raw.UTF8String;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(cstr, (CC_LONG)strlen(cstr), digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH*2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [hex appendFormat:@"%02x", digest[i]];
    return hex;
}

static NSString *AGDeviceModel(void) {
    struct utsname u; uname(&u);
    return [NSString stringWithUTF8String:u.machine];
}

// ---------------------------------------------------------------------------
// Keychain token persistence
// ---------------------------------------------------------------------------

static NSMutableDictionary *AGQueryFor(NSString *account) {
    return [@{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainService,
        (__bridge id)kSecAttrAccount: account,
    } mutableCopy];
}

static void AGWrite(NSString *account, NSString *value) {
    if (!account.length) return;
    NSMutableDictionary *q = AGQueryFor(account);
    SecItemDelete((__bridge CFDictionaryRef)q);
    if (!value.length) return;
    q[(__bridge id)kSecValueData]      = [value dataUsingEncoding:NSUTF8StringEncoding];
    q[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;
    SecItemAdd((__bridge CFDictionaryRef)q, NULL);
}

static NSString *AGRead(NSString *account) {
    NSMutableDictionary *q = AGQueryFor(account);
    q[(__bridge id)kSecReturnData]  = @YES;
    q[(__bridge id)kSecMatchLimit]  = (__bridge id)kSecMatchLimitOne;
    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
    if (st != errSecSuccess || !out) return nil;
    NSData *data = (__bridge_transfer NSData *)out;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

static void AGSaveToken(NSString *token)   { AGWrite(kKeychainAccount, token); }
static NSString *AGLoadToken(void)         { return AGRead(kKeychainAccount); }
static void AGClearToken(void)             { AGWrite(kKeychainAccount, nil); }
static void AGSaveLastKey(NSString *key)   { AGWrite(kKeychainKeyAccount, key); }
static NSString *AGLoadLastKey(void)       { return AGRead(kKeychainKeyAccount); }

// Forward decl — defined near the NSURLSession swizzle below.
static void AGMarkAuthorized(NSString *token);
static void AGSeedBundledPatches(void);

// ---------------------------------------------------------------------------
// Backend calls
// ---------------------------------------------------------------------------

typedef void (^AGResult)(BOOL ok, NSString *token, NSString *errOrVerdict);

// NSNull-safe accessor. JSON null -> nil; non-strings become their description.
static NSString *AGStr(id v) {
    if (!v || v == (id)[NSNull null]) return nil;
    if ([v isKindOfClass:[NSString class]]) return (NSString *)v;
    if ([v isKindOfClass:[NSNumber class]]) return [(NSNumber *)v stringValue];
    return nil;
}

// Marks requests originating from this dylib so the NSURLSession swizzle
// lets them through unchanged. Any OTHER request to the gate endpoints is
// intercepted post-authorization.
static NSString * const kAGHeaderTag = @"X-AuthGate-Internal";

static void AGPostJSON(NSString *path, NSDictionary *body, AGResult cb) {
    NSURL *u = [NSURL URLWithString:[kAuthBaseURL stringByAppendingString:path]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [req setValue:@"3105-ios/2.2" forHTTPHeaderField:@"User-Agent"];
    [req setValue:@"1" forHTTPHeaderField:kAGHeaderTag];
    req.timeoutInterval = 20.0;
    NSError *je = nil;
    @try {
        req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:&je];
    } @catch (NSException *ex) {
        dispatch_async(dispatch_get_main_queue(), ^{ cb(NO, nil, ex.reason ?: @"Encoding error."); });
        return;
    }
    if (je) { dispatch_async(dispatch_get_main_queue(), ^{ cb(NO, nil, je.localizedDescription ?: @"Encoding error."); }); return; }

    NSURLSessionDataTask *t = [[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            if (e) { dispatch_async(dispatch_get_main_queue(), ^{ cb(NO, nil, e.localizedDescription ?: @"Network error."); }); return; }
            NSInteger code = [(NSHTTPURLResponse *)r statusCode];
            id j = nil;
            if (d.length) {
                @try { j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil]; }
                @catch (NSException *ex) { j = nil; }
            }
            NSDictionary *o = [j isKindOfClass:[NSDictionary class]] ? j : @{};
            NSString *tok     = AGStr(o[@"token"]) ?: AGStr(o[@"device_key"]) ?: AGStr(o[@"deviceKey"]);
            NSString *verdict = AGStr(o[@"verdict"]) ?: AGStr(o[@"status"]) ?: @"";
            NSString *detail  = AGStr(o[@"detail"])  ?: AGStr(o[@"message"]) ?: AGStr(o[@"error"]);
            BOOL ok = (code >= 200 && code < 300) && (tok.length > 0 || [verdict isEqualToString:@"allow"]);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (ok) cb(YES, tok, verdict);
                else    cb(NO, nil, detail ?: (verdict.length ? verdict : [NSString stringWithFormat:@"HTTP %ld", (long)code]));
            });
        }];
    [t resume];
}

// The hosted backend uses a 2-step native flow — /v1/activations then
// /v1/verifications. /v1/verifications accepts any signature string (server
// only looks up activationId), so we can complete it from a plain POST.
static void AGVerify(NSString *key, AGResult cb) {
    NSString *clean = [[(key ?: @"") stringByTrimmingCharactersInSet:
                       [NSCharacterSet whitespaceAndNewlineCharacterSet]] uppercaseString];
    if (!clean.length) { cb(NO, nil, @"Enter a valid license key."); return; }

    // Step 1: POST /v1/activations {key, publicKey} → {activationId}
    NSDictionary *actBody = @{
        @"key":       clean,
        @"publicKey": @"authgate.ios.v1",
    };
    NSURL *u = [NSURL URLWithString:[kAuthBaseURL stringByAppendingString:kActivatePath]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:u];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [req setValue:@"3105-ios/2.2" forHTTPHeaderField:@"User-Agent"];
    [req setValue:@"1" forHTTPHeaderField:kAGHeaderTag];
    req.timeoutInterval = 20.0;
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:actBody options:0 error:nil];

    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (e) { dispatch_async(dispatch_get_main_queue(), ^{ cb(NO, nil, e.localizedDescription); }); return; }
        NSInteger code = [(NSHTTPURLResponse *)r statusCode];
        NSDictionary *o = @{};
        if (d.length) {
            @try { id j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
                   if ([j isKindOfClass:[NSDictionary class]]) o = j; }
            @catch (NSException *ex) {}
        }
        NSString *actId = AGStr(o[@"activationId"]) ?: AGStr(o[@"activation_id"]);
        NSString *detail = AGStr(o[@"detail"]) ?: AGStr(o[@"message"]) ?: AGStr(o[@"error"]);
        if (code < 200 || code >= 300 || !actId.length) {
            dispatch_async(dispatch_get_main_queue(), ^{
                cb(NO, nil, detail.length ? detail : [NSString stringWithFormat:@"Activation failed (HTTP %ld).", (long)code]);
            });
            return;
        }

        // Step 2: POST /v1/verifications {activationId, challengeId, signature}
        NSDictionary *verBody = @{
            @"activationId": actId,
            @"challengeId":  @"authgate-direct",
            @"signature":    @"authgate-direct",
        };
        NSURL *vu = [NSURL URLWithString:[kAuthBaseURL stringByAppendingString:kVerifyPath]];
        NSMutableURLRequest *vreq = [NSMutableURLRequest requestWithURL:vu];
        vreq.HTTPMethod = @"POST";
        [vreq setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        [vreq setValue:@"3105-ios/2.2" forHTTPHeaderField:@"User-Agent"];
        [vreq setValue:@"1" forHTTPHeaderField:kAGHeaderTag];
        vreq.timeoutInterval = 20.0;
        vreq.HTTPBody = [NSJSONSerialization dataWithJSONObject:verBody options:0 error:nil];

        [[[NSURLSession sharedSession] dataTaskWithRequest:vreq completionHandler:^(NSData *d2, NSURLResponse *r2, NSError *e2) {
            if (e2) { dispatch_async(dispatch_get_main_queue(), ^{ cb(NO, nil, e2.localizedDescription); }); return; }
            NSInteger code2 = [(NSHTTPURLResponse *)r2 statusCode];
            NSDictionary *o2 = @{};
            if (d2.length) {
                @try { id j = [NSJSONSerialization JSONObjectWithData:d2 options:0 error:nil];
                       if ([j isKindOfClass:[NSDictionary class]]) o2 = j; }
                @catch (NSException *ex) {}
            }
            NSString *stat = AGStr(o2[@"status"]) ?: @"";
            NSString *detail2 = AGStr(o2[@"detail"]) ?: AGStr(o2[@"message"]) ?: AGStr(o2[@"error"]);
            BOOL ok2 = (code2 >= 200 && code2 < 300) && ([stat isEqualToString:@"active"] || [stat isEqualToString:@"ok"]);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (ok2) cb(YES, actId, @"allow");
                else     cb(NO, nil, detail2.length ? detail2 : [NSString stringWithFormat:@"Verify failed (HTTP %ld).", (long)code2]);
            });
        }] resume];
    }] resume];
}

static void AGHeartbeat(NSString *token, AGResult cb) {
    // The hosted backend has no dedicated heartbeat route. Re-run step 2
    // against the stored activationId; a 200 with status=active means the
    // license is still live.
    if (!token.length) { cb(NO, nil, @"No stored activation."); return; }
    NSDictionary *verBody = @{
        @"activationId": token,
        @"challengeId":  @"authgate-heartbeat",
        @"signature":    @"authgate-heartbeat",
    };
    NSURL *vu = [NSURL URLWithString:[kAuthBaseURL stringByAppendingString:kVerifyPath]];
    NSMutableURLRequest *vreq = [NSMutableURLRequest requestWithURL:vu];
    vreq.HTTPMethod = @"POST";
    [vreq setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [vreq setValue:@"3105-ios/2.2" forHTTPHeaderField:@"User-Agent"];
    [vreq setValue:@"1" forHTTPHeaderField:kAGHeaderTag];
    vreq.timeoutInterval = 20.0;
    vreq.HTTPBody = [NSJSONSerialization dataWithJSONObject:verBody options:0 error:nil];
    [[[NSURLSession sharedSession] dataTaskWithRequest:vreq completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (e) { dispatch_async(dispatch_get_main_queue(), ^{ cb(NO, nil, e.localizedDescription); }); return; }
        NSInteger code = [(NSHTTPURLResponse *)r statusCode];
        NSDictionary *o = @{};
        if (d.length) {
            @try { id j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
                   if ([j isKindOfClass:[NSDictionary class]]) o = j; }
            @catch (NSException *ex) {}
        }
        NSString *stat = AGStr(o[@"status"]) ?: @"";
        BOOL ok = (code >= 200 && code < 300) && ([stat isEqualToString:@"active"] || [stat isEqualToString:@"ok"]);
        dispatch_async(dispatch_get_main_queue(), ^{ cb(ok, ok ? token : nil, stat); });
    }] resume];
}

// ---------------------------------------------------------------------------
// AuthGateViewController — the gate UI
// ---------------------------------------------------------------------------

@interface AuthGateViewController : UIViewController <UITextFieldDelegate>
@property (nonatomic, strong) UITextField  *keyField;
@property (nonatomic, strong) UIButton     *activateBtn;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@property (nonatomic, strong) UILabel      *errorLabel;
@property (nonatomic, strong) UILabel      *subtitle;
@property (nonatomic, strong) CAGradientLayer *haloLayer;
@property (nonatomic, copy)   void (^onSuccess)(NSString *token);
@end

@implementation AuthGateViewController

- (UIStatusBarStyle)preferredStatusBarStyle { return UIStatusBarStyleLightContent; }
- (BOOL)prefersHomeIndicatorAutoHidden { return NO; }
- (UIModalPresentationStyle)modalPresentationStyle { return UIModalPresentationFullScreen; }

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = THEME_BG;
    self.modalInPresentation = YES;
    [self addGridOverlay];
    [self buildUI];
}

- (void)addGridOverlay {
    self.haloLayer = [CAGradientLayer layer];
    self.haloLayer.frame = self.view.bounds;
    self.haloLayer.colors = @[
        (id)[UIColor colorWithRed:0.545 green:0.361 blue:0.965 alpha:0.18].CGColor,
        (id)[UIColor clearColor].CGColor,
    ];
    self.haloLayer.startPoint = CGPointMake(0.5, 0);
    self.haloLayer.endPoint   = CGPointMake(0.5, 0.6);
    [self.view.layer insertSublayer:self.haloLayer atIndex:0];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    self.haloLayer.frame = self.view.bounds;
}

- (void)buildUI {
    UIView *card = [UIView new];
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.backgroundColor = THEME_CARD;
    card.layer.cornerRadius = 20;
    card.layer.borderColor = THEME_BORDER.CGColor;
    card.layer.borderWidth = 1.0;
    card.layer.shadowColor = THEME_ACCENT.CGColor;
    card.layer.shadowOpacity = 0.15;
    card.layer.shadowRadius = 32;
    card.layer.shadowOffset = CGSizeMake(0, 16);
    [self.view addSubview:card];

    UILabel *brand = [UILabel new];
    brand.translatesAutoresizingMaskIntoConstraints = NO;
    brand.text = @"BYTE EXTERNAL";
    brand.font = [UIFont systemFontOfSize:24 weight:UIFontWeightBlack];
    brand.textColor = THEME_FG;
    brand.textAlignment = NSTextAlignmentCenter;
    brand.adjustsFontSizeToFitWidth = YES;
    brand.minimumScaleFactor = 0.7;
    [card addSubview:brand];

    UILabel *title = [UILabel new];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"License Activation";
    title.font = [UIFont systemFontOfSize:20 weight:UIFontWeightSemibold];
    title.textColor = THEME_FG;
    title.textAlignment = NSTextAlignmentCenter;
    [card addSubview:title];

    self.subtitle = [UILabel new];
    self.subtitle.translatesAutoresizingMaskIntoConstraints = NO;
    self.subtitle.text = @"Enter your license key to continue.\nOne key binds to one device.";
    self.subtitle.font = [UIFont systemFontOfSize:13 weight:UIFontWeightRegular];
    self.subtitle.textColor = THEME_MUTED;
    self.subtitle.textAlignment = NSTextAlignmentCenter;
    self.subtitle.numberOfLines = 0;
    [card addSubview:self.subtitle];

    self.keyField = [UITextField new];
    self.keyField.translatesAutoresizingMaskIntoConstraints = NO;
    NSString *lastKey = AGLoadLastKey();
    NSString *placeholder = lastKey.length ? lastKey : @"XXXX-XXXX-XXXX-XXXX";
    self.keyField.placeholder = placeholder;
    self.keyField.attributedPlaceholder = [[NSAttributedString alloc]
        initWithString:placeholder
            attributes:@{NSForegroundColorAttributeName: [THEME_MUTED colorWithAlphaComponent:0.6],
                         NSFontAttributeName:[UIFont monospacedSystemFontOfSize:15 weight:UIFontWeightMedium]}];
    // Pre-fill the field so the user can simply tap Activate.
    if (lastKey.length) self.keyField.text = lastKey;
    self.keyField.backgroundColor = THEME_INPUT_BG;
    self.keyField.textColor = THEME_FG;
    self.keyField.tintColor = THEME_ACCENT;
    self.keyField.font = [UIFont monospacedSystemFontOfSize:15 weight:UIFontWeightMedium];
    self.keyField.textAlignment = NSTextAlignmentCenter;
    self.keyField.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    self.keyField.autocorrectionType = UITextAutocorrectionTypeNo;
    self.keyField.spellCheckingType = UITextSpellCheckingTypeNo;
    self.keyField.returnKeyType = UIReturnKeyGo;
    self.keyField.delegate = self;
    self.keyField.layer.cornerRadius = 12;
    self.keyField.layer.borderColor = THEME_BORDER.CGColor;
    self.keyField.layer.borderWidth = 1.0;
    UIView *pad = [[UIView alloc] initWithFrame:CGRectMake(0,0,16,0)];
    self.keyField.leftView = pad; self.keyField.leftViewMode = UITextFieldViewModeAlways;
    self.keyField.rightView = pad; self.keyField.rightViewMode = UITextFieldViewModeAlways;
    [card addSubview:self.keyField];

    self.errorLabel = [UILabel new];
    self.errorLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.errorLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightMedium];
    self.errorLabel.textColor = THEME_DANGER;
    self.errorLabel.textAlignment = NSTextAlignmentCenter;
    self.errorLabel.numberOfLines = 0;
    self.errorLabel.alpha = 0.0;
    [card addSubview:self.errorLabel];

    self.activateBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.activateBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [self.activateBtn setTitle:@"Activate" forState:UIControlStateNormal];
    self.activateBtn.titleLabel.font = [UIFont systemFontOfSize:16 weight:UIFontWeightBold];
    [self.activateBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.activateBtn.backgroundColor = THEME_ACCENT;
    self.activateBtn.layer.cornerRadius = 12;
    [self.activateBtn addTarget:self action:@selector(didTapActivate) forControlEvents:UIControlEventTouchUpInside];
    [card addSubview:self.activateBtn];

    self.spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.spinner.translatesAutoresizingMaskIntoConstraints = NO;
    self.spinner.color = [UIColor whiteColor];
    self.spinner.hidesWhenStopped = YES;
    [self.activateBtn addSubview:self.spinner];

    UILabel *footer = [UILabel new];
    footer.translatesAutoresizingMaskIntoConstraints = NO;
    footer.text = @"Secured by Byte_Ios · Developer: @nxvoid12";
    footer.font = [UIFont systemFontOfSize:11 weight:UIFontWeightRegular];
    footer.textColor = [THEME_MUTED colorWithAlphaComponent:0.7];
    footer.textAlignment = NSTextAlignmentCenter;
    footer.numberOfLines = 0;
    [self.view addSubview:footer];

    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [card.leadingAnchor  constraintEqualToAnchor:g.leadingAnchor  constant:24],
        [card.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-24],
        [card.centerYAnchor  constraintEqualToAnchor:g.centerYAnchor],

        [brand.topAnchor      constraintEqualToAnchor:card.topAnchor constant:32],
        [brand.centerXAnchor  constraintEqualToAnchor:card.centerXAnchor],

        [title.topAnchor      constraintEqualToAnchor:brand.bottomAnchor constant:4],
        [title.centerXAnchor  constraintEqualToAnchor:card.centerXAnchor],

        [self.subtitle.topAnchor      constraintEqualToAnchor:title.bottomAnchor constant:8],
        [self.subtitle.leadingAnchor  constraintEqualToAnchor:card.leadingAnchor constant:24],
        [self.subtitle.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-24],

        [self.keyField.topAnchor      constraintEqualToAnchor:self.subtitle.bottomAnchor constant:28],
        [self.keyField.leadingAnchor  constraintEqualToAnchor:card.leadingAnchor constant:20],
        [self.keyField.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-20],
        [self.keyField.heightAnchor   constraintEqualToConstant:52],

        [self.errorLabel.topAnchor      constraintEqualToAnchor:self.keyField.bottomAnchor constant:12],
        [self.errorLabel.leadingAnchor  constraintEqualToAnchor:card.leadingAnchor constant:24],
        [self.errorLabel.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-24],

        [self.activateBtn.topAnchor      constraintEqualToAnchor:self.errorLabel.bottomAnchor constant:16],
        [self.activateBtn.leadingAnchor  constraintEqualToAnchor:card.leadingAnchor constant:20],
        [self.activateBtn.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-20],
        [self.activateBtn.heightAnchor   constraintEqualToConstant:52],
        [self.activateBtn.bottomAnchor   constraintEqualToAnchor:card.bottomAnchor constant:-28],

        [self.spinner.centerXAnchor constraintEqualToAnchor:self.activateBtn.centerXAnchor],
        [self.spinner.centerYAnchor constraintEqualToAnchor:self.activateBtn.centerYAnchor],

        [footer.leadingAnchor  constraintEqualToAnchor:g.leadingAnchor  constant:24],
        [footer.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-24],
        [footer.bottomAnchor   constraintEqualToAnchor:g.bottomAnchor   constant:-20],
    ]];

    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(dismissKb)];
    tap.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:tap];
}

- (void)dismissKb { [self.view endEditing:YES]; }

- (BOOL)textFieldShouldReturn:(UITextField *)tf {
    [tf resignFirstResponder];
    [self didTapActivate];
    return NO;
}

- (void)showError:(NSString *)msg {
    self.errorLabel.text = msg ?: @"Activation failed.";
    [UIView animateWithDuration:0.25 animations:^{ self.errorLabel.alpha = 1.0; }];
    CAKeyframeAnimation *shake = [CAKeyframeAnimation animationWithKeyPath:@"transform.translation.x"];
    shake.values = @[@-10, @10, @-6, @6, @-3, @3, @0];
    shake.duration = 0.35;
    [self.view.layer addAnimation:shake forKey:@"shake"];
}

- (void)setBusy:(BOOL)busy {
    self.activateBtn.enabled = !busy;
    self.keyField.enabled = !busy;
    [self.activateBtn setTitle:(busy ? @"" : @"Activate") forState:UIControlStateNormal];
    if (busy) [self.spinner startAnimating]; else [self.spinner stopAnimating];
    self.activateBtn.backgroundColor = busy ? THEME_ACCENT_HI : THEME_ACCENT;
}

- (void)didTapActivate {
    NSString *key = [[self.keyField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] uppercaseString];
    if (key.length < 8) { [self showError:@"Enter a valid license key."]; return; }
    [self.view endEditing:YES];
    self.errorLabel.alpha = 0.0;
    [self setBusy:YES];

    __weak __typeof__(self) weakSelf = self;
    AGVerify(key, ^(BOOL ok, NSString *token, NSString *detail) {
        __strong __typeof__(weakSelf) self = weakSelf;
        if (!self) return;
        [self setBusy:NO];
        if (ok && token.length) {
            AGSaveToken(token);
            AGSaveLastKey(key);
            // Install the interceptor BEFORE any further Swift code runs so
            // the Swift app's own license requests are short-circuited.
            AGMarkAuthorized(token);

            void (^finish)(void) = ^{
                @try {
                    if (self.onSuccess) self.onSuccess(token);
                } @catch (NSException *ex) {
                    NSLog(@"[AuthGate] onSuccess threw: %@", ex);
                }
                @try { AGSeedBundledPatches(); }
                @catch (NSException *ex) { NSLog(@"[AuthGate] seed threw: %@", ex); }
                @try {
                    // Hide first, then dismiss on the next runloop tick so no
                    // UIView* teardown overlaps the Swift app's resume path.
                    self.view.hidden = YES;
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [self dismissViewControllerAnimated:NO completion:nil];
                    });
                } @catch (NSException *ex) {
                    NSLog(@"[AuthGate] dismiss threw: %@", ex);
                }
            };
            // Tiny delay to let the swizzle settle before dismissal gives
            // control back to the Swift launch continuation.
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.15 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), finish);
        } else {
            [self showError:detail.length ? detail : @"Activation rejected."];
        }
    });
}

@end

// ---------------------------------------------------------------------------
// Launch hook — present the gate before anything paints
// ---------------------------------------------------------------------------

@interface AuthGateLauncher : NSObject
+ (void)presentGate;
+ (void)startHeartbeatWith:(NSString *)token;
@end

@implementation AuthGateLauncher

static NSTimer *_agHeartbeatTimer = nil;

+ (UIWindow *)findKeyWindow {
    if (@available(iOS 13.0, *)) {
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) {
            if (s.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *w in s.windows) if (w.isKeyWindow) return w;
                if (s.windows.firstObject) return s.windows.firstObject;
            }
        }
        for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes)
            if (s.windows.firstObject) return s.windows.firstObject;
    }
    return [UIApplication sharedApplication].keyWindow;
}

+ (UIViewController *)topViewController {
    UIWindow *w = [self findKeyWindow];
    UIViewController *vc = w.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

+ (void)presentGate {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *top = [self topViewController];
        if (!top) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ [self presentGate]; });
            return;
        }
        if ([NSStringFromClass([top class]) isEqualToString:@"AuthGateViewController"]) return;

        AuthGateViewController *gate = [AuthGateViewController new];
        gate.modalPresentationStyle = UIModalPresentationFullScreen;
        gate.onSuccess = ^(NSString *tok) { [self startHeartbeatWith:tok]; };
        [top presentViewController:gate animated:NO completion:nil];
    });
}

+ (void)startHeartbeatWith:(NSString *)token {
    if (!token.length) return;
    if (_agHeartbeatTimer) [_agHeartbeatTimer invalidate];
    _agHeartbeatTimer = [NSTimer scheduledTimerWithTimeInterval:kHeartbeatInterval
                                                        repeats:YES
                                                          block:^(NSTimer *t) {
        NSString *tok = AGLoadToken();
        if (!tok.length) { [t invalidate]; return; }
        AGHeartbeat(tok, ^(BOOL ok, NSString *_t, NSString *detail) {
            if (!ok) { AGClearToken(); [t invalidate]; [AuthGateLauncher presentGate]; }
        });
    }];
}

+ (void)bootstrap {
    // Policy: ask for the key on EVERY launch. The previously-used key is
    // pre-filled into the field (and surfaced as placeholder), so the user
    // just taps Activate — but the server is still contacted every time,
    // which keeps the HWID binding + revocation path honest.
    [self presentGate];
}

@end

// ---------------------------------------------------------------------------
// NSURLSession swizzle — once the gate authorizes, shield the Swift / Rust
// layer from making its own license requests. The Swift Codable / Rust serde
// decoders are strict; any field they didn't expect panics. Return a canned
// authorized envelope locally instead of letting the Swift app hit the wire.
// ---------------------------------------------------------------------------

static BOOL _agAuthorized = NO;
static NSString *_agCachedToken = nil;

static NSSet<NSString *> *AGInterceptedPaths(void) {
    static NSSet *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        s = [NSSet setWithArray:@[ @"/v1/verifications", @"/v1/device-check", @"/v1/tunnel-report" ]];
    });
    return s;
}

static NSData *AGCannedPayload(NSString *path, NSString *token) {
    NSString *tok = token.length ? token : (_agCachedToken.length ? _agCachedToken : @"");
    long long now = (long long)[[NSDate date] timeIntervalSince1970];
    long long farFuture = 4102444799LL;  // 2099-12-31T23:59:59Z
    NSString *farIso = @"2099-12-31T23:59:59+00:00";
    NSDictionary *o = nil;
    if ([path hasSuffix:@"/v1/tunnel-report"]) {
        o = @{ @"status": @"ok", @"received": @YES, @"server_time": @(now) };
    } else if ([path hasSuffix:@"/v1/device-check"]) {
        o = @{
            @"verdict": @"allow", @"status": @"active", @"valid": @YES,
            @"expires_at": farIso, @"expiresAt": farIso,
            @"expires_at_epoch": @(farFuture), @"expiresAtEpoch": @(farFuture),
            @"server_time": @(now), @"serverTime": @(now),
            @"lease_ttl_hours": @12, @"leaseTtlHours": @12,
            @"signature": @"",
        };
    } else {  // /v1/verifications
        o = @{
            @"status": @"verified", @"verdict": @"allow",
            @"activation_id": tok.length ? tok : @"allow",
            @"activationId":  tok.length ? tok : @"allow",
            @"token": tok, @"device_key": tok, @"deviceKey": tok,
            @"expires_at": farIso, @"expiresAt": farIso,
            @"expires_at_epoch": @(farFuture), @"expiresAtEpoch": @(farFuture),
            @"grace_hours": @24, @"graceHours": @24,
            @"lease_ttl_hours": @12, @"leaseTtlHours": @12,
            @"server_time": @(now), @"serverTime": @(now),
            @"issued_at": @(now), @"issuedAt": @(now),
        };
    }
    return [NSJSONSerialization dataWithJSONObject:o options:0 error:nil];
}

static BOOL AGShouldIntercept(NSURLRequest *req) {
    if (!_agAuthorized) return NO;
    if ([[req valueForHTTPHeaderField:kAGHeaderTag] isEqualToString:@"1"]) return NO;
    NSString *path = req.URL.path ?: @"";
    for (NSString *p in AGInterceptedPaths()) {
        if ([path hasSuffix:p]) return YES;
    }
    return NO;
}

static NSURLSessionDataTask *(*AG_orig_dataTaskWithRequestCompletion)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)) = NULL;

static NSURLSessionDataTask *AG_swz_dataTaskWithRequestCompletion(id self_, SEL _cmd, NSURLRequest *req,
                                                                   void (^completion)(NSData *, NSURLResponse *, NSError *)) {
    if (AGShouldIntercept(req)) {
        NSData *payload = AGCannedPayload(req.URL.path ?: @"", _agCachedToken);
        NSHTTPURLResponse *resp = [[NSHTTPURLResponse alloc] initWithURL:req.URL
                                                              statusCode:200
                                                             HTTPVersion:@"HTTP/1.1"
                                                            headerFields:@{ @"Content-Type": @"application/json" }];
        // Return a no-op task that fires the completion on a background queue,
        // mirroring NSURLSession semantics.
        NSURLSessionDataTask *task = AG_orig_dataTaskWithRequestCompletion(self_, _cmd,
            [NSURLRequest requestWithURL:[NSURL URLWithString:@"about:blank"]], ^(NSData *_d, NSURLResponse *_r, NSError *_e) {
                if (completion) completion(payload, resp, nil);
            });
        return task;
    }
    return AG_orig_dataTaskWithRequestCompletion(self_, _cmd, req, completion);
}

static void AGInstallSessionSwizzle(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Class cls = NSClassFromString(@"NSURLSession");
        SEL sel = @selector(dataTaskWithRequest:completionHandler:);
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) return;
        AG_orig_dataTaskWithRequestCompletion = (void *)method_getImplementation(m);
        method_setImplementation(m, (IMP)AG_swz_dataTaskWithRequestCompletion);
        NSLog(@"[AuthGate] NSURLSession.dataTaskWithRequest: swizzled");
    });
}

static void AGMarkAuthorized(NSString *token) {
    _agCachedToken = [token copy];
    _agAuthorized = YES;
    AGInstallSessionSwizzle();
}

// ---------------------------------------------------------------------------
// Bundled patch seeding — ship default .3105 packs in the bundle and feed
// them to the app's own import pathway once, after the user authorizes.
// Runs through +[UIApplication openURL:…] so the PatchLibrary DB records a
// normal import; guarded by a UserDefaults flag so later user deletes/moves
// aren't clobbered on next launch.
// ---------------------------------------------------------------------------

// The app registers URL scheme "threeoneosfive" (from Info.plist CFBundleURLSchemes)
// and its SwiftUI .onOpenURL handler recognises `threeoneosfive://import?url=<file-url>`
// as a patch-import request — see 3105 binary FUN_1002c21d0 / FUN_1002c2620.
// Opening that URL through UIApplication routes back to this process via
// scene URL contexts → SwiftUI onOpenURL → the native import pipeline, with
// the proper StateObject context (impossible to reconstruct from a dylib).
// Same-app UIApplication.openURL returns YES but iOS never redelivers the URL
// to a running app via onOpenURL — "accepted" ≠ "fired". The working path is
// to synthesise a UIOpenURLContext and hand it to the scene delegate directly;
// SwiftUI's private scene adapter forwards contexts to its onOpenURL subscribers.
// We wrap the file URL inside `threeoneosfive://import?url=<file-url>` so the
// app's handler (FUN_1002c21d0 → FUN_1002c2620) classifies it as a patch file.
static void AGFeedPatchToApp(NSURL *fileURL, void (^done)(BOOL ok)) {
    NSCharacterSet *allowed = [NSCharacterSet URLQueryAllowedCharacterSet];
    NSString *enc = [fileURL.absoluteString stringByAddingPercentEncodingWithAllowedCharacters:allowed];
    if (!enc.length) { if (done) done(NO); return; }
    NSString *urlStr = [NSString stringWithFormat:@"threeoneosfive://import?url=%@", enc];
    NSURL *openURL = [NSURL URLWithString:urlStr];
    if (!openURL) { if (done) done(NO); return; }

    __block BOOL delivered = NO;
    Class ctxCls = NSClassFromString(@"UIOpenURLContext");
    if (ctxCls) {
        for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (![scene isKindOfClass:[UIWindowScene class]]) continue;
            @try {
                id ctx = [[ctxCls alloc] init];
                // UIOpenURLContext has readonly URL / options — set via KVC.
                [ctx setValue:openURL forKey:@"URL"];
                NSSet *contexts = [NSSet setWithObject:ctx];
                id sd = scene.delegate;
                // SwiftUI's scene delegate is a private class that implements
                // scene:openURLContexts:; call directly if available.
                if ([sd respondsToSelector:@selector(scene:openURLContexts:)]) {
                    [sd scene:scene openURLContexts:contexts];
                    delivered = YES;
                }
                // Also post the scene connection notification SwiftUI watches —
                // some SwiftUI builds subscribe via NSNotificationCenter rather
                // than delegate, so belt-and-braces.
                [[NSNotificationCenter defaultCenter]
                    postNotificationName:@"UISceneDidOpenURLsNotification"
                                  object:scene
                                userInfo:@{ @"UISceneOpenURLContexts": contexts }];
            } @catch (NSException *ex) {
                NSLog(@"[AuthGate] scene openURLContexts threw: %@", ex);
            }
        }
    }

    // Fallback: still fire UIApplication.openURL in case the device is on an
    // iOS build where that path IS redelivered.
    @try {
        [[UIApplication sharedApplication] openURL:openURL
                                           options:@{}
                                 completionHandler:^(BOOL ok) {
            if (done) done(delivered || ok);
        }];
    } @catch (NSException *ex) {
        if (done) done(delivered);
    }
}

static void AGSeedBundledPatches(void) {
    NSString * const kSeededKey = @"AuthGate.PatchesSeeded.v7";
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    if ([ud boolForKey:kSeededKey]) return;

    NSString *src = [[NSBundle mainBundle].bundlePath
                        stringByAppendingPathComponent:@"BundledPatches"];
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:src isDirectory:&isDir] || !isDir) return;

    NSArray<NSString *> *entries = [fm contentsOfDirectoryAtPath:src error:nil];
    NSMutableArray<NSURL *> *targets = [NSMutableArray array];
    NSString *tmpDir = [NSTemporaryDirectory() stringByAppendingPathComponent:@"ByteSeed"];
    [fm createDirectoryAtPath:tmpDir withIntermediateDirectories:YES attributes:nil error:nil];
    for (NSString *name in entries) {
        if (![[name pathExtension] isEqualToString:@"3105"]) continue;
        NSString *srcPath = [src stringByAppendingPathComponent:name];
        NSString *dstPath = [tmpDir stringByAppendingPathComponent:name];
        [fm removeItemAtPath:dstPath error:nil];
        if ([fm copyItemAtPath:srcPath toPath:dstPath error:nil]) {
            [targets addObject:[NSURL fileURLWithPath:dstPath]];
        }
    }
    if (targets.count == 0) return;

    __block NSUInteger okCount = 0;
    __block NSUInteger idx = 0;
    NSMutableArray *log = [NSMutableArray array];
    NSMutableArray *holder = [NSMutableArray arrayWithCapacity:1];
    void (^feedNext)(void) = ^{
        if (idx >= targets.count) {
            NSLog(@"[AuthGate] seeded %lu / %lu bundled patches via openURL",
                  (unsigned long)okCount, (unsigned long)targets.count);
            // Diagnostic alert so we can see what iOS actually did.
            NSString *msg = [NSString stringWithFormat:@"openURL ok=%lu/%lu\n\n%@",
                             (unsigned long)okCount, (unsigned long)targets.count,
                             [log componentsJoinedByString:@"\n"]];
            UIAlertController *ac = [UIAlertController
                alertControllerWithTitle:@"AuthGate seed diag"
                                 message:msg
                          preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"OK"
                                                   style:UIAlertActionStyleDefault
                                                 handler:nil]];
            UIViewController *top = nil;
            for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) {
                for (UIWindow *w in s.windows) {
                    if (w.isKeyWindow) { top = w.rootViewController; break; }
                }
                if (top) break;
            }
            while (top.presentedViewController) top = top.presentedViewController;
            @try { [top presentViewController:ac animated:YES completion:nil]; }
            @catch (NSException *ex) { NSLog(@"[AuthGate] diag present: %@", ex); }

            if (okCount == targets.count) {
                [ud setBool:YES forKey:kSeededKey];
                [ud synchronize];
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(25 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{
                    for (NSURL *u in targets) {
                        [[NSFileManager defaultManager] removeItemAtURL:u error:nil];
                    }
                });
            }
            [holder removeAllObjects];
            return;
        }
        NSURL *u = targets[idx++];
        AGFeedPatchToApp(u, ^(BOOL ok) {
            if (ok) okCount++;
            [log addObject:[NSString stringWithFormat:@"%@ -> %@",
                            u.lastPathComponent, ok ? @"YES" : @"NO"]];
            void (^next)(void) = holder.firstObject;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), next ?: ^{});
        });
    };
    [holder addObject:[feedNext copy]];

    // Wait long enough that the SwiftUI scene is up and the onOpenURL handler is wired.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        void (^next)(void) = holder.firstObject;
        if (next) next();
    });
}

// ---------------------------------------------------------------------------
// UIImage swizzle — replace the app's "AppIcon" references with AppLogo.png
// shipped at the bundle root. The Swift app loads the icon through
// +[UIImage imageNamed:], so intercepting that one call replaces every
// in-app occurrence of the icon.
// ---------------------------------------------------------------------------

static UIImage *(*_ag_orig_imageNamed)(id, SEL, NSString *) = NULL;

static UIImage *ag_swz_imageNamed(id self_, SEL _cmd, NSString *name) {
    if (name.length) {
        NSString *lo = [name lowercaseString];
        if ([lo containsString:@"appicon"] ||
            [lo isEqualToString:@"logo"] ||
            [lo isEqualToString:@"applogo"] ||
            [lo isEqualToString:@"brandlogo"]) {
            static UIImage *cached = nil;
            static dispatch_once_t once;
            dispatch_once(&once, ^{
                NSString *p = [[NSBundle mainBundle].bundlePath
                                stringByAppendingPathComponent:@"AppLogo.png"];
                cached = [UIImage imageWithContentsOfFile:p];
            });
            if (cached) return cached;
        }
    }
    return _ag_orig_imageNamed(self_, _cmd, name);
}

static void AGInstallImageSwizzle(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Method m = class_getClassMethod([UIImage class], @selector(imageNamed:));
        if (!m) return;
        _ag_orig_imageNamed = (void *)method_getImplementation(m);
        method_setImplementation(m, (IMP)ag_swz_imageNamed);
        NSLog(@"[AuthGate] UIImage imageNamed: swizzled -> AppLogo.png");
    });
}

// ---------------------------------------------------------------------------
// Entry: dylib load constructor
// ---------------------------------------------------------------------------

__attribute__((constructor))
static void AuthGateInit(void) {
    NSLog(@"[AuthGate] injected into %@", [[NSBundle mainBundle] bundleIdentifier]);
    AGInstallImageSwizzle();
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification *n) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.05 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [AuthGateLauncher bootstrap];
        });
    }];
    // Belt-and-suspenders: also fire on becoming active (covers Scene lifecycle).
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                      object:nil queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification *n) {
        static dispatch_once_t once; dispatch_once(&once, ^{
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                UIViewController *top = [AuthGateLauncher topViewController];
                if (![NSStringFromClass([top class]) isEqualToString:@"AuthGateViewController"])
                    [AuthGateLauncher bootstrap];
            });
        });
    }];
}