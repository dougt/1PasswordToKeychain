#import <Foundation/Foundation.h>
#import <Security/SecKeychain.h>
#import <Security/SecKeychainItem.h>

#import "AgileKeychain.h"

#include <getopt.h>
// This comment is used to mark the Keychain items so that we can
// remove them when we do an update.
const char *kCommentKey = "Imported from 1Password";

SecAccessRef CreateSecurityAccess()
{
  unsigned int count = 0;
  SecTrustedApplicationRef appRefs[3];
  OSStatus secRes = SecTrustedApplicationCreateFromPath(NULL, &appRefs[count]);
  if (secRes == noErr) {
    count++;
  }
  secRes = SecTrustedApplicationCreateFromPath("/Applications/Safari.app", &appRefs[count]);
  if (secRes == noErr) {
    count++;
  }
  secRes = SecTrustedApplicationCreateFromPath("/Applications/Google Chrome.app", &appRefs[count]);
  if (secRes == noErr) {
    count++;
  }

  CFArrayRef trustedList = CFArrayCreate(NULL, (void*) appRefs, sizeof(appRefs)/sizeof(*appRefs), NULL);

  SecAccessRef accessRef;
  SecAccessCreate(CFSTR("1Password to Keychain"), trustedList, &accessRef);

  CFRelease(trustedList);
  return accessRef;
}

void AddPasswordToKeychain(NSURL *aUrl, NSString *aUsername, NSString *aPassword)
{
  if (!aUrl || !aUsername || !aPassword) {
    return;
  }
  
  const char *host = [[aUrl host] UTF8String];
  const char *path = [[aUrl path] UTF8String];
  const char *user = [aUsername UTF8String];
  const char *pass = [aPassword UTF8String];
  UInt16 port = [[aUrl port] shortValue];
  
  if (!host || !path || !user || !pass) {
    return;
  }

  bool isHttp = [[[aUrl scheme] lowercaseString] hasPrefix:@"http://"];
  SecProtocolType protocol = isHttp ? kSecProtocolTypeHTTP: kSecProtocolTypeHTTPS;

  SecKeychainAttribute attrs[] = {
    { kSecAccountItemAttr, strlen(user),        (char *) user },
    { kSecServerItemAttr,  strlen(host),        (char *) host },
    { kSecPortItemAttr,    sizeof(UInt16),      (UInt16 *) &port },
    { kSecPathItemAttr,    strlen(path),        (char *) path },
    { kSecCommentItemAttr, strlen(kCommentKey), (char *) kCommentKey },
    { kSecProtocolItemAttr, sizeof(SecProtocolType), (SecProtocolType *) &protocol }
  };
  SecKeychainAttributeList attributes = { sizeof(attrs) / sizeof(attrs[0]), attrs };
  
  SecAccessRef accessRef = CreateSecurityAccess();

  SecKeychainItemRef item = nil;
  OSStatus err = SecKeychainItemCreateFromContent(kSecInternetPasswordItemClass,
                                                  &attributes,
                                                  strlen(pass),
                                                  pass,
                                                  NULL,
                                                  accessRef,
                                                  &item);
  if (err == noErr && item) {
    NSLog(@"Adding %s", host);
    CFRelease(item);
  }

  if (accessRef) {
    CFRelease(accessRef);
  }
}

void DeleteImportedPassword() {

  const SecKeychainAttribute kCommentAttribute[1] = {
    { kSecCommentItemAttr, strlen(kCommentKey), (char*) kCommentKey }
  };
  const SecKeychainAttributeList kCommentAttributes = {1, (void*) kCommentAttribute };
  
  SecKeychainSearchRef search = NULL;
  OSStatus status = SecKeychainSearchCreateFromAttributes(NULL,
                                                          kSecInternetPasswordItemClass,
                                                          &kCommentAttributes,
                                                          &search);
  if (status != errSecSuccess) {
    return;
  }
  
  SecKeychainItemRef searchItem = NULL;
  while (SecKeychainSearchCopyNext(search, &searchItem) != errSecItemNotFound) {
    SecKeychainItemDelete(searchItem);
    CFRelease(searchItem);
  }

  CFRelease(search);
}

static void
usage(const char *name)
{
  printf("Usage: %s --password <password> --keychain <path-to-1password-keyfile>\n", name);
}

static struct option long_options[] = {
  { "password", required_argument, 0, 'p' },
  { "keychain", required_argument, 0, 'k' },
  { "help",     no_argument,       0, '?' },
  { 0,          0,                 0,  0  }
};

int main(int argc, char *argv[])
{
  const char *inputPassword, *inputPath;
  int c;
  while (1) {
    int option_index = 0;
    c = getopt_long(argc, argv, "?p:k:", long_options, &option_index);
    if (c < 0)
      break;

    switch (c) {
    case '?':
      usage(argv[0]);
      return 0;
      
    case 'p':
      inputPassword = optarg;
      break;

    case 'k':
      inputPath = optarg;
      break;

    default:
      usage(argv[0]);
      return 1;
    }
  }

  if (!inputPath || !inputPassword) {
    usage(argv[0]);
    return 1;
  }

  NSString *password = [NSString stringWithUTF8String: inputPassword];
  NSString *path = [NSString stringWithUTF8String: inputPath];

  // Clear out any passwords we've added.
  DeleteImportedPassword();
  
  AgileKeychain *keychain = [[AgileKeychain alloc] initWithPath:path name:nil];
  
  if(![keychain unlockWithPassword:password]) {
    NSLog(@"wrong password");
    return -1;
  }
  unsigned long count = [keychain numberOfItems];
  for (unsigned long i = 0; i < count; i++) {
    AgileKeychainItem *item = [keychain itemAtIndex:i];
    if ([[item type] compare: @"webforms.WebForm"] == 0) {
      NSURL *url = [NSURL URLWithString:[item location]];
      AddPasswordToKeychain(url, [item username], [item password]);
    }
  }
  return 0;
}
