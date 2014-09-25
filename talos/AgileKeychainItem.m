//
//  AgileKeychainItem.m
//  Talos
//
//  Created by Saumitro Dasgupta on 9/1/12.
//  Copyright (c) 2012 Saumitro Dasgupta. All rights reserved.
//

#import "AgileKeychainItem.h"
#import "AgileKeychain.h"
#import "NSData+Base64Decode.h"

static NSString* const kKeychainItemFileExtension = @"1password";
static NSString* const kKeyNameForSecurityLevel = @"securityLevel";
static NSString* const kKeyNameForOpenContents = @"openContents";
static NSString* const kKeyNameForEncryptedFields = @"encrypted";
static NSString* const kDefaultSecurityLevel = @"SL5";

#define RNIF(x, msg) if(!(x)) { NSLog(msg); return nil; }

@interface AgileKeychainItem ()
@property (nonatomic, retain) NSDictionary* fields;
@property (nonatomic, retain) NSString* password;
@property (nonatomic, retain) NSString* username;
@end

@implementation AgileKeychainItem

@synthesize identifier, type, title, location, creationTime, keychain;
@synthesize password = _password;
@synthesize username = _username;
@synthesize fields = _fields;

+(id) keyInfoFromJSON:(NSArray*)jsonArray keychain:(AgileKeychain*)keychain
{
    if([jsonArray count]<5) return nil;
    
    AgileKeychainItem* keyInfo = [[[AgileKeychainItem alloc] init] autorelease];
    [keyInfo setIdentifier:jsonArray[0]];
    [keyInfo setType:jsonArray[1]];
    [keyInfo setTitle:jsonArray[2]];
    [keyInfo setLocation:jsonArray[3]];
    [keyInfo setCreationTime:jsonArray[4]];
    [keyInfo setKeychain:keychain];
    
    return keyInfo;
}

-(void) dealloc
{
    [self setIdentifier:nil];
    [self setType:nil];
    [self setTitle:nil];
    [self setLocation:nil];
    [self setCreationTime:nil];
    [self setFields:nil];
    [self setPassword:nil];
    [self setUsername:nil];
    [self setKeychain:nil];
    [super dealloc];
}

-(NSDictionary*) fields
{
    if(!_fields)
    {
        //Load the key's info dict from its associated file
        NSString* filename = [[self identifier] stringByAppendingPathExtension:kKeychainItemFileExtension];
        NSDictionary* keyInfo = [[self keychain] objectFromJSONFile:filename];
        RNIF(keyInfo, @"Could not load data for keychain item");
        
        //Get the security level
        NSString* secLevel = keyInfo[kKeyNameForSecurityLevel];
        if(!secLevel)
        {
            secLevel = keyInfo[kKeyNameForOpenContents][kKeyNameForSecurityLevel];
        }
        if(!secLevel)
        {
            secLevel = kDefaultSecurityLevel;
        }
        
        //Decrypt the fields
        AgileKey* key = [keychain keyForSecurityLevel:secLevel];
        RNIF(key, @"Could not find key for item's security level")
        NSData* encrypted = [NSData dataFromBase64:keyInfo[kKeyNameForEncryptedFields]];
        RNIF(encrypted, @"Could not acquire encrypted key fields.")
        NSData* decrypted = [key decryptData:encrypted];
        RNIF(decrypted, @"Could not decrypt key fields.")
        [self setFields:[NSJSONSerialization JSONObjectWithData:decrypted options:0 error:NULL]];
        RNIF(_fields, @"Could not deserialize decrypted fields")
    }
    
    return _fields;
}

-(NSDictionary*) subFieldsWithDesignation:(NSString*)designation
{
    for(NSDictionary* subField in [self fields][@"fields"])
    {
        if([subField[@"designation"] isEqual:designation])
        {
            return subField;
        }
    }
    return nil;
}

-(NSString*) password
{
    if(!_password)
    {
        NSDictionary* fields = [self fields];
        RNIF(fields, @"Could not acquire fields for item");
        [self setPassword:fields[@"password"]];
        if(!_password)
        {
            [self setPassword:[self subFieldsWithDesignation:@"password"][@"value"]];
        }
        if(!_password)
        {
            NSLog(@"Could not locate password for item.");
        }
    }
    
    return _password;
}


-(NSString*) username
{
    if(!_username)
    {
        NSDictionary* fields = [self fields];
        RNIF(fields, @"Could not acquire fields for item");
        [self setUsername:fields[@"username"]];
        if(!_password)
        {
            [self setUsername:[self subFieldsWithDesignation:@"username"][@"value"]];
        }
        if(!_username)
        {
            NSLog(@"Could not locate username for item.");
        }
    }
    
    return _username;
}


-(void) clearPrivateData
{
    [self setPassword:nil];
    [self setFields:nil];
}

@end
