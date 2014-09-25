//
//  AgileKeychain.m
//  Talos
//
//  Created by Saumitro Dasgupta on 8/20/12.
//  Copyright (c) 2012 Saumitro Dasgupta. All rights reserved.
//

#import "AgileKeychain.h"
#import "AgileKeychainItem.h"
#import "AgileCrypto.h"

static NSString* const kDefaultKeychainName = @"default";
static NSString* const kDataDirName = @"data";
static NSString* const kEncryptionKeysFileName = @"encryptionKeys.js";
static NSString* const kKeychainContentsFileName = @"contents.js";
static NSString* const kKeyNameForEncryptionKeyList = @"list";

@interface AgileKeychain ()
@property (retain) NSString* path;
@property (retain) NSString* name;
@property (retain) NSMutableDictionary* keyLookup;
@property (readwrite, retain) NSArray* items;
@property (readwrite, assign) BOOL isUnlocked;
@end

@implementation AgileKeychain

@synthesize path, name;
@synthesize keyLookup, items, isUnlocked;

-(id) initWithPath:(NSString*)thePath name:(NSString*)theName
{
    if(!(self=[super init])) return nil;
    [self setPath:[thePath stringByStandardizingPath]];
    [self setName:theName?theName:kDefaultKeychainName];
    if(![self load])
    {
        [self release];
        return nil;
    }
    return self;
}

-(void) dealloc
{
    [self setPath:nil];
    [self setName:nil];
    [self setKeyLookup:nil];
    [self setItems:nil];
    [super dealloc];
}

-(NSString*) dataDirPath
{
    return [[path stringByAppendingPathComponent:kDataDirName] stringByAppendingPathComponent:name];
}

-(NSString*) pathForResource:(NSString*)filename
{
    return [[self dataDirPath] stringByAppendingPathComponent:filename];
}

-(id) objectFromJSONFile:(NSString*)filename
{
    NSString* keyFile = [self pathForResource:filename];
    NSData* jsonData = [NSData dataWithContentsOfFile:keyFile];
    if(!jsonData)
    {
        NSLog(@"Failed to read contents of file: %@", filename);
        return nil;
    }
    
    id jsonDict = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:NULL];
    if(!jsonDict)
    {
        NSLog(@"Failed to deserialize contents of JSON file: %@", filename);
        return nil;
    }
    
    return jsonDict;
}

-(BOOL) loadEncryptedKeys
{
    id keyDict = [self objectFromJSONFile:kEncryptionKeysFileName];
    if(!keyDict) return NO;
    [self setKeyLookup:[NSMutableDictionary dictionary]];
    for(NSDictionary* keyParams in keyDict[kKeyNameForEncryptionKeyList])
    {
        AgileKey* key = [AgileKey keyFromJSON:keyParams];
        if(!key)
        {
            NSLog(@"Failed to load encryption key.");
            return NO;
        }
        keyLookup[[key level]] = key;
    }
    return YES;
}

-(BOOL) loadContentsIndex
{
    NSMutableArray* keychainItems = [NSMutableArray array];
    id contentsArray = [self objectFromJSONFile:kKeychainContentsFileName];
    if(!contentsArray) return NO;
    for(NSArray* infoList in contentsArray)
    {
        AgileKeychainItem* keychainItem = [AgileKeychainItem keyInfoFromJSON:infoList keychain:self];
        if(!keychainItem)
        {
            NSLog(@"Failed to load key info.");
            continue;
        }
        if([[keychainItem type] hasPrefix:@"system."])
        {
            //Internal system keychain item. Skip.
            continue;
        }
        [keychainItems addObject:keychainItem];
    }
    [self setItems:keychainItems];
    return YES;
}

-(BOOL) load
{
    return [self loadEncryptedKeys] && [self loadContentsIndex];
}

-(NSArray*) keys
{
    return [keyLookup allValues];
}

-(BOOL) unlockWithPassword:(NSString *)masterPassword
{
    @synchronized(self)
    {
        if([self isUnlocked]) return YES;
        for(AgileKey* key in [self keys])
        {
            if(![key decryptKeyUsingPassword:masterPassword])
            {
                return NO;
            }
        }
        [self setIsUnlocked:YES];
        return YES;
    }
}

-(void) lock
{
    @synchronized(self)
    {
        for(AgileKey* key in [self keys])
        {
            [key clearDecrypted];
        }
        
        for(AgileKeychainItem* item in items)
        {
            [item clearPrivateData];
        }
        
        [self setIsUnlocked:NO];
    }
}

-(AgileKey*) keyForSecurityLevel:(NSString*)secLevel
{
    @synchronized(self)
    {
        NSAssert([self isUnlocked], @"The keychain must be unlocked first.");
        return keyLookup[secLevel];
    }
}

-(NSUInteger) numberOfItems
{
    return [items count];
}

-(AgileKeychainItem*) itemAtIndex:(NSUInteger)idx
{
    return [items objectAtIndex:idx];
}

@end
