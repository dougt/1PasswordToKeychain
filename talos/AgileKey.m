//
//  AgileKey.m
//  Talos
//
//  Created by Saumitro Dasgupta on 8/30/12.
//  Copyright (c) 2012 Saumitro Dasgupta. All rights reserved.
//

#import "AgileKey.h"
#import "AgileCrypto.h"
#import "NSData+Base64Decode.h"

@interface AgileKey ()
@property (retain) NSData* key;
@property (retain) NSData* salt;
@property (retain) NSData* validationData;
@property (retain) NSData* encryptedKeyData;
@property (assign) NSUInteger iterations;
@end

@implementation AgileKey

@synthesize identifier, level;
@synthesize key, salt, validationData, encryptedKeyData, iterations;

+(id) keyFromJSON:(NSDictionary*)keyParams
{
    AgileKey* key = [[[AgileKey alloc] init] autorelease];
    [key setIdentifier:keyParams[@"identifier"]];
    [key setLevel:keyParams[@"level"]];
    [key setEncryptedKeyData:[NSData dataFromBase64:keyParams[@"data"]]];
    [key setValidationData:[NSData dataFromBase64:keyParams[@"validation"]]];
    [key setIterations:MAX([keyParams[@"iterations"] integerValue], 1000)];
    if(!([key identifier] && [key encryptedKeyData] && [key validationData])) return nil;
    return key;
}

-(void) dealloc
{
    [self setKey:nil];
    [self setSalt:nil];
    [self setValidationData:nil];
    [self setEncryptedKeyData:nil];
    [super dealloc];
}

-(BOOL) decryptKeyUsingPassword:(NSString*)password
{
    if(!(encryptedKeyData && validationData)) return NO;
    
    AgileDataSaltPair* pair = [AgileDataSaltPair pairFromData:[self encryptedKeyData]];
    
    //Derive key using PBKDF2
    NSData* derivedKey = [AgileCrypto deriveKeyUsingPassword:password salt:[pair salt] iterations:iterations];
    if(!derivedKey) return NO;
    
    //Decrypt to recover original key
    NSData* decryptedKey = [AgileCrypto decryptData:[pair data] usingDerivedKey:derivedKey];
    if(!decryptedKey) return NO;
    
    //Validate decrypted key
    AgileDataSaltPair* validationPair = [AgileDataSaltPair pairFromData:[self validationData]];
    NSData* vData = [AgileCrypto decryptData:[validationPair data] usingKey:decryptedKey salt:[validationPair salt]];
    BOOL success = (vData && [vData isEqualToData:decryptedKey]);
    if(success)
    {
        [self setKey:decryptedKey];
        [self setSalt:[pair salt]];
    }
    return success;
}

-(NSData*) decryptData:(NSData*)data
{
    if(!key) return nil;
    AgileDataSaltPair* pair = [AgileDataSaltPair pairFromData:data];
    return [AgileCrypto decryptData:[pair data] usingKey:[self key] salt:[pair salt]];
}

-(BOOL) isDecrypted
{
    return (key!=nil);
}

-(void) clearDecrypted
{
    [self setKey:nil];
    [self setSalt:nil];
}

@end
