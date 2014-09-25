//
//  AgileCrypto.m
//  Talos
//
//  Created by Saumitro Dasgupta on 8/31/12.
//  Copyright (c) 2012 Saumitro Dasgupta. All rights reserved.
//

#import "AgileCrypto.h"
#import <CommonCrypto/CommonCrypto.h>

static const int kAgileKeyLength = kCCBlockSizeAES128;
static const int kAgileIVLength = kCCBlockSizeAES128;
static const int kAgileSaltLength = 8;

static const char* kAgileKeySaltPrefix = "Salted__";
static const int kAgileKeySaltPrefixLength = 8;

static const uint8_t kNullInitializationVector[kAgileSaltLength] = {0};

@implementation AgileDataSaltPair

+(id) pairFromData:(NSData *)data
{
    const uint8_t* dataBytes = [data bytes];
    size_t dataLength = [data length];
    const uint8_t* saltBytes = kNullInitializationVector;
    if(strncmp((const char*)dataBytes, kAgileKeySaltPrefix, kAgileKeySaltPrefixLength)==0)
    {
        saltBytes = dataBytes + kAgileKeySaltPrefixLength;
        dataBytes = saltBytes + kAgileSaltLength;
        dataLength -= (kAgileKeySaltPrefixLength + kAgileSaltLength);
    }
    else
    {
        //TODO: Handle Unsalted Case
        NSLog(@"Unsalted key!!");
    }
    
    AgileDataSaltPair* pair = [[[AgileDataSaltPair alloc] init] autorelease];
    [pair setData:[NSData dataWithBytes:dataBytes length:dataLength]];
    [pair setSalt:[NSData dataWithBytes:saltBytes length:kAgileSaltLength]];
    return pair;
}

@end

@implementation AgileCrypto

+(NSData*) deriveKeyUsingPassword:(NSString*)password salt:(NSData*)salt iterations:(NSUInteger)nIterations
{
    int derivedKeyTotalSize = kAgileKeyLength + kAgileIVLength;
    NSMutableData* derivedKey = [NSMutableData dataWithLength:derivedKeyTotalSize];
    const char* passwordStr = [password UTF8String];
    int result = CCKeyDerivationPBKDF(kCCPBKDF2,
                                      passwordStr,
                                      strlen(passwordStr),
                                      [salt bytes],
                                      [salt length],
                                      kCCPRFHmacAlgSHA1,
                                      (uint)nIterations,
                                      [derivedKey mutableBytes],
                                      derivedKeyTotalSize);
    
    if(result==kCCSuccess) return derivedKey;
    return nil;
}

+(NSData*) decryptData:(NSData*)data usingKey:(NSData*)key iv:(NSData*)iv
{
    NSMutableData* cipherOut = [NSMutableData dataWithLength:[data length] + kCCBlockSizeAES128];
    size_t dataOutMoved;
    CCCryptorStatus result =  CCCrypt(kCCDecrypt,
                                      kCCAlgorithmAES128,
                                      kCCOptionPKCS7Padding,
                                      [key bytes],
                                      kAgileKeyLength,
                                      [iv bytes],
                                      [data bytes],
                                      [data length],
                                      [cipherOut mutableBytes],
                                      [cipherOut length],
                                      &dataOutMoved);
    if(result!=kCCSuccess) return nil;
    [cipherOut setLength:dataOutMoved];
    return cipherOut;
}

+(NSData*) decryptData:(NSData *)data usingKey:(NSData *)key salt:(NSData *)salt
{
    NSArray* keyIV = [self keyIVPairFromKey:key salt:salt];
    return [self decryptData:data usingKey:keyIV[0] iv:keyIV[1]];
}


+(NSData*) decryptData:(NSData*)data usingDerivedKey:(NSData*)derivedKey
{
    return [self decryptData:data
                    usingKey:[derivedKey subdataWithRange:NSMakeRange(0, kAgileKeyLength)]
                          iv:[derivedKey subdataWithRange:NSMakeRange(kAgileKeyLength, kAgileKeyLength)]];
}

//Usually, this would be handled using OpenSSL's EVP_BytesToKey function.
//However, since OpenSSL has been deprecated as of OS X 10.7, we'll implement our own.
+(NSArray*) keyIVPairFromKey:(NSData*)key salt:(NSData*)salt
{
    const unsigned int keySize = kAgileKeyLength;
    const unsigned int ivSize = kAgileIVLength;
    const unsigned int nRounds = 2; //for 128-bit
    const unsigned int hashLen = CC_MD5_DIGEST_LENGTH;
    
    NSMutableData* argData = [NSMutableData dataWithLength:hashLen];
    [argData appendData:key];
    [argData appendData:salt];
    char* argBytes = [argData mutableBytes];
    unsigned int argLen = (unsigned int)[argData length];
    unsigned char hashBuffer[hashLen];
    
    //Initialize with md5(key+salt)
    NSMutableData* resultData = [NSMutableData dataWithCapacity:nRounds*hashLen];
    CC_MD5(argBytes+hashLen, argLen-hashLen, hashBuffer);
    [resultData appendBytes:hashBuffer length:hashLen];
    
    //Generate hashes
    for(int i=1; i<nRounds; ++i)
    {
        memcpy(argBytes, hashBuffer, hashLen);
        CC_MD5(argBytes, argLen, hashBuffer);
        [resultData appendBytes:hashBuffer length:hashLen];
    }
    
    return @[[resultData subdataWithRange:NSMakeRange(0, keySize)], [resultData subdataWithRange:NSMakeRange(keySize, ivSize)]];
}

@end