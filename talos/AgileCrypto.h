//
//  AgileCrypto.h
//  Talos
//
//  Created by Saumitro Dasgupta on 8/31/12.
//  Copyright (c) 2012 Saumitro Dasgupta. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AgileDataSaltPair : NSObject

+(id) pairFromData:(NSData*)data;

@property (retain) NSData* data;
@property (retain) NSData* salt;

@end

@interface AgileCrypto : NSObject

+(NSData*) deriveKeyUsingPassword:(NSString*)password salt:(NSData*)salt iterations:(NSUInteger)nIterations;
+(NSData*) decryptData:(NSData*)data usingKey:(NSData*)key iv:(NSData*)iv;
+(NSData*) decryptData:(NSData *)data usingKey:(NSData *)key salt:(NSData *)salt;
+(NSData*) decryptData:(NSData*)data usingDerivedKey:(NSData*)derivedKey;

@end