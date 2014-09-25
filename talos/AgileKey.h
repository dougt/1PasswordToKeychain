//
//  AgileKey.h
//  Talos
//
//  Created by Saumitro Dasgupta on 8/30/12.
//  Copyright (c) 2012 Saumitro Dasgupta. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AgileKey : NSObject

+(id) keyFromJSON:(NSDictionary*)keyParams;

-(BOOL) decryptKeyUsingPassword:(NSString*)password;
-(NSData*) decryptData:(NSData*)data;
-(BOOL) isDecrypted;
-(void) clearDecrypted;

@property (retain) NSString* identifier;
@property (retain) NSString* level;

@end
