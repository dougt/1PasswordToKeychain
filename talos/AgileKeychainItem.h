//
//  AgileKeychainItem.h
//  Talos
//
//  Created by Saumitro Dasgupta on 9/1/12.
//  Copyright (c) 2012 Saumitro Dasgupta. All rights reserved.
//

#import <Foundation/Foundation.h>

@class AgileKeychain;

@interface AgileKeychainItem : NSObject

+(id) keyInfoFromJSON:(NSArray*)jsonArray keychain:(AgileKeychain*)keychain;

-(NSString*) password;
-(NSString*) username;

-(void) clearPrivateData;

@property (assign) AgileKeychain* keychain;
@property (retain) NSString* identifier;
@property (retain) NSString* type;
@property (retain) NSString* title;
@property (retain) NSString* location;
@property (retain) NSDate* creationTime;

@end
