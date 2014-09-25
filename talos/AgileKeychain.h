//
//  AgileKeychain.h
//  Talos
//
//  Created by Saumitro Dasgupta on 8/20/12.
//  Copyright (c) 2012 Saumitro Dasgupta. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "AgileKeychainItem.h"
#import "AgileKey.h"

@interface AgileKeychain : NSObject

-(id) initWithPath:(NSString*)path name:(NSString*)name;
-(BOOL) unlockWithPassword:(NSString*)masterPassword;
-(void) lock;
-(NSUInteger) numberOfItems;
-(AgileKeychainItem*) itemAtIndex:(NSUInteger)idx;
-(AgileKey*) keyForSecurityLevel:(NSString*)secLevel;
-(id) objectFromJSONFile:(NSString*)filename;

@property (readonly, retain) NSArray* items;
@property (readonly, assign) BOOL isUnlocked;

@end
