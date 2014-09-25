//
//  NSData+Base64Decode.h
//  Talos
//
//  Created by Saumitro Dasgupta on 9/19/12.
//  Copyright (c) 2012 Saumitro Dasgupta. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (Base64Decode)

+(NSData*) dataFromBase64:(NSString*)s;

@end
