//
//  NSData+Base64Decode.m
//  Talos
//
//  Created by Saumitro Dasgupta on 9/19/12.
//  Copyright (c) 2012 Saumitro Dasgupta. All rights reserved.
//

#import "NSData+Base64Decode.h"

static const int kNumEncodingBits = 6;
static const char kPaddingSym = '=';
static const uint8_t kInvalidSym = -1;
static const uint8_t kPaddingSymValue = -2;
static const uint8_t kLUT[128] = {
    
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
};

@implementation NSData (Base64Decode)

+(NSData*) dataFromBase64:(NSString*)s
{
    const char* input = [s cStringUsingEncoding:NSASCIIStringEncoding];
    if(!input)
    {
        NSLog(@"Failed to get an ASCII representation of the string.");
        return nil;
    }
    
    NSUInteger inputLength = strlen(input);
    NSMutableData* decoded = [NSMutableData dataWithLength:(inputLength*kNumEncodingBits)/8];
    uint8_t* dataOut = [decoded mutableBytes];
    NSUInteger numBytesDecoded = 0;
    NSUInteger numBitsInBuffer = 0;
    uint32_t buffer = 0;
    
    for(NSUInteger i=0; i<inputLength; ++i)
    {
        uint8_t outputByte = kLUT[(int) input[i]];
        switch (outputByte)
        {
            case kPaddingSymValue:
                //Make sure this is at the end, and no more non-padding symbols follow.
                if(!((i==inputLength-1) || ((i==inputLength-2) && (input[inputLength-1]==kPaddingSym))))
                {
                    NSLog(@"Invalid padding detected.");
                    return nil;
                }
                break;
                
            case kInvalidSym:
                NSLog(@"Invalid character (code=%d) detected while decoding.", input[i]);
                return nil;
                
            default:
                buffer <<= kNumEncodingBits;
                buffer |= outputByte;
                numBitsInBuffer += kNumEncodingBits;
                if(numBitsInBuffer>=8)
                {
                    dataOut[numBytesDecoded++] = (uint8_t)((buffer >> (numBitsInBuffer-8)) & 0xFF);
                    numBitsInBuffer -= 8;
                }
                break;
        }
    }
    
    //Check if we have any non-padding bits left in the buffer
    if(numBitsInBuffer && (buffer & ((1<<numBitsInBuffer)-1)))
    {
        NSLog(@"Truncated data encountered.");
        return nil;
    }
    
    [decoded setLength:numBytesDecoded];
    return decoded;
}

@end
