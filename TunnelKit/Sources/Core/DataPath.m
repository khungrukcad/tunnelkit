//
//  DataPath.m
//  TunnelKit
//
//  Created by Davide De Rosa on 3/2/17.
//  Copyright (c) 2018 Davide De Rosa. All rights reserved.
//
//  https://github.com/keeshux
//
//  This file is part of TunnelKit.
//
//  TunnelKit is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TunnelKit is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with TunnelKit.  If not, see <http://www.gnu.org/licenses/>.
//
//  This file incorporates work covered by the following copyright and
//  permission notice:
//
//      Copyright (c) 2018-Present Private Internet Access
//
//      Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
//      The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
//      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#import <arpa/inet.h>

#import "DataPath.h"
#import "DataPathEncryption.h"
#import "MSS.h"
#import "ReplayProtector.h"
#import "Allocation.h"
#import "Errors.h"

#define DataPathByteAlignment   16

@interface DataPath ()

@property (nonatomic, strong) id<DataPathEncrypter> encrypter;
@property (nonatomic, strong) id<DataPathDecrypter> decrypter;
@property (nonatomic, assign) int packetCapacity;

// outbound -> UDP
@property (nonatomic, strong) NSMutableArray *outPackets;
@property (nonatomic, assign) uint32_t outPacketId;
@property (nonatomic, unsafe_unretained) uint8_t *encBuffer;
@property (nonatomic, assign) int encBufferCapacity;

// inbound -> TUN
@property (nonatomic, strong) NSMutableArray *inPackets;
@property (nonatomic, strong) NSArray *inProtocols;
@property (nonatomic, unsafe_unretained) uint8_t *decBuffer;
@property (nonatomic, assign) int decBufferCapacity;
@property (nonatomic, strong) ReplayProtector *inReplay;

@property (nonatomic, copy) DataPathAssembleBlock assemblePayloadBlock;
@property (nonatomic, copy) DataPathParseBlock parsePayloadBlock;

@end

@implementation DataPath

+ (uint8_t *)alignedPointer:(uint8_t *)pointer
{
    uint8_t *stack = pointer;
    uintptr_t addr = (uintptr_t)stack;
    if (addr % DataPathByteAlignment != 0) {
        addr += DataPathByteAlignment - addr % DataPathByteAlignment;
    }
    return (uint8_t *)addr;
}

- (instancetype)initWithEncrypter:(id<DataPathEncrypter>)encrypter decrypter:(id<DataPathDecrypter>)decrypter maxPackets:(NSInteger)maxPackets usesReplayProtection:(BOOL)usesReplayProtection
{
    NSParameterAssert(encrypter);
    NSParameterAssert(decrypter);
    NSParameterAssert(maxPackets > 0);
    
    if ((self = [super init])) {
        self.encrypter = encrypter;
        self.decrypter = decrypter;
        
        self.maxPacketId = UINT32_MAX - 10000;
        self.outPackets = [[NSMutableArray alloc] initWithCapacity:maxPackets];
        self.outPacketId = 0;
        self.encBufferCapacity = 65000;
        self.encBuffer = allocate_safely(self.encBufferCapacity);
        
        self.inPackets = [[NSMutableArray alloc] initWithCapacity:maxPackets];
        NSMutableArray *protocols = [[NSMutableArray alloc] initWithCapacity:maxPackets];
        for (NSUInteger i = 0; i < maxPackets; ++i) {
            [protocols addObject:@(AF_INET)];
        }
        self.inProtocols = protocols;
        self.decBufferCapacity = 65000;
        self.decBuffer = allocate_safely(self.decBufferCapacity);
        if (usesReplayProtection) {
            self.inReplay = [[ReplayProtector alloc] init];
        }

        self.compressionFraming = CompressionFramingDisabled;
    }
    return self;
}

- (void)dealloc
{
    bzero(self.encBuffer, self.encBufferCapacity);
    bzero(self.decBuffer, self.decBufferCapacity);
    free(self.encBuffer);
    free(self.decBuffer);
}

- (void)adjustEncBufferToPacketSize:(int)size
{
    const int neededCapacity = DataPathByteAlignment + (int)safe_crypto_capacity(size, self.encrypter.overheadLength);
    if (self.encBufferCapacity >= neededCapacity) {
        return;
    }
    bzero(self.encBuffer, self.encBufferCapacity);
    free(self.encBuffer);
    self.encBufferCapacity = neededCapacity;
    self.encBuffer = allocate_safely(self.encBufferCapacity);
}

- (void)adjustDecBufferToPacketSize:(int)size
{
    const int neededCapacity = DataPathByteAlignment + (int)safe_crypto_capacity(size, self.decrypter.overheadLength);
    if (self.decBufferCapacity >= neededCapacity) {
        return;
    }
    bzero(self.decBuffer, self.decBufferCapacity);
    free(self.decBuffer);
    self.decBufferCapacity = neededCapacity;
    self.decBuffer = allocate_safely(self.decBufferCapacity);
}

- (uint8_t *)encBufferAligned
{
    return [[self class] alignedPointer:self.encBuffer];
}

- (uint8_t *)decBufferAligned
{
    return [[self class] alignedPointer:self.decBuffer];
}

- (void)setPeerId:(uint32_t)peerId
{
    NSAssert(self.encrypter, @"Setting peer-id to nil encrypter");
    NSAssert(self.decrypter, @"Setting peer-id to nil decrypter");

    [self.encrypter setPeerId:peerId];
    [self.decrypter setPeerId:peerId];
}

- (void)setCompressionFraming:(CompressionFraming)compressionFraming
{
    switch (compressionFraming) {
        case CompressionFramingDisabled: {
            self.assemblePayloadBlock = ^(uint8_t * _Nonnull packetDest, NSInteger * _Nonnull packetLengthOffset, NSData * _Nonnull payload) {
                memcpy(packetDest, payload.bytes, payload.length);
                *packetLengthOffset = 0;
            };
            self.parsePayloadBlock = ^(uint8_t * _Nonnull payload, NSInteger *payloadOffset, NSInteger * _Nonnull headerLength, const uint8_t * _Nonnull packet, NSInteger packetLength) {
                *payloadOffset = 0;
                *headerLength = 0;
            };
            break;
        }
        case CompressionFramingCompress: {
            self.assemblePayloadBlock = ^(uint8_t * _Nonnull packetDest, NSInteger * _Nonnull packetLengthOffset, NSData * _Nonnull payload) {
                memcpy(packetDest, payload.bytes, payload.length);
                packetDest[payload.length] = packetDest[0];
                packetDest[0] = CompressionFramingNoCompressSwap;
                *packetLengthOffset = 1;
            };
            self.parsePayloadBlock = ^(uint8_t * _Nonnull payload, NSInteger *payloadOffset, NSInteger * _Nonnull headerLength, const uint8_t * _Nonnull packet, NSInteger packetLength) {
                NSCAssert(payload[0] == CompressionFramingNoCompressSwap, @"Expected NO_COMPRESS_SWAP (found %X != %X)", payload[0], CompressionFramingNoCompressSwap);
                payload[0] = packet[packetLength - 1];
                *payloadOffset = 0;
                *headerLength = 1;
            };
            break;
        }
        case CompressionFramingCompLZO: {
            self.assemblePayloadBlock = ^(uint8_t * _Nonnull packetDest, NSInteger * _Nonnull packetLengthOffset, NSData * _Nonnull payload) {
                memcpy(packetDest + 1, payload.bytes, payload.length);
                packetDest[0] = CompressionFramingNoCompress;
                *packetLengthOffset = 1;
            };
            self.parsePayloadBlock = ^(uint8_t * _Nonnull payload, NSInteger *payloadOffset, NSInteger * _Nonnull headerLength, const uint8_t * _Nonnull packet, NSInteger packetLength) {
                NSCAssert(payload[0] == CompressionFramingNoCompress, @"Expected NO_COMPRESS (found %X != %X)", payload[0], CompressionFramingNoCompress);
                *payloadOffset = 1;
                *headerLength = 1;
            };
            break;
        }
    }
}

#pragma mark DataPath

- (NSArray<NSData *> *)encryptPackets:(NSArray<NSData *> *)packets key:(uint8_t)key error:(NSError *__autoreleasing *)error
{
//    NSAssert(self.encrypter.peerId == self.decrypter.peerId, @"Peer-id mismatch in DataPath encrypter/decrypter");
    
    if (self.outPacketId > self.maxPacketId) {
        if (error) {
            *error = TunnelKitErrorWithCode(TunnelKitErrorCodeDataPathOverflow);
        }
        return nil;
    }
    
    [self.outPackets removeAllObjects];
    
    for (NSData *raw in packets) {
        self.outPacketId += 1;
        
        // may resize encBuffer to hold encrypted payload
        [self adjustEncBufferToPacketSize:(int)raw.length];
        
        uint8_t *payload = self.encBufferAligned;
        NSInteger payloadLength;
        [self.encrypter assembleDataPacketWithBlock:self.assemblePayloadBlock
                                           packetId:self.outPacketId
                                            payload:raw
                                               into:payload
                                             length:&payloadLength];
        MSSFix(payload, payloadLength);
        
        NSData *encryptedPacket = [self.encrypter encryptedDataPacketWithKey:key
                                                                    packetId:self.outPacketId
                                                                     payload:payload
                                                               payloadLength:payloadLength
                                                                       error:error];
        if (!encryptedPacket) {
            return nil;
        }
        
        [self.outPackets addObject:encryptedPacket];
    }
    
    return self.outPackets;
}

- (NSArray<NSData *> *)decryptPackets:(NSArray<NSData *> *)packets keepAlive:(bool *)keepAlive error:(NSError *__autoreleasing *)error
{
//    NSAssert(self.encrypter.peerId == self.decrypter.peerId, @"Peer-id mismatch in DataPath encrypter/decrypter");

    [self.inPackets removeAllObjects];
    
    for (NSData *encryptedPacket in packets) {
        
        // may resize decBuffer to encryptedPacket.length
        [self adjustDecBufferToPacketSize:(int)encryptedPacket.length];
        
        uint8_t *packet = self.decBufferAligned;
        NSInteger packetLength = INT_MAX;
        uint32_t packetId;
        const BOOL success = [self.decrypter decryptDataPacket:encryptedPacket
                                                          into:packet
                                                        length:&packetLength
                                                      packetId:&packetId
                                                         error:error];
        if (!success) {
            return nil;
        }
        if (packetId > self.maxPacketId) {
            if (error) {
                *error = TunnelKitErrorWithCode(TunnelKitErrorCodeDataPathOverflow);
            }
            return nil;
        }
        if (self.inReplay && [self.inReplay isReplayedPacketId:packetId]) {
            continue;
        }
        
        NSInteger payloadLength;
        const uint8_t *payload = [self.decrypter parsePayloadWithBlock:self.parsePayloadBlock
                                                            dataPacket:packet
                                                          packetLength:packetLength
                                                                length:&payloadLength];
        
        if ((payloadLength == sizeof(DataPacketPingData)) && !memcmp(payload, DataPacketPingData, payloadLength)) {
            if (keepAlive) {
                *keepAlive = true;
            }
            continue;
        }
        
//        MSSFix(payload, payloadLength);
        
        NSData *raw = [[NSData alloc] initWithBytes:payload length:payloadLength];
        [self.inPackets addObject:raw];
    }
    
    return self.inPackets;
}

@end
