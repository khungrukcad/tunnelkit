//
//  DataPathEncryption.h
//  TunnelKit
//
//  Created by Davide De Rosa on 7/11/18.
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

#import <Foundation/Foundation.h>

typedef void (^DataPathAssembleBlock)(uint8_t *_Nonnull packetDest, NSInteger *_Nonnull packetLengthOffset, NSData *_Nonnull payload);
typedef void (^DataPathParseBlock)(uint8_t *_Nonnull payload, NSInteger *_Nonnull payloadOffset, NSInteger *_Nonnull headerLength, const uint8_t *_Nonnull packet, NSInteger packetLength);

@protocol DataPathChannel

- (int)overheadLength;
- (void)setPeerId:(uint32_t)peerId;

@end

@protocol DataPathEncrypter <DataPathChannel>

- (void)assembleDataPacketWithBlock:(DataPathAssembleBlock)block packetId:(uint32_t)packetId payload:(NSData *)payload into:(nonnull uint8_t *)packetBytes length:(nonnull NSInteger *)packetLength;
- (NSData *)encryptedDataPacketWithKey:(uint8_t)key packetId:(uint32_t)packetId packetBytes:(const uint8_t *)packetBytes packetLength:(NSInteger)packetLength error:(NSError **)error;

@end

@protocol DataPathDecrypter <DataPathChannel>

- (BOOL)decryptDataPacket:(nonnull NSData *)packet into:(nonnull uint8_t *)packetBytes length:(nonnull NSInteger *)packetLength packetId:(nonnull uint32_t *)packetId error:(NSError **)error;
- (nonnull const uint8_t *)parsePayloadWithBlock:(DataPathParseBlock)block length:(nonnull NSInteger *)length packetBytes:(nonnull uint8_t *)packetBytes packetLength:(NSInteger)packetLength;

@end
