//
//  PacketMacros.h
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
//

#import <Foundation/Foundation.h>

#define PacketPeerIdDisabled        0xffffffu
#define PacketIdLength              4

typedef NS_ENUM(uint8_t, PacketCode) {
    PacketCodeSoftResetV1           = 0x03,
    PacketCodeControlV1             = 0x04,
    PacketCodeAckV1                 = 0x05,
    PacketCodeDataV1                = 0x06,
    PacketCodeHardResetClientV2     = 0x07,
    PacketCodeHardResetServerV2     = 0x08,
    PacketCodeDataV2                = 0x09,
    PacketCodeUnknown               = 0xff
};

extern const uint8_t DataPacketPingData[16];

static inline int PacketHeaderSet(uint8_t *_Nonnull to, PacketCode code, uint8_t key)
{
    *(uint8_t *)to = (code << 3) | (key & 0b111);
    return sizeof(uint8_t);
}

// Ruby: header
static inline NSData *_Nonnull PacketWithHeader(PacketCode code, uint8_t key, NSData *sessionId)
{
    NSMutableData *to = [[NSMutableData alloc] initWithLength:(sizeof(uint8_t) + (sessionId ? sessionId.length : 0))];
    const int offset = PacketHeaderSet(to.mutableBytes, code, key);
    if (sessionId) {
        memcpy(to.mutableBytes + offset, sessionId.bytes, sessionId.length);
    }
    return to;
}

static inline int PacketHeaderSetDataV2(uint8_t *_Nonnull to, uint8_t key, uint32_t peerId)
{
    *(uint32_t *)to = ((PacketCodeDataV2 << 3) | (key & 0b111)) | htonl(peerId & 0xffffff);
    return sizeof(uint32_t);
}

static inline int PacketHeaderGetDataV2PeerId(const uint8_t *_Nonnull from)
{
    return ntohl(*(const uint32_t *)from & 0xffffff00);
}

static inline NSData *_Nonnull PacketWithHeaderDataV2(uint8_t key, uint32_t peerId, NSData *sessionId)
{
    NSMutableData *to = [[NSMutableData alloc] initWithLength:(sizeof(uint32_t) + (sessionId ? sessionId.length : 0))];
    const int offset = PacketHeaderSetDataV2(to.mutableBytes, key, peerId);
    if (sessionId) {
        memcpy(to.mutableBytes + offset, sessionId.bytes, sessionId.length);
    }
    return to;
}
