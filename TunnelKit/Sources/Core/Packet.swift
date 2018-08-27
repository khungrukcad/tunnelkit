//
//  Packet.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 2/3/17.
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

import Foundation
import __TunnelKitNative

class CommonPacket {
    let packetId: UInt32
    
    let code: PacketCode
    
    let key: UInt8
    
    let sessionId: Data?
    
    let payload: Data?
    
    var sentDate: Date?

    static func parsed(_ stream: Data) -> (Int, [Data]) {
        var ni = 0
        var parsed: [Data] = []
        while (ni + 2 <= stream.count) {
            let packlen = Int(stream.networkUInt16Value(from: ni))
            let start = ni + 2
            let end = start + packlen
            guard (end <= stream.count) else {
                break
            }
            let packet = stream.subdata(offset: start, count: end - start)
            parsed.append(packet)
            ni = end
        }
        return (ni, parsed)
    }
    
    static func stream(_ packet: Data) -> Data {
        var stream = Data(capacity: 2 + packet.count)
        stream.append(UInt16(packet.count).bigEndian)
        stream.append(contentsOf: packet)
        return stream
    }
    
    static func stream(_ packets: [Data]) -> Data {
        var raw = Data()
        for payload in packets {
            raw.append(UInt16(payload.count).bigEndian)
            raw.append(payload)
        }
        return raw
    }
    
    init(_ packetId: UInt32, _ code: PacketCode, _ key: UInt8, _ sessionId: Data?, _ payload: Data?) {
        self.packetId = packetId
        self.code = code
        self.key = key
        self.sessionId = sessionId
        self.payload = payload
        self.sentDate = nil
    }

    // Ruby: send_ctrl
    func toBuffer() -> Data {
        var raw = PacketWithHeader(code, key, sessionId)
        raw.append(UInt8(0))
        raw.append(UInt32(packetId).bigEndian)
        if let payload = payload {
            raw.append(payload)
        }
        return raw
    }
}

class DataPacket {
    static let pingString = Data(hex: "2a187bf3641eb4cb07ed2d0a981fc748")
}
