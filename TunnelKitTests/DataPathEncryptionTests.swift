//
//  DataPathEncryptionTests.swift
//  TunnelKitTests
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

import XCTest
@testable import TunnelKit
@testable import __TunnelKitNative

class DataPathEncryptionTests: XCTestCase {
    private var cipherKey: ZeroingData!
    
    private var hmacKey: ZeroingData!
    
    override func setUp() {
        cipherKey = try! SecureRandom.safeData(length: 32)
        hmacKey = try! SecureRandom.safeData(length: 32)
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func testCBC() {
        privateTestDataPath(cipher: "aes-128-cbc", digest: "sha256", peerId: nil)
    }
    
    func testFloatingCBC() {
        privateTestDataPath(cipher: "aes-128-cbc", digest: "sha256", peerId: 0x64385837)
    }
    
    func testGCM() {
        privateTestDataPath(cipher: "aes-256-gcm", digest: nil, peerId: nil)
    }

    func testFloatingGCM() {
        privateTestDataPath(cipher: "aes-256-gcm", digest: nil, peerId: 0x64385837)
    }
    
    func privateTestDataPath(cipher: String, digest: String?, peerId: UInt32?) {
        let box = CryptoBox(cipherAlgorithm: cipher, digestAlgorithm: digest)
        try! box.configure(withCipherEncKey: cipherKey, cipherDecKey: cipherKey, hmacEncKey: hmacKey, hmacDecKey: hmacKey)
        let enc = box.encrypter().dataPathEncrypter()
        let dec = box.decrypter().dataPathDecrypter()
        
        if let peerId = peerId {
            enc.setPeerId(peerId)
            dec.setPeerId(peerId)
            XCTAssertEqual(enc.peerId(), peerId & 0xffffff)
            XCTAssertEqual(dec.peerId(), peerId & 0xffffff)
        }
//        enc.setLZOFraming(true)
//        dec.setLZOFraming(true)

        let payload = Data(hex: "00112233445566778899")
        let packetId: UInt32 = 0x56341200
        let key: UInt8 = 4
        var encryptedPayload: [UInt8] = [UInt8](repeating: 0, count: 1000)
        var encryptedPayloadLength: Int = 0
        enc.assembleDataPacket(withPacketId: packetId, payload: payload, into: &encryptedPayload, length: &encryptedPayloadLength)
        let encrypted = try! enc.encryptedDataPacket(withKey: key, packetId: packetId, payload: encryptedPayload, payloadLength: encryptedPayloadLength)

        var decrypted: [UInt8] = [UInt8](repeating: 0, count: 1000)
        var decryptedLength: Int = 0
        var decryptedPacketId: UInt32 = 0
        var decryptedPayloadLength: Int = 0
        try! dec.decryptDataPacket(encrypted, into: &decrypted, length: &decryptedLength, packetId: &decryptedPacketId)
        let decryptedPtr = dec.parsePayload(withDataPacket: &decrypted, packetLength: decryptedLength, length: &decryptedPayloadLength)
        let decryptedPayload = Data(bytes: decryptedPtr, count: decryptedPayloadLength)

        XCTAssertEqual(payload, decryptedPayload)
        XCTAssertEqual(packetId, decryptedPacketId)
    }
}
