//
//  EncryptionTests.swift
//  TunnelKitTests
//
//  Created by Davide De Rosa on 7/7/18.
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

class EncryptionTests: XCTestCase {
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
        let cbc = CryptoBox(cipherAlgorithm: "aes-128-cbc", digestAlgorithm: "sha256")
        try! cbc.configure(withCipherEncKey: cipherKey, cipherDecKey: cipherKey, hmacEncKey: hmacKey, hmacDecKey: hmacKey)
        let enc = cbc.encrypter()
        let dec = cbc.decrypter()
        
        let plain = Data(hex: "00112233445566778899")
        let encrypted = try! enc.encryptData(plain, offset: 0, extra: nil)
        let decrypted = try! dec.decryptData(encrypted, offset: 0, extra: nil)
        XCTAssertEqual(plain, decrypted)
    }

    func testHMAC() {
        let cbc = CryptoBox(cipherAlgorithm: nil, digestAlgorithm: "sha256")
        try! cbc.configure(withCipherEncKey: nil, cipherDecKey: nil, hmacEncKey: hmacKey, hmacDecKey: hmacKey)
        let enc = cbc.encrypter()
        let dec = cbc.decrypter()
        
        let plain = Data(hex: "00112233445566778899")
        let encrypted = try! enc.encryptData(plain, offset: 0, extra: nil)
        do {
            try dec.verifyData(encrypted, offset: 0, extra: nil)
            XCTAssert(true)
        } catch {
            XCTAssert(false)
        }
    }
    
    func testGCM() {
        let gcm = CryptoBox(cipherAlgorithm: "aes-256-gcm", digestAlgorithm: nil)
        try! gcm.configure(withCipherEncKey: cipherKey, cipherDecKey: cipherKey, hmacEncKey: hmacKey, hmacDecKey: hmacKey)
        let enc = gcm.encrypter()
        let dec = gcm.decrypter()
        
//        let packetId: UInt32 = 0x56341200
        let extra: [UInt8] = [0x00, 0x12, 0x34, 0x56]
        let plain = Data(hex: "00112233445566778899")
        let encrypted = try! enc.encryptData(plain, offset: 0, extra: extra)
        let decrypted = try! dec.decryptData(encrypted, offset: 0, extra: extra)
        XCTAssertEqual(plain, decrypted)
    }

//    func testCryptoOperation() {
//        let data = Data(hex: "aabbccddeeff")
//
//        print("Original : \(data.toHex())")
//        var enc: Data
//        var dec: Data
//
//        enc = Data()
//        enc.append(try! encrypter.encryptData(data, offset: 0, packetId: 0))
//        print("Encrypted: \(enc.toHex())")
//        dec = try! decrypter.decryptData(enc, offset: 0, packetId: 0)
//        print("Decrypted: \(dec.toHex())")
//        XCTAssert(dec == data)
//
//        let prefix = "abcdef"
//        enc = Data(hex: prefix)
//        enc.append(try! encrypter.encryptData(data, offset: 0, packetId: 0))
//        print("Encrypted: \(enc.toHex())")
//        dec = try! decrypter.decryptData(enc, offset: (prefix.count / 2), packetId: 0)
//        print("Decrypted: \(dec.toHex())")
//        XCTAssert(dec == data)
//    }
}
