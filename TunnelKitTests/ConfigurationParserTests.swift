//
//  ConfigurationParserTests.swift
//  TunnelKitTests
//
//  Created by Davide De Rosa on 11/10/18.
//  Copyright (c) 2019 Davide De Rosa. All rights reserved.
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

import XCTest
import TunnelKit

class ConfigurationParserTests: XCTestCase {
    let base: [String] = ["<ca>", "</ca>", "remote 1.2.3.4"]
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testPIA() throws {
        let file = try ConfigurationParser.parsed(fromURL: url(withName: "pia-hungary"))
        XCTAssertEqual(file.hostname, "hungary.privateinternetaccess.com")
        XCTAssertEqual(file.configuration.cipher, .aes128cbc)
        XCTAssertEqual(file.configuration.digest, .sha1)
        XCTAssertEqual(file.protocols, [
            EndpointProtocol(.udp, 1198),
            EndpointProtocol(.tcp, 502)
        ])
    }

    func testStripped() throws {
        let lines = try ConfigurationParser.parsed(fromURL: url(withName: "pia-hungary"), returnsStripped: true).strippedLines!
        let stripped = lines.joined(separator: "\n")
        print(stripped)
    }
    
    func testCompression() throws {
//        XCTAssertNotNil(try ConfigurationParser.parsed(fromLines: base + ["comp-lzo"]).warning)
        XCTAssertNil(try ConfigurationParser.parsed(fromLines: base + ["comp-lzo"]).warning)
        XCTAssertNoThrow(try ConfigurationParser.parsed(fromLines: base + ["comp-lzo no"]))
        XCTAssertNoThrow(try ConfigurationParser.parsed(fromLines: base + ["comp-lzo yes"]))
//        XCTAssertThrowsError(try ConfigurationParser.parsed(fromLines: base + ["comp-lzo yes"]))

        XCTAssertNoThrow(try ConfigurationParser.parsed(fromLines: base + ["compress"]))
        XCTAssertNoThrow(try ConfigurationParser.parsed(fromLines: base + ["compress lzo"]))
    }
    
    func testDHCPOption() throws {
        let lines = base + ["dhcp-option DNS 8.8.8.8", "dhcp-option DNS6 ffff::1"]
        XCTAssertNoThrow(try ConfigurationParser.parsed(fromLines: lines))

        let parsed = try! ConfigurationParser.parsed(fromLines: lines)
        XCTAssertEqual(parsed.configuration.dnsServers, ["8.8.8.8", "ffff::1"])
    }
    
    func testConnectionBlock() throws {
        let lines = base + ["<connection>", "</connection>"]
        XCTAssertThrowsError(try ConfigurationParser.parsed(fromLines: lines))
    }
    
    func testEncryptedCertificateKey() throws {
        let url = Bundle(for: ConfigurationParserTests.self).url(forResource: "tunnelbear", withExtension: "enc.ovpn")!
        XCTAssertThrowsError(try ConfigurationParser.parsed(fromURL: url))
        XCTAssertNoThrow(try ConfigurationParser.parsed(fromURL: url, passphrase: "foobar"))
    }
    
    private func url(withName name: String) -> URL {
        return Bundle(for: ConfigurationParserTests.self).url(forResource: name, withExtension: "ovpn")!
    }
    
}
