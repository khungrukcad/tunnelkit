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
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    // from lines
    
    func testCompression() throws {
//        XCTAssertNotNil(try OptionsBundle.parsed(fromLines: ["comp-lzo"]).warning)
        XCTAssertNil(try ConfigurationParser.parsed(fromLines: ["comp-lzo"]).warning)
        XCTAssertNoThrow(try ConfigurationParser.parsed(fromLines: ["comp-lzo no"]))
        XCTAssertNoThrow(try ConfigurationParser.parsed(fromLines: ["comp-lzo yes"]))
//        XCTAssertThrowsError(try ConfigurationParser.parsed(fromLines: ["comp-lzo yes"]))
        
        XCTAssertNoThrow(try ConfigurationParser.parsed(fromLines: ["compress"]))
        XCTAssertNoThrow(try ConfigurationParser.parsed(fromLines: ["compress lzo"]))
    }
    
    func testDHCPOption() throws {
        let lines = [
            "dhcp-option DNS 8.8.8.8",
            "dhcp-option DNS6 ffff::1",
            "dhcp-option DOMAIN example.com",
            "dhcp-option PROXY_HTTP 1.2.3.4 8081",
            "dhcp-option PROXY_HTTPS 7.8.9.10 8082",
            "dhcp-option PROXY_BYPASS   foo.com   bar.org     net.chat"
        ]
        XCTAssertNoThrow(try ConfigurationParser.parsed(fromLines: lines))
        
        let parsed = try! ConfigurationParser.parsed(fromLines: lines).configuration
        XCTAssertEqual(parsed.dnsServers, ["8.8.8.8", "ffff::1"])
        XCTAssertEqual(parsed.searchDomain, "example.com")
        XCTAssertEqual(parsed.httpProxy?.address, "1.2.3.4")
        XCTAssertEqual(parsed.httpProxy?.port, 8081)
        XCTAssertEqual(parsed.httpsProxy?.address, "7.8.9.10")
        XCTAssertEqual(parsed.httpsProxy?.port, 8082)
        XCTAssertEqual(parsed.proxyBypassDomains, ["foo.com", "bar.org", "net.chat"])
    }
    
    func testRedirectGateway() throws {
        var parsed: SessionProxy.Configuration

        parsed = try! ConfigurationParser.parsed(fromLines: []).configuration
        XCTAssertEqual(parsed.routingPolicies, nil)
        XCTAssertNotEqual(parsed.routingPolicies, [])
        parsed = try! ConfigurationParser.parsed(fromLines: ["redirect-gateway   ipv4   block-local"]).configuration
        XCTAssertEqual(parsed.routingPolicies, [.IPv4, .IPv6])
    }

    func testConnectionBlock() throws {
        let lines = ["<connection>", "</connection>"]
        XCTAssertThrowsError(try ConfigurationParser.parsed(fromLines: lines))
    }

    // from file
    
    func testPIA() throws {
        let file = try ConfigurationParser.parsed(fromURL: url(withName: "pia-hungary"))
        XCTAssertEqual(file.configuration.hostname, "hungary.privateinternetaccess.com")
        XCTAssertEqual(file.configuration.cipher, .aes128cbc)
        XCTAssertEqual(file.configuration.digest, .sha1)
        XCTAssertEqual(file.configuration.endpointProtocols, [
            EndpointProtocol(.udp, 1198),
            EndpointProtocol(.tcp, 502)
        ])
    }

    func testStripped() throws {
        let lines = try ConfigurationParser.parsed(fromURL: url(withName: "pia-hungary"), returnsStripped: true).strippedLines!
        let stripped = lines.joined(separator: "\n")
        print(stripped)
    }
    
    func testEncryptedCertificateKey() throws {
        try privateTestEncryptedCertificateKey(pkcs: "1")
        try privateTestEncryptedCertificateKey(pkcs: "8")
    }
    
    private func privateTestEncryptedCertificateKey(pkcs: String) throws {
        let cfgURL = url(withName: "tunnelbear.enc.\(pkcs)")
        XCTAssertThrowsError(try ConfigurationParser.parsed(fromURL: cfgURL))
        XCTAssertNoThrow(try ConfigurationParser.parsed(fromURL: cfgURL, passphrase: "foobar"))
    }
    
    private func url(withName name: String) -> URL {
        return Bundle(for: ConfigurationParserTests.self).url(forResource: name, withExtension: "ovpn")!
    }
    
}
