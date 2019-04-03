//
//  OptionsBundleTests.swift
//  TunnelKitTests
//
//  Created by Davide De Rosa on 4/3/19.
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

class OptionsBundleTests: XCTestCase {
    let base: [String] = ["<ca>", "</ca>", "remote 1.2.3.4"]
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testCompression() throws {
//        XCTAssertNotNil(try OptionsBundle.parsed(fromLines: base + ["comp-lzo"]).warning)
        XCTAssertNil(try OptionsBundle(from: base + ["comp-lzo"]).warning)
        XCTAssertNoThrow(try OptionsBundle(from: base + ["comp-lzo no"]))
        XCTAssertNoThrow(try OptionsBundle(from: base + ["comp-lzo yes"]))
//        XCTAssertThrowsError(try OptionsBundle(from: base + ["comp-lzo yes"]))
        
        XCTAssertNoThrow(try OptionsBundle(from: base + ["compress"]))
        XCTAssertNoThrow(try OptionsBundle(from: base + ["compress lzo"]))
    }
    
    func testDHCPOption() throws {
        let lines = base + ["dhcp-option DNS 8.8.8.8", "dhcp-option DNS6 ffff::1", "dhcp-option DOMAIN example.com"]
        XCTAssertNoThrow(try OptionsBundle(from: lines))
        
        let parsed = try! OptionsBundle(from: lines)
        XCTAssertEqual(parsed.dnsServers, ["8.8.8.8", "ffff::1"])
        XCTAssertEqual(parsed.searchDomain, "example.com")
    }
    
    func testConnectionBlock() throws {
        let lines = base + ["<connection>", "</connection>"]
        XCTAssertThrowsError(try OptionsBundle(from: lines))
    }
}
