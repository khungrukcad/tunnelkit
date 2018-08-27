//
//  SessionProxy+PushReply.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 7/25/18.
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

extension SessionProxy {
    struct PushReply {
        private static let ifconfigRegexp = try! NSRegularExpression(pattern: "ifconfig [\\d\\.]+ [\\d\\.]+", options: [])

        private static let dnsRegexp = try! NSRegularExpression(pattern: "dhcp-option DNS [\\d\\.]+", options: [])

        private static let authTokenRegexp = try! NSRegularExpression(pattern: "auth-token [a-zA-Z0-9/=+]+", options: [])

        private static let peerIdRegexp = try! NSRegularExpression(pattern: "peer-id [0-9]+", options: [])
        
        let address: String

        let gatewayAddress: String
        
        let dnsServers: [String]
        
        let authToken: String?
        
        let peerId: UInt32?
        
        init?(message: String) throws {
            guard message.hasPrefix("PUSH_REPLY") else {
                return nil
            }
            
            var ifconfigComponents: [String]?
            var dnsServers = [String]()
            var authToken: String?
            var peerId: UInt32?

            PushReply.ifconfigRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                guard let range = result?.range else { return }
                
                let match = (message as NSString).substring(with: range)
                ifconfigComponents = match.components(separatedBy: " ")
            }
            
            guard let addresses = ifconfigComponents, addresses.count >= 2 else {
                throw SessionError.malformedPushReply
            }
            
            PushReply.dnsRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                guard let range = result?.range else { return }
                
                let match = (message as NSString).substring(with: range)
                let dnsEntryComponents = match.components(separatedBy: " ")
                
                dnsServers.append(dnsEntryComponents[2])
            }
            
            PushReply.authTokenRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                guard let range = result?.range else { return }
                
                let match = (message as NSString).substring(with: range)
                let tokenComponents = match.components(separatedBy: " ")
                
                if (tokenComponents.count > 1) {
                    authToken = tokenComponents[1]
                }
            }
            
            PushReply.peerIdRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                guard let range = result?.range else { return }
                
                let match = (message as NSString).substring(with: range)
                let tokenComponents = match.components(separatedBy: " ")
                
                if (tokenComponents.count > 1) {
                    peerId = UInt32(tokenComponents[1])
                }
            }

            address = addresses[1]
            gatewayAddress = addresses[2]
            self.dnsServers = dnsServers
            self.authToken = authToken
            self.peerId = peerId
        }
    }
}
