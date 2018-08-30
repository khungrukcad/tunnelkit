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

/// Represents the reply of a successful session start.
public protocol SessionReply {

    /// The obtained address.
    var address: String { get }

    /// The obtained address mask.
    var addressMask: String { get }

    /// The address of the default gateway.
    var defaultGateway: String { get }

    /// The additional routes.
    var routes: [SessionProxy.Route] { get }

    /// The DNS servers set up for this session.
    var dnsServers: [String] { get }
}

extension SessionProxy {

    // XXX: parsing is very optimistic
    
    /// Represents a route in the routing table.
    public struct Route {

        /// The destination host or subnet.
        public let destination: String
        
        /// The address mask.
        public let mask: String
        
        /// The address of the gateway (uses default gateway if not set).
        public let gateway: String?
        
        fileprivate init(_ destination: String, _ mask: String?, _ gateway: String?) {
            self.destination = destination
            self.mask = mask ?? "255.255.255.255"
            self.gateway = gateway
        }
    }
    
    struct PushReply: SessionReply {
        private enum Topology: String {
            case net30
            
            case p2p
            
            case subnet
        }
        
        private static let topologyRegexp = try! NSRegularExpression(pattern: "topology (net30|p2p|subnet)", options: [])
        
        private static let ifconfigRegexp = try! NSRegularExpression(pattern: "ifconfig [\\d\\.]+ [\\d\\.]+", options: [])

        private static let gatewayRegexp = try! NSRegularExpression(pattern: "route-gateway [\\d\\.]+", options: [])
        
        private static let routeRegexp = try! NSRegularExpression(pattern: "route [\\d\\.]+( [\\d\\.]+){0,2}", options: [])
        
        private static let dnsRegexp = try! NSRegularExpression(pattern: "dhcp-option DNS [\\d\\.]+", options: [])

        private static let authTokenRegexp = try! NSRegularExpression(pattern: "auth-token [a-zA-Z0-9/=+]+", options: [])

        private static let peerIdRegexp = try! NSRegularExpression(pattern: "peer-id [0-9]+", options: [])
        
        let address: String

        let addressMask: String

        let defaultGateway: String

        let routes: [Route]
        
        let dnsServers: [String]
        
        let authToken: String?
        
        let peerId: UInt32?
        
        init?(message: String) throws {
            guard message.hasPrefix("PUSH_REPLY") else {
                return nil
            }
            
            var optTopologyComponents: [String]?
            var optIfconfigComponents: [String]?
            var optGatewayComponents: [String]?

            let address: String
            let addressMask: String
            let defaultGateway: String
            var routes: [Route] = []
            var dnsServers: [String] = []
            var authToken: String?
            var peerId: UInt32?
            
            // MARK: Routing

            PushReply.topologyRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                guard let range = result?.range else { return }
                
                let match = (message as NSString).substring(with: range)
                optTopologyComponents = match.components(separatedBy: " ")
            }
            guard let topologyComponents = optTopologyComponents, topologyComponents.count == 2 else {
                throw SessionError.malformedPushReply
            }

            // assumes "topology" to be always pushed to clients, even when not explicitly set (defaults to net30)
            guard let topology = Topology(rawValue: topologyComponents[1]) else {
                fatalError("Bad topology regexp, accepted unrecognized value: \(topologyComponents[1])")
            }

            PushReply.ifconfigRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                guard let range = result?.range else { return }
                
                let match = (message as NSString).substring(with: range)
                optIfconfigComponents = match.components(separatedBy: " ")
            }
            guard let ifconfigComponents = optIfconfigComponents, ifconfigComponents.count == 3 else {
                throw SessionError.malformedPushReply
            }
            
            PushReply.gatewayRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                guard let range = result?.range else { return }

                let match = (message as NSString).substring(with: range)
                optGatewayComponents = match.components(separatedBy: " ")
            }

            //
            // excerpts from OpenVPN manpage
            //
            // "--ifconfig l rn":
            //
            // Set  TUN/TAP  adapter parameters.  l is the IP address of the local VPN endpoint.  For TUN devices in point-to-point mode, rn is the IP address of
            // the remote VPN endpoint.  For TAP devices, or TUN devices used with --topology subnet, rn is the subnet mask of the virtual network segment  which
            // is being created or connected to.
            //
            // "--topology mode":
            //
            // Note: Using --topology subnet changes the interpretation of the arguments of --ifconfig to mean "address netmask", no longer "local remote".
            //
            switch topology {
            case .subnet:

                // default gateway required when topology is subnet
                guard let gatewayComponents = optGatewayComponents, gatewayComponents.count == 2 else {
                    throw SessionError.malformedPushReply
                }
                address = ifconfigComponents[1]
                addressMask = ifconfigComponents[2]
                defaultGateway = gatewayComponents[1]
                
            default:
                address = ifconfigComponents[1]
                addressMask = "255.255.255.255"
                defaultGateway = ifconfigComponents[2]
            }
            
            // MARK: DNS

            PushReply.dnsRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                guard let range = result?.range else { return }
                
                let match = (message as NSString).substring(with: range)
                let dnsEntryComponents = match.components(separatedBy: " ")
                
                dnsServers.append(dnsEntryComponents[2])
            }
            
            // MARK: Routes
            
            PushReply.routeRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                guard let range = result?.range else { return }

                let match = (message as NSString).substring(with: range)
                let routeEntryComponents = match.components(separatedBy: " ")

                let destination = routeEntryComponents[1]
                let mask: String?
                let gateway: String?
                if routeEntryComponents.count > 2 {
                    mask = routeEntryComponents[2]
                } else {
                    mask = nil
                }
                if routeEntryComponents.count > 3 {
                    gateway = routeEntryComponents[3]
                } else {
                    gateway = defaultGateway
                }
                routes.append(Route(destination, mask, gateway))
            }
            
            // MARK: Authentication

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

            self.address = address
            self.addressMask = addressMask
            self.defaultGateway = defaultGateway
            self.dnsServers = dnsServers
            self.routes = routes
            self.authToken = authToken
            self.peerId = peerId
        }
    }
}
