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

/// Encapsulates the IPv4 settings for the tunnel.
public struct IPv4Settings: CustomStringConvertible {

    /// Represents an IPv4 route in the routing table.
    public struct Route: CustomStringConvertible {
        
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

        // MARK: CustomStringConvertible
        
        /// :nodoc:
        public var description: String {
            return "{\(destination)/\(mask) \(gateway ?? "default")}"
        }
    }

    /// The address.
    let address: String
    
    /// The address mask.
    let addressMask: String
    
    /// The address of the default gateway.
    let defaultGateway: String

    /// The additional routes.
    let routes: [Route]

    // MARK: CustomStringConvertible

    /// :nodoc:
    public var description: String {
        return "addr \(address) netmask \(addressMask) gw \(defaultGateway) routes \(routes)"
    }
}

/// Encapsulates the IPv6 settings for the tunnel.
public struct IPv6Settings: CustomStringConvertible {

    /// Represents an IPv6 route in the routing table.
    public struct Route: CustomStringConvertible {
        
        /// The destination host or subnet.
        public let destination: String
        
        /// The address prefix length.
        public let prefixLength: UInt8
        
        /// The address of the gateway (uses default gateway if not set).
        public let gateway: String?
        
        fileprivate init(_ destination: String, _ prefixLength: UInt8?, _ gateway: String?) {
            self.destination = destination
            self.prefixLength = prefixLength ?? 3
            self.gateway = gateway
        }

        // MARK: CustomStringConvertible
        
        /// :nodoc:
        public var description: String {
            return "{\(destination)/\(prefixLength) \(gateway ?? "default")}"
        }
    }

    /// The address.
    public let address: String
    
    /// The address prefix length.
    public let addressPrefixLength: UInt8
    
    /// The address of the default gateway.
    public let defaultGateway: String
    
    /// The additional routes.
    public let routes: [Route]

    // MARK: CustomStringConvertible
    
    /// :nodoc:
    public var description: String {
        return "addr \(address)/\(addressPrefixLength) gw \(defaultGateway) routes \(routes)"
    }
}

/// Groups the parsed reply of a successfully started session.
public protocol SessionReply {

    /// The IPv4 settings.
    var ipv4: IPv4Settings? { get }
    
    /// The IPv6 settings.
    var ipv6: IPv6Settings? { get }
    
    /// The DNS servers set up for this session.
    var dnsServers: [String] { get }
}

extension SessionProxy {

    // XXX: parsing is very optimistic
    
    struct PushReply: SessionReply {
        private enum Topology: String {
            case net30
            
            case p2p
            
            case subnet
        }
        
        private static let topologyRegexp = try! NSRegularExpression(pattern: "topology (net30|p2p|subnet)", options: [])
        
        private static let ifconfigRegexp = try! NSRegularExpression(pattern: "ifconfig [\\d\\.]+ [\\d\\.]+", options: [])

        private static let ifconfig6Regexp = try! NSRegularExpression(pattern: "ifconfig-ipv6 [\\da-fA-F:]+/\\d+ [\\da-fA-F:]+", options: [])

        private static let gatewayRegexp = try! NSRegularExpression(pattern: "route-gateway [\\d\\.]+", options: [])
        
        private static let routeRegexp = try! NSRegularExpression(pattern: "route [\\d\\.]+( [\\d\\.]+){0,2}", options: [])

        private static let route6Regexp = try! NSRegularExpression(pattern: "route-ipv6 [\\da-fA-F:]+/\\d+( [\\da-fA-F:]+){0,2}", options: [])

        private static let dnsRegexp = try! NSRegularExpression(pattern: "dhcp-option DNS6? [\\d\\.a-fA-F:]+", options: [])

        private static let authTokenRegexp = try! NSRegularExpression(pattern: "auth-token [a-zA-Z0-9/=+]+", options: [])

        private static let peerIdRegexp = try! NSRegularExpression(pattern: "peer-id [0-9]+", options: [])

        let ipv4: IPv4Settings?
        
        let ipv6: IPv6Settings?
        
        let dnsServers: [String]
        
        let authToken: String?
        
        let peerId: UInt32?
        
        init?(message: String) throws {
            guard message.hasPrefix("PUSH_REPLY") else {
                return nil
            }
            
            var optTopologyComponents: [String]?
            var optIfconfig4Components: [String]?
            var optGateway4Components: [String]?
            let address4: String
            let addressMask4: String
            let defaultGateway4: String
            var routes4: [IPv4Settings.Route] = []

            var optIfconfig6Components: [String]?

            var dnsServers: [String] = []
            var authToken: String?
            var peerId: UInt32?
            
            // MARK: Routing (IPv4)

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
                optIfconfig4Components = match.components(separatedBy: " ")
            }
            guard let ifconfig4Components = optIfconfig4Components, ifconfig4Components.count == 3 else {
                throw SessionError.malformedPushReply
            }
            
            PushReply.gatewayRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                guard let range = result?.range else { return }

                let match = (message as NSString).substring(with: range)
                optGateway4Components = match.components(separatedBy: " ")
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
                guard let gateway4Components = optGateway4Components, gateway4Components.count == 2 else {
                    throw SessionError.malformedPushReply
                }
                address4 = ifconfig4Components[1]
                addressMask4 = ifconfig4Components[2]
                defaultGateway4 = gateway4Components[1]
                
            default:
                address4 = ifconfig4Components[1]
                addressMask4 = "255.255.255.255"
                defaultGateway4 = ifconfig4Components[2]
            }

            PushReply.routeRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                guard let range = result?.range else { return }
                
                let match = (message as NSString).substring(with: range)
                let routeEntryComponents = match.components(separatedBy: " ")
                
                let address = routeEntryComponents[1]
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
                    gateway = defaultGateway4
                }
                routes4.append(IPv4Settings.Route(address, mask, gateway))
            }

            ipv4 = IPv4Settings(
                address: address4,
                addressMask: addressMask4,
                defaultGateway: defaultGateway4,
                routes: routes4
            )

            // MARK: Routing (IPv6)
            
            PushReply.ifconfig6Regexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                guard let range = result?.range else { return }
                
                let match = (message as NSString).substring(with: range)
                optIfconfig6Components = match.components(separatedBy: " ")
            }
            if let ifconfig6Components = optIfconfig6Components, ifconfig6Components.count == 3 {
                let address6Components = ifconfig6Components[1].components(separatedBy: "/")
                guard address6Components.count == 2 else {
                    throw SessionError.malformedPushReply
                }
                guard let addressPrefix6 = UInt8(address6Components[1]) else {
                    throw SessionError.malformedPushReply
                }
                let address6 = address6Components[0]
                let defaultGateway6 = ifconfig6Components[2]
                
                var routes6: [IPv6Settings.Route] = []
                PushReply.route6Regexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                    guard let range = result?.range else { return }
                        
                    let match = (message as NSString).substring(with: range)
                    let routeEntryComponents = match.components(separatedBy: " ")
                    
                    let destinationComponents = routeEntryComponents[1].components(separatedBy: "/")
                    guard destinationComponents.count == 2 else {
//                        throw SessionError.malformedPushReply
                        return
                    }
                    guard let prefix = UInt8(destinationComponents[1]) else {
//                        throw SessionError.malformedPushReply
                        return
                    }

                    let destination = destinationComponents[0]
                    let gateway: String?
                    if routeEntryComponents.count > 2 {
                        gateway = routeEntryComponents[2]
                    } else {
                        gateway = defaultGateway6
                    }
                    routes6.append(IPv6Settings.Route(destination, prefix, gateway))
                }

                ipv6 = IPv6Settings(
                    address: address6,
                    addressPrefixLength: addressPrefix6,
                    defaultGateway: defaultGateway6,
                    routes: routes6
                )
            } else {
                ipv6 = nil
            }

            // MARK: DNS

            PushReply.dnsRegexp.enumerateMatches(in: message, options: [], range: NSMakeRange(0, message.count)) { (result, flags, _) in
                guard let range = result?.range else { return }
                
                let match = (message as NSString).substring(with: range)
                let dnsEntryComponents = match.components(separatedBy: " ")
                
                dnsServers.append(dnsEntryComponents[2])
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

            self.dnsServers = dnsServers
            self.authToken = authToken
            self.peerId = peerId
        }
    }
}
