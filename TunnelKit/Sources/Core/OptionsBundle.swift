//
//  OptionsBundle.swift
//  TunnelKit
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

import Foundation
import SwiftyBeaver
import __TunnelKitNative

private let log = SwiftyBeaver.self

/// Wraps together all recognized options from either configuration files or PUSH_REPLY.
public struct OptionsBundle {
    struct Regex {
        
        // MARK: General
        
        static let cipher = NSRegularExpression("^cipher +[^,\\s]+")
        
        static let auth = NSRegularExpression("^auth +[\\w\\-]+")
        
        static let compLZO = NSRegularExpression("^comp-lzo.*")
        
        static let compress = NSRegularExpression("^compress.*")
        
        static let keyDirection = NSRegularExpression("^key-direction +\\d")
        
        static let ping = NSRegularExpression("^ping +\\d+")
        
        static let renegSec = NSRegularExpression("^reneg-sec +\\d+")
        
        static let blockBegin = NSRegularExpression("^<[\\w\\-]+>")
        
        static let blockEnd = NSRegularExpression("^<\\/[\\w\\-]+>")
        
        // MARK: Client
        
        static let proto = NSRegularExpression("^proto +(udp6?|tcp6?)")
        
        static let port = NSRegularExpression("^port +\\d+")
        
        static let remote = NSRegularExpression("^remote +[^ ]+( +\\d+)?( +(udp6?|tcp6?))?")
        
        static let eku = NSRegularExpression("^remote-cert-tls +server")
        
        static let remoteRandom = NSRegularExpression("^remote-random")
        
        // MARK: Server
        
        static let authToken = NSRegularExpression("^auth-token +[a-zA-Z0-9/=+]+")
        
        static let peerId = NSRegularExpression("^peer-id +[0-9]+")
        
        // MARK: Routing
        
        static let topology = NSRegularExpression("^topology +(net30|p2p|subnet)")
        
        static let ifconfig = NSRegularExpression("^ifconfig +[\\d\\.]+ [\\d\\.]+")
        
        static let ifconfig6 = NSRegularExpression("^ifconfig-ipv6 +[\\da-fA-F:]+/\\d+ [\\da-fA-F:]+")
        
        static let route = NSRegularExpression("^route +[\\d\\.]+( +[\\d\\.]+){0,2}")
        
        static let route6 = NSRegularExpression("^route-ipv6 +[\\da-fA-F:]+/\\d+( +[\\da-fA-F:]+){0,2}")

        static let gateway = NSRegularExpression("^route-gateway +[\\d\\.]+")
        
        static let dns = NSRegularExpression("^dhcp-option +DNS6? +[\\d\\.a-fA-F:]+")
        
        static let domain = NSRegularExpression("^dhcp-option +DOMAIN +[^ ]+")
        
        // MARK: Unsupported
        
//        static let fragment = NSRegularExpression("^fragment +\\d+")
        static let fragment = NSRegularExpression("^fragment")
        
        static let proxy = NSRegularExpression("^\\w+-proxy")
        
        static let externalFiles = NSRegularExpression("^(ca|cert|key|tls-auth|tls-crypt) ")
        
        static let connection = NSRegularExpression("^<connection>")
    }
    
    private enum Topology: String {
        case net30
        
        case p2p
        
        case subnet
    }
    
    public let strippedLines: [String]?
    
    public let warning: OptionsError?
    
    // MARK: General
    
    /// The cipher algorithm for data encryption.
    public let cipher: SessionProxy.Cipher?

    /// The digest algorithm for HMAC.
    public let digest: SessionProxy.Digest?

    /// Compression framing, disabled by default.
    public let compressionFraming: SessionProxy.CompressionFraming?

    /// Compression algorithm, disabled by default.
    public let compressionAlgorithm: SessionProxy.CompressionAlgorithm?

    /// The CA for TLS negotiation (PEM format).
    public let ca: CryptoContainer?
    
    /// The optional client certificate for TLS negotiation (PEM format).
    public let clientCertificate: CryptoContainer?
    
    /// The private key for the certificate in `clientCertificate` (PEM format).
    public let clientKey: CryptoContainer?
    
    /// The optional TLS wrapping.
    public let tlsWrap: SessionProxy.TLSWrap?
    
    /// Sends periodical keep-alive packets if set.
    public let keepAliveSeconds: TimeInterval?
    
    /// The number of seconds after which a renegotiation should be initiated. If `nil`, the client will never initiate a renegotiation.
    public let renegotiateAfterSeconds: TimeInterval?
    
    // MARK: Client
    
    /// The server hostname (picked from first remote).
    public let hostname: String?
    
    /// The list of server endpoints (address, port, socket).
    public let remotes: [(String, UInt16, SocketType)]
    
    /// If true, checks EKU of server certificate.
    public let checksEKU: Bool
    
    /// Picks endpoint from `remotes` randomly.
    public let randomizeEndpoint: Bool
    
    // MARK: Server
    
    /// The auth-token returned by the server.
    public let authToken: String?
    
    /// The peer-id returned by the server.
    public let peerId: UInt32?
    
    // MARK: Routing
    
    /// The settings for IPv4.
    public let ipv4: IPv4Settings?
    
    /// The settings for IPv6.
    public let ipv6: IPv6Settings?
    
    /// The DNS servers.
    public let dnsServers: [String]

    /// The search domain.
    public let searchDomain: String?
    
    /**
     Parses options from an array of lines.
     
     - Parameter lines: The array of lines holding the options.
     - Parameter returnsStripped: When `true`, stores the stripped lines into `strippedLines`. Defaults to `false`.
     - Throws: `OptionsError` if the options are wrong or incomplete.
     */
    public init(from lines: [String], returnsStripped: Bool = false) throws {
        var optStrippedLines: [String]? = returnsStripped ? [] : nil
        var optWarning: OptionsError?
        var unsupportedError: OptionsError?
        var currentBlockName: String?
        var currentBlock: [String] = []

        var optCipher: SessionProxy.Cipher?
        var optDigest: SessionProxy.Digest?
        var optCompressionFraming: SessionProxy.CompressionFraming?
        var optCompressionAlgorithm: SessionProxy.CompressionAlgorithm?
        var optCA: CryptoContainer?
        var optClientCertificate: CryptoContainer?
        var optClientKey: CryptoContainer?
        var optKeyDirection: StaticKey.Direction?
        var optTLSKeyLines: [Substring]?
        var optTLSStrategy: SessionProxy.TLSWrap.Strategy?
        var optKeepAliveSeconds: TimeInterval?
        var optRenegotiateAfterSeconds: TimeInterval?
        //
        var optHostname: String?
        var optDefaultProto: SocketType?
        var optDefaultPort: UInt16?
        var optRemotes: [(String, UInt16?, SocketType?)] = [] // address, port, socket
        var optChecksEKU: Bool?
        var optRandomizeEndpoint: Bool?
        //
        var optAuthToken: String?
        var optPeerId: UInt32?
        //
        var optTopology: String?
        var optIfconfig4Arguments: [String]?
        var optIfconfig6Arguments: [String]?
        var optGateway4Arguments: [String]?
        var optRoutes4: [(String, String, String?)] = [] // address, netmask, gateway
        var optRoutes6: [(String, UInt8, String?)] = [] // destination, prefix, gateway
        var optDNSServers: [String] = []
        var optSearchDomain: String?

        log.verbose("Configuration file:")
        for line in lines {
            log.verbose(line)
            
            var isHandled = false
            var strippedLine = line
            defer {
                if isHandled {
                    optStrippedLines?.append(strippedLine)
                }
            }
            
            // MARK: Unsupported
            
            // check blocks first
            Regex.connection.enumerateComponents(in: line) { (_) in
                unsupportedError = OptionsError.unsupportedConfiguration(option: "<connection> blocks")
            }
            Regex.fragment.enumerateComponents(in: line) { (_) in
                unsupportedError = OptionsError.unsupportedConfiguration(option: "fragment")
            }
            Regex.proxy.enumerateComponents(in: line) { (_) in
                unsupportedError = OptionsError.unsupportedConfiguration(option: "proxy: \"\(line)\"")
            }
            Regex.externalFiles.enumerateComponents(in: line) { (_) in
                unsupportedError = OptionsError.unsupportedConfiguration(option: "external file: \"\(line)\"")
            }
            if line.contains("mtu") || line.contains("mssfix") {
                isHandled = true
            }

            // MARK: Inline content
            
            if unsupportedError == nil {
                if currentBlockName == nil {
                    Regex.blockBegin.enumerateComponents(in: line) {
                        isHandled = true
                        let tag = $0.first!
                        let from = tag.index(after: tag.startIndex)
                        let to = tag.index(before: tag.endIndex)
                        
                        currentBlockName = String(tag[from..<to])
                        currentBlock = []
                    }
                }
                Regex.blockEnd.enumerateComponents(in: line) {
                    isHandled = true
                    let tag = $0.first!
                    let from = tag.index(tag.startIndex, offsetBy: 2)
                    let to = tag.index(before: tag.endIndex)
                    
                    let blockName = String(tag[from..<to])
                    guard blockName == currentBlockName else {
                        return
                    }
                    
                    // first is opening tag
                    currentBlock.removeFirst()
                    switch blockName {
                    case "ca":
                        optCA = CryptoContainer(pem: currentBlock.joined(separator: "\n"))
                        
                    case "cert":
                        optClientCertificate = CryptoContainer(pem: currentBlock.joined(separator: "\n"))
                        
                    case "key":
                        OptionsBundle.normalizeEncryptedPEMBlock(block: &currentBlock)
                        optClientKey = CryptoContainer(pem: currentBlock.joined(separator: "\n"))
                    
                    case "tls-auth":
                        optTLSKeyLines = currentBlock.map { Substring($0) }
                        optTLSStrategy = .auth
                        
                    case "tls-crypt":
                        optTLSKeyLines = currentBlock.map { Substring($0) }
                        optTLSStrategy = .crypt
                        
                    default:
                        break
                    }
                    currentBlockName = nil
                    currentBlock = []
                }
            }
            if let _ = currentBlockName {
                currentBlock.append(line)
                continue
            }
            
            // MARK: General

            Regex.cipher.enumerateArguments(in: line) {
                isHandled = true
                guard let rawValue = $0.first else {
                    return
                }
                optCipher = SessionProxy.Cipher(rawValue: rawValue.uppercased())
                if optCipher == nil {
                    unsupportedError = OptionsError.unsupportedConfiguration(option: "cipher \(rawValue)")
                }
            }
            Regex.auth.enumerateArguments(in: line) {
                isHandled = true
                guard let rawValue = $0.first else {
                    return
                }
                optDigest = SessionProxy.Digest(rawValue: rawValue.uppercased())
                if optDigest == nil {
                    unsupportedError = OptionsError.unsupportedConfiguration(option: "auth \(rawValue)")
                }
            }
            Regex.compLZO.enumerateArguments(in: line) {
                isHandled = true
                optCompressionFraming = .compLZO
                
                if !LZOIsSupported() {
                    guard let arg = $0.first else {
                        optWarning = optWarning ?? .unsupportedConfiguration(option: line)
                        return
                    }
                    guard arg == "no" else {
                        unsupportedError = .unsupportedConfiguration(option: line)
                        return
                    }
                } else {
                    let arg = $0.first
                    optCompressionAlgorithm = (arg == "no") ? .disabled : .LZO
                }
            }
            Regex.compress.enumerateArguments(in: line) {
                isHandled = true
                optCompressionFraming = .compress
                
                if !LZOIsSupported() {
                    guard $0.isEmpty else {
                        unsupportedError = .unsupportedConfiguration(option: line)
                        return
                    }
                } else {
                    if let arg = $0.first {
                        optCompressionAlgorithm = (arg == "lzo") ? .LZO : .other
                    } else {
                        optCompressionAlgorithm = .disabled
                    }
                }
            }
            Regex.keyDirection.enumerateArguments(in: line) {
                isHandled = true
                guard let arg = $0.first, let value = Int(arg) else {
                    return
                }
                optKeyDirection = StaticKey.Direction(rawValue: value)
            }
            Regex.ping.enumerateArguments(in: line) {
                isHandled = true
                guard let arg = $0.first else {
                    return
                }
                optKeepAliveSeconds = TimeInterval(arg)
            }
            Regex.renegSec.enumerateArguments(in: line) {
                isHandled = true
                guard let arg = $0.first else {
                    return
                }
                optRenegotiateAfterSeconds = TimeInterval(arg)
            }

            // MARK: Client
            
            Regex.proto.enumerateArguments(in: line) {
                isHandled = true
                guard let str = $0.first else {
                    return
                }
                optDefaultProto = SocketType(protoString: str)
                if optDefaultProto == nil {
                    unsupportedError = OptionsError.unsupportedConfiguration(option: "proto \(str)")
                }
            }
            Regex.port.enumerateArguments(in: line) {
                isHandled = true
                guard let str = $0.first else {
                    return
                }
                optDefaultPort = UInt16(str)
            }
            Regex.remote.enumerateArguments(in: line) {
                isHandled = true
                guard let hostname = $0.first else {
                    return
                }
                var port: UInt16?
                var proto: SocketType?
                var strippedComponents = ["remote", "<hostname>"]
                if $0.count > 1 {
                    port = UInt16($0[1])
                    strippedComponents.append($0[1])
                }
                if $0.count > 2 {
                    proto = SocketType(protoString: $0[2])
                    strippedComponents.append($0[2])
                }
                optRemotes.append((hostname, port, proto))
                
                // replace private data
                strippedLine = strippedComponents.joined(separator: " ")
            }
            Regex.eku.enumerateComponents(in: line) { (_) in
                isHandled = true
                optChecksEKU = true
            }
            Regex.remoteRandom.enumerateComponents(in: line) { (_) in
                isHandled = true
                optRandomizeEndpoint = true
            }
            
            // MARK: Server
            
            Regex.authToken.enumerateArguments(in: line) {
                optAuthToken = $0[0]
            }
            Regex.peerId.enumerateArguments(in: line) {
                optPeerId = UInt32($0[0])
            }

            // MARK: Routing
            
            Regex.topology.enumerateArguments(in: line) {
                optTopology = $0.first
            }
            Regex.ifconfig.enumerateArguments(in: line) {
                optIfconfig4Arguments = $0
            }
            Regex.ifconfig6.enumerateArguments(in: line) {
                optIfconfig6Arguments = $0
            }
            Regex.route.enumerateArguments(in: line) {
                let routeEntryArguments = $0
                
                let address = routeEntryArguments[0]
                let mask = (routeEntryArguments.count > 1) ? routeEntryArguments[1] : "255.255.255.255"
                let gateway = (routeEntryArguments.count > 2) ? routeEntryArguments[2] : nil // defaultGateway4
                optRoutes4.append((address, mask, gateway))
            }
            Regex.route6.enumerateArguments(in: line) {
                let routeEntryArguments = $0
                
                let destinationComponents = routeEntryArguments[0].components(separatedBy: "/")
                guard destinationComponents.count == 2 else {
                    return
                }
                guard let prefix = UInt8(destinationComponents[1]) else {
                    return
                }
                
                let destination = destinationComponents[0]
                let gateway = (routeEntryArguments.count > 1) ? routeEntryArguments[1] : nil // defaultGateway6
                optRoutes6.append((destination, prefix, gateway))
            }
            Regex.gateway.enumerateArguments(in: line) {
                optGateway4Arguments = $0
            }
            Regex.dns.enumerateArguments(in: line) {
                guard $0.count == 2 else {
                    return
                }
                optDNSServers.append($0[1])
            }
            Regex.domain.enumerateArguments(in: line) {
                guard $0.count == 2 else {
                    return
                }
                optSearchDomain = $0[1]
            }
            
            //

            if let error = unsupportedError {
                throw error
            }
        }
        
        //
        
        strippedLines = optStrippedLines
        warning = optWarning
        
        // MARK: General

        cipher = optCipher
        digest = optDigest
        compressionFraming = optCompressionFraming
        compressionAlgorithm = optCompressionAlgorithm
        ca = optCA
        clientCertificate = optClientCertificate
        clientKey = optClientKey

        if let keyLines = optTLSKeyLines, let strategy = optTLSStrategy {
            let optKey: StaticKey?
            switch strategy {
            case .auth:
                optKey = StaticKey(lines: keyLines, direction: optKeyDirection)
                
            case .crypt:
                optKey = StaticKey(lines: keyLines, direction: .client)
            }
            if let key = optKey {
                tlsWrap = SessionProxy.TLSWrap(strategy: strategy, key: key)
            } else {
                tlsWrap = nil
            }
        } else {
            tlsWrap = nil
        }
        
        keepAliveSeconds = optKeepAliveSeconds
        renegotiateAfterSeconds = optRenegotiateAfterSeconds

        // MARK: Client

        optDefaultProto = optDefaultProto ?? .udp
        optDefaultPort = optDefaultPort ?? 1194
        if !optRemotes.isEmpty {
            hostname = optRemotes[0].0
            
            var fullRemotes: [(String, UInt16, SocketType)] = []
            let hostname = optRemotes[0].0
            optRemotes.forEach {
                guard $0.0 == hostname else {
                    return
                }
                guard let port = $0.1 ?? optDefaultPort else {
                    return
                }
                guard let socketType = $0.2 ?? optDefaultProto else {
                    return
                }
                fullRemotes.append((hostname, port, socketType))
            }
            remotes = fullRemotes
        } else {
            hostname = nil
            remotes = []
        }

        checksEKU = optChecksEKU ?? false
        randomizeEndpoint = optRandomizeEndpoint ?? false

        // MARK: Server

        authToken = optAuthToken
        peerId = optPeerId
        
        // MARK: Routing
        
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
        if let ifconfig4Arguments = optIfconfig4Arguments {
            guard ifconfig4Arguments.count == 2 else {
                throw OptionsError.malformed(option: "ifconfig takes 2 arguments")
            }

            let address4: String
            let addressMask4: String
            let defaultGateway4: String

            let topology = Topology(rawValue: optTopology ?? "") ?? .net30
            switch topology {
            case .subnet:
                
                // default gateway required when topology is subnet
                guard let gateway4Arguments = optGateway4Arguments, gateway4Arguments.count == 1 else {
                    throw OptionsError.malformed(option: "route-gateway takes 1 argument")
                }
                address4 = ifconfig4Arguments[0]
                addressMask4 = ifconfig4Arguments[1]
                defaultGateway4 = gateway4Arguments[0]
                
            default:
                address4 = ifconfig4Arguments[0]
                addressMask4 = "255.255.255.255"
                defaultGateway4 = ifconfig4Arguments[1]
            }
            let routes4 = optRoutes4.map { IPv4Settings.Route($0.0, $0.1, $0.2 ?? defaultGateway4) }
            
            ipv4 = IPv4Settings(
                address: address4,
                addressMask: addressMask4,
                defaultGateway: defaultGateway4,
                routes: routes4
            )
        } else {
            ipv4 = nil
        }

        if let ifconfig6Arguments = optIfconfig6Arguments {
            guard ifconfig6Arguments.count == 2 else {
                throw OptionsError.malformed(option: "ifconfig-ipv6 takes 2 arguments")
            }
            let address6Components = ifconfig6Arguments[0].components(separatedBy: "/")
            guard address6Components.count == 2 else {
                throw OptionsError.malformed(option: "ifconfig-ipv6 address must have a /prefix")
            }
            guard let addressPrefix6 = UInt8(address6Components[1]) else {
                throw OptionsError.malformed(option: "ifconfig-ipv6 address prefix must be a 8-bit number")
            }

            let address6 = address6Components[0]
            let defaultGateway6 = ifconfig6Arguments[1]
            let routes6 = optRoutes6.map { IPv6Settings.Route($0.0, $0.1, $0.2 ?? defaultGateway6) }

            ipv6 = IPv6Settings(
                address: address6,
                addressPrefixLength: addressPrefix6,
                defaultGateway: defaultGateway6,
                routes: routes6
            )
        } else {
            ipv6 = nil
        }

        dnsServers = optDNSServers
        searchDomain = optSearchDomain
    }
        
    private static func normalizeEncryptedPEMBlock(block: inout [String]) {
//        if block.count >= 1 && block[0].contains("ENCRYPTED") {
//            return true
//        }
        
        // XXX: restore blank line after encryption header (easier than tweaking trimmedLines)
        if block.count >= 3 && block[1].contains("Proc-Type") {
            block.insert("", at: 3)
//            return true
        }
//        return false
    }
}

/// Encapsulates the IPv4 settings for the tunnel.
public struct IPv4Settings: Codable, CustomStringConvertible {
    
    /// Represents an IPv4 route in the routing table.
    public struct Route: Codable, CustomStringConvertible {
        
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
            return "{\(destination.maskedDescription)/\(mask) \(gateway?.maskedDescription ?? "default")}"
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
        return "addr \(address.maskedDescription) netmask \(addressMask) gw \(defaultGateway.maskedDescription) routes \(routes.map { $0.maskedDescription })"
    }
}

/// Encapsulates the IPv6 settings for the tunnel.
public struct IPv6Settings: Codable, CustomStringConvertible {
    
    /// Represents an IPv6 route in the routing table.
    public struct Route: Codable, CustomStringConvertible {
        
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
            return "{\(destination.maskedDescription)/\(prefixLength) \(gateway?.maskedDescription ?? "default")}"
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
        return "addr \(address.maskedDescription)/\(addressPrefixLength) gw \(defaultGateway.maskedDescription) routes \(routes.map { $0.maskedDescription })"
    }
}

private extension SocketType {
    init?(protoString: String) {
        var str = protoString
        if str.hasSuffix("6") {
            str.removeLast()
        }
        self.init(rawValue: str.uppercased())
    }
}
