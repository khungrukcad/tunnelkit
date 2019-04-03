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

public struct OptionsBundle {
    private struct Regex {
        
        // shared
        
        static let cipher = NSRegularExpression("^cipher +[^,\\s]+")
        
        static let auth = NSRegularExpression("^auth +[\\w\\-]+")
        
        static let compLZO = NSRegularExpression("^comp-lzo.*")
        
        static let compress = NSRegularExpression("^compress.*")
        
        static let ping = NSRegularExpression("^ping +\\d+")
        
        static let renegSec = NSRegularExpression("^reneg-sec +\\d+")
        
        static let blockBegin = NSRegularExpression("^<[\\w\\-]+>")
        
        static let blockEnd = NSRegularExpression("^<\\/[\\w\\-]+>")
        
        static let keyDirection = NSRegularExpression("^key-direction +\\d")
        
        static let gateway = NSRegularExpression("route-gateway [\\d\\.]+")
        
        static let route = NSRegularExpression("route [\\d\\.]+( [\\d\\.]+){0,2}")
        
        static let route6 = NSRegularExpression("route-ipv6 [\\da-fA-F:]+/\\d+( [\\da-fA-F:]+){0,2}")
        
        static let dns = NSRegularExpression("^dhcp-option +DNS6? +[\\d\\.a-fA-F:]+")
        
        static let remoteRandom = NSRegularExpression("^remote-random")
        
        // client
        
        static let proto = NSRegularExpression("^proto +(udp6?|tcp6?)")
        
        static let port = NSRegularExpression("^port +\\d+")
        
        static let remote = NSRegularExpression("^remote +[^ ]+( +\\d+)?( +(udp6?|tcp6?))?")
        
        static let eku = NSRegularExpression("^remote-cert-tls +server")
        
        // server
        
        static let topology = NSRegularExpression("topology (net30|p2p|subnet)")
        
        static let ifconfig = NSRegularExpression("ifconfig [\\d\\.]+ [\\d\\.]+")
        
        static let ifconfig6 = NSRegularExpression("ifconfig-ipv6 [\\da-fA-F:]+/\\d+ [\\da-fA-F:]+")
        
        static let authToken = NSRegularExpression("auth-token [a-zA-Z0-9/=+]+")
        
        static let peerId = NSRegularExpression("peer-id [0-9]+")
        
        // unsupported
        
//        static let fragment = NSRegularExpression("^fragment +\\d+")
        static let fragment = NSRegularExpression("^fragment")
        
        static let proxy = NSRegularExpression("^\\w+-proxy")
        
        static let externalFiles = NSRegularExpression("^(ca|cert|key|tls-auth|tls-crypt) ")
        
        static let connection = NSRegularExpression("^<connection>")
    }
    
    public let strippedLines: [String]?
    
    public let warning: OptionsError?
    
    //
    
    public let hostname: String?
    
    public let remotes: [(String, UInt16, SocketType)]
    
    public let cipher: SessionProxy.Cipher?

    public let digest: SessionProxy.Digest?

    public let compressionFraming: SessionProxy.CompressionFraming?

    public let compressionAlgorithm: SessionProxy.CompressionAlgorithm?

    public let ca: CryptoContainer?

    public let clientCertificate: CryptoContainer?

    public let clientKey: CryptoContainer?

    public let checksEKU: Bool

    public let keepAliveSeconds: TimeInterval?

    public let renegotiateAfterSeconds: TimeInterval?

    public let tlsWrap: SessionProxy.TLSWrap?

    public let dnsServers: [String]

    public let randomizeEndpoint: Bool

    public init(from lines: [String], returnsStripped: Bool = false) throws {
        var optStrippedLines: [String]? = returnsStripped ? [] : nil
        var optWarning: OptionsError?
        var unsupportedError: OptionsError?

        var optHostname: String?
        var optDefaultProto: SocketType?
        var optDefaultPort: UInt16?
        var optRemotes: [(String, UInt16?, SocketType?)] = []
        var optCipher: SessionProxy.Cipher?
        var optDigest: SessionProxy.Digest?
        var optCompressionFraming: SessionProxy.CompressionFraming?
        var optCompressionAlgorithm: SessionProxy.CompressionAlgorithm?
        var optCA: CryptoContainer?
        var optClientCertificate: CryptoContainer?
        var optClientKey: CryptoContainer?
        var optChecksEKU: Bool?
        var optKeepAliveSeconds: TimeInterval?
        var optRenegotiateAfterSeconds: TimeInterval?
        var optKeyDirection: StaticKey.Direction?
        var optTLSKeyLines: [Substring]?
        var optTLSStrategy: SessionProxy.TLSWrap.Strategy?
        var optDnsServers: [String] = []
        var optRandomizeEndpoint: Bool?
        var currentBlockName: String?
        var currentBlock: [String] = []

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
            
            // check blocks first
            Regex.connection.enumerateComponents(in: line) { (_) in
                unsupportedError = OptionsError.unsupportedConfiguration(option: "<connection> blocks")
            }
            
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
            
            Regex.eku.enumerateComponents(in: line) { (_) in
                optChecksEKU = true
            }
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
            Regex.dns.enumerateArguments(in: line) {
                isHandled = true
                guard $0.count == 2 else {
                    return
                }
                optDnsServers.append($0[1])
            }
            Regex.remoteRandom.enumerateComponents(in: line) { (_) in
                optRandomizeEndpoint = true
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
            
            if let error = unsupportedError {
                throw error
            }
        }
        
        //
        
        strippedLines = optStrippedLines
        warning = optWarning
        
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

        cipher = optCipher
        digest = optDigest
        compressionFraming = optCompressionFraming
        compressionAlgorithm = optCompressionAlgorithm
        ca = optCA
        clientCertificate = optClientCertificate
        clientKey = optClientKey
        checksEKU = optChecksEKU ?? false
        keepAliveSeconds = optKeepAliveSeconds
        renegotiateAfterSeconds = optRenegotiateAfterSeconds
        dnsServers = optDnsServers
        randomizeEndpoint = optRandomizeEndpoint ?? false

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

private extension SocketType {
    init?(protoString: String) {
        var str = protoString
        if str.hasSuffix("6") {
            str.removeLast()
        }
        self.init(rawValue: str.uppercased())
    }
}
