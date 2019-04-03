//
//  ConfigurationParser.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 9/5/18.
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

/// Provides methods to parse a `SessionProxy.Configuration` from an .ovpn configuration file.
public class ConfigurationParser {

    /// Result of the parser.
    public struct ParsingResult {

        /// Original URL of the configuration file, if parsed from an URL.
        public let url: URL?

        /// The main endpoint hostname.
        public let hostname: String
        
        /// The list of `EndpointProtocol` to which the client can connect to.
        public let protocols: [EndpointProtocol]

        /// The overall parsed `SessionProxy.Configuration`.
        public let configuration: SessionProxy.Configuration

        /// - Seealso: `OptionsBundle.init(...)`
        public let strippedLines: [String]?
        
        /// - Seealso: `OptionsBundle.warning`
        public let warning: OptionsError?
    }
    
    /**
     Parses an .ovpn file from an URL.
     
     - Parameter url: The URL of the configuration file.
     - Parameter passphrase: The optional passphrase for encrypted data.
     - Parameter returnsStripped: When `true`, stores the stripped file into `ParsingResult.strippedLines`. Defaults to `false`.
     - Returns: The `ParsingResult` outcome of the parsing.
     - Throws: `OptionsError` if the configuration file is wrong or incomplete.
     */
    public static func parsed(fromURL url: URL, passphrase: String? = nil, returnsStripped: Bool = false) throws -> ParsingResult {
        let lines = try String(contentsOf: url).trimmedLines()
        return try parsed(fromLines: lines, passphrase: passphrase, originalURL: url, returnsStripped: returnsStripped)
    }

    /**
     Parses an .ovpn file as an array of lines.
     
     - Parameter lines: The array of lines holding the configuration.
     - Parameter passphrase: The optional passphrase for encrypted data.
     - Parameter originalURL: The optional original URL of the configuration file.
     - Parameter returnsStripped: When `true`, stores the stripped file into `ParsingResult.strippedLines`. Defaults to `false`.
     - Returns: The `ParsingResult` outcome of the parsing.
     - Throws: `OptionsError` if the configuration file is wrong or incomplete.
     */
    public static func parsed(fromLines lines: [String], passphrase: String? = nil, originalURL: URL? = nil, returnsStripped: Bool = false) throws -> ParsingResult {
        let options = try OptionsBundle(from: lines, returnsStripped: returnsStripped)
        
        guard let ca = options.ca else {
            throw OptionsError.missingConfiguration(option: "ca")
        }
        guard let hostname = options.hostname, !options.remotes.isEmpty else {
            throw OptionsError.missingConfiguration(option: "remote")
        }
        let endpointProtocols = options.remotes.map { EndpointProtocol($0.2, $0.1) }
        
        var optClientKey: CryptoContainer?
        if let clientKey = options.clientKey, clientKey.isEncrypted {
            guard let passphrase = passphrase else {
                throw OptionsError.encryptionPassphrase
            }
            do {
                optClientKey = try clientKey.decrypted(with: passphrase)
            } catch let e {
                throw OptionsError.unableToDecrypt(error: e)
            }
        } else {
            optClientKey = options.clientKey
        }
        
        var sessionBuilder = SessionProxy.ConfigurationBuilder(ca: ca)
        sessionBuilder.cipher = options.cipher ?? .aes128cbc
        sessionBuilder.digest = options.digest ?? .sha1
        sessionBuilder.compressionFraming = options.compressionFraming ?? .disabled
        sessionBuilder.compressionAlgorithm = options.compressionAlgorithm ?? .disabled
        sessionBuilder.tlsWrap = options.tlsWrap
        sessionBuilder.clientCertificate = options.clientCertificate
        sessionBuilder.clientKey = optClientKey
        sessionBuilder.checksEKU = options.checksEKU
        sessionBuilder.keepAliveInterval = options.keepAliveSeconds
        sessionBuilder.renegotiatesAfter = options.renegotiateAfterSeconds
        sessionBuilder.dnsServers = options.dnsServers
        sessionBuilder.randomizeEndpoint = options.randomizeEndpoint

        return ParsingResult(
            url: originalURL,
            hostname: hostname,
            protocols: endpointProtocols,
            configuration: sessionBuilder.build(),
            strippedLines: options.strippedLines,
            warning: options.warning
        )
    }
}

extension String {
    func trimmedLines() -> [String] {
        return components(separatedBy: .newlines).map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter {
            !$0.isEmpty
        }
    }
}
