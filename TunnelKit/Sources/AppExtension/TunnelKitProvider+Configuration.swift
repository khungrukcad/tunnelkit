//
//  TunnelKitProvider+Configuration.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 10/23/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import Foundation
import NetworkExtension
import SwiftyBeaver

private let log = SwiftyBeaver.self

extension TunnelKitProvider {
    
    // MARK: Cryptography
    
    /// The available encryption algorithms.
    public enum Cipher: String {

        // WARNING: must match OpenSSL algorithm names

        /// AES encryption with 128-bit key size and CBC.
        case aes128cbc = "AES-128-CBC"
        
        /// AES encryption with 256-bit key size and CBC.
        case aes256cbc = "AES-256-CBC"

        /// AES encryption with 128-bit key size and GCM.
        case aes128gcm = "AES-128-GCM"

        /// AES encryption with 256-bit key size and GCM.
        case aes256gcm = "AES-256-GCM"
    }
    
    /// The available message digest algorithms.
    public enum Digest: String {
        
        // WARNING: must match OpenSSL algorithm names
        
        /// SHA1 message digest.
        case sha1 = "SHA1"
        
        /// SHA256 message digest.
        case sha256 = "SHA256"
    }
}

extension TunnelKitProvider {

    // MARK: Configuration
    
    /// A socket type between UDP (recommended) and TCP.
    public enum SocketType: String {

        /// UDP socket type.
        case udp = "UDP"
        
        /// TCP socket type.
        case tcp = "TCP"
    }
    
    /// Defines the communication protocol of an endpoint.
    public struct EndpointProtocol: Equatable, CustomStringConvertible {

        /// The socket type.
        public let socketType: SocketType
        
        /// The remote port.
        public let port: UInt16
        
        /// :nodoc:
        public init(_ socketType: SocketType, _ port: UInt16) {
            self.socketType = socketType
            self.port = port
        }
        
        // MARK: Equatable
        
        /// :nodoc:
        public static func ==(lhs: EndpointProtocol, rhs: EndpointProtocol) -> Bool {
            return (lhs.socketType == rhs.socketType) && (lhs.port == rhs.port)
        }
        
        // MARK: CustomStringConvertible
        
        /// :nodoc:
        public var description: String {
            return "\(socketType.rawValue):\(port)"
        }
    }

    /// Encapsulates an endpoint along with the authentication credentials.
    public struct AuthenticatedEndpoint {
        
        /// The remote hostname or IP address.
        public let hostname: String
        
        /// The username.
        public let username: String
        
        /// The password.
        public let password: String
        
        /// :nodoc:
        public init(hostname: String, username: String, password: String) {
            self.hostname = hostname
            self.username = username
            self.password = password
        }
        
        init(protocolConfiguration: NEVPNProtocol) throws {
            guard let hostname = protocolConfiguration.serverAddress else {
                throw ProviderError.configuration(field: "protocolConfiguration.serverAddress")
            }
            guard let username = protocolConfiguration.username else {
                throw ProviderError.credentials(field: "protocolConfiguration.username")
            }
            guard let passwordReference = protocolConfiguration.passwordReference else {
                throw ProviderError.credentials(field: "protocolConfiguration.passwordReference")
            }
            guard let password = try? Keychain.password(for: username, reference: passwordReference) else {
                throw ProviderError.credentials(field: "protocolConfiguration.passwordReference (keychain)")
            }
            
            self.hostname = hostname
            self.username = username
            self.password = password
        }
    }
    
    /// The way to create a `TunnelKitProvider.Configuration` object for the tunnel profile.
    public struct ConfigurationBuilder {
        
        // MARK: App group
        
        /// The name of a shared app group.
        public let appGroup: String
        
        // MARK: Tunnel parameters
        
        /// Prefers resolved addresses over DNS resolution. `resolvedAddresses` must be set and non-empty. Default is `false`.
        ///
        /// - Seealso: `fallbackServerAddresses`
        public var prefersResolvedAddresses: Bool
        
        /// Resolved addresses in case DNS fails or `prefersResolvedAddresses` is `true`.
        public var resolvedAddresses: [String]?
        
        /// The accepted communication protocols. Must be non-empty.
        public var endpointProtocols: [EndpointProtocol]

        /// The encryption algorithm.
        public var cipher: Cipher
        
        /// The message digest algorithm.
        public var digest: Digest
        
        /// The optional CA certificate to validate server against. Set to `nil` to disable CA validation (default).
        public var ca: Certificate?
        
        /// The MTU of the tunnel.
        public var mtu: NSNumber
        
        /// The number of seconds after which a renegotiation is started. Set to `nil` to disable renegotiation (default).
        public var renegotiatesAfterSeconds: Int?
        
        // MARK: Debugging
        
        /// Enables debugging. If `true`, then `debugLogKey` is a mandatory field.
        public var shouldDebug: Bool
        
        /// The key in `defaults` where the latest debug log snapshot is stored. Ignored if `shouldDebug` is `false`.
        public var debugLogKey: String?
        
        /// Optional debug log format (SwiftyBeaver format).
        public var debugLogFormat: String?
        
        // MARK: Building
        
        /**
         Default initializer.
         
         - Parameter appGroup: The name of the app group in which the tunnel extension lives in.
         */
        public init(appGroup: String) {
            self.appGroup = appGroup
            prefersResolvedAddresses = false
            resolvedAddresses = nil
            endpointProtocols = [EndpointProtocol(.udp, 1194)]
            cipher = .aes128cbc
            digest = .sha1
            ca = nil
            mtu = 1500
            renegotiatesAfterSeconds = nil
            shouldDebug = false
            debugLogKey = nil
            debugLogFormat = nil
        }
        
        fileprivate init(providerConfiguration: [String: Any]) throws {
            let S = Configuration.Keys.self

            guard let appGroup = providerConfiguration[S.appGroup] as? String else {
                throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.appGroup)]")
            }
            guard let cipherAlgorithm = providerConfiguration[S.cipherAlgorithm] as? String, let cipher = Cipher(rawValue: cipherAlgorithm) else {
                throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.cipherAlgorithm)]")
            }
            guard let digestAlgorithm = providerConfiguration[S.digestAlgorithm] as? String, let digest = Digest(rawValue: digestAlgorithm) else {
                throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.digestAlgorithm)]")
            }

            let ca: Certificate?
            if let caPEM = providerConfiguration[S.ca] as? String {
                ca = Certificate(pem: caPEM)
            } else {
                ca = nil
            }

            prefersResolvedAddresses = providerConfiguration[S.prefersResolvedAddresses] as? Bool ?? false
            resolvedAddresses = providerConfiguration[S.resolvedAddresses] as? [String]
            guard let endpointProtocolsStrings = providerConfiguration[S.endpointProtocols] as? [String], !endpointProtocolsStrings.isEmpty else {
                throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.endpointProtocols)] is nil or empty")
            }
            endpointProtocols = try endpointProtocolsStrings.map {
                let components = $0.components(separatedBy: ":")
                guard components.count == 2 else {
                    throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.endpointProtocols)] entries must be in the form 'socketType:port'")
                }
                let socketTypeString = components[0]
                let portString = components[1]
                guard let socketType = SocketType(rawValue: socketTypeString) else {
                    throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.endpointProtocols)] unrecognized socketType '\(socketTypeString)'")
                }
                guard let port = UInt16(portString) else {
                    throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.endpointProtocols)] non-numeric port '\(portString)'")
                }
                return EndpointProtocol(socketType, port)
            }
            
            self.appGroup = appGroup
            self.cipher = cipher
            self.digest = digest
            self.ca = ca
            mtu = providerConfiguration[S.mtu] as? NSNumber ?? 1500
            renegotiatesAfterSeconds = providerConfiguration[S.renegotiatesAfter] as? Int

            shouldDebug = providerConfiguration[S.debug] as? Bool ?? false
            if shouldDebug {
                guard let debugLogKey = providerConfiguration[S.debugLogKey] as? String else {
                    throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.debugLogKey)]")
                }
                self.debugLogKey = debugLogKey
                debugLogFormat = providerConfiguration[S.debugLogFormat] as? String
            } else {
                debugLogKey = nil
            }

            guard !prefersResolvedAddresses || !(resolvedAddresses?.isEmpty ?? true) else {
                throw ProviderError.configuration(field: "protocolConfiguration.providerConfiguration[\(S.prefersResolvedAddresses)] is true but no [\(S.resolvedAddresses)]")
            }
        }
        
        /**
         Builds a `TunnelKitProvider.Configuration` object that will connect to the provided endpoint.
         
         - Returns: A `TunnelKitProvider.Configuration` object with this builder and the additional method parameters.
         */
        public func build() -> Configuration {
            return Configuration(
                appGroup: appGroup,
                prefersResolvedAddresses: prefersResolvedAddresses,
                resolvedAddresses: resolvedAddresses,
                endpointProtocols: endpointProtocols,
                cipher: cipher,
                digest: digest,
                ca: ca,
                mtu: mtu,
                renegotiatesAfterSeconds: renegotiatesAfterSeconds,
                shouldDebug: shouldDebug,
                debugLogKey: shouldDebug ? debugLogKey : nil,
                debugLogFormat: shouldDebug ? debugLogFormat : nil
            )
        }
    }
    
    /// Offers a bridge between the abstract `TunnelKitProvider.ConfigurationBuilder` and a concrete `NETunnelProviderProtocol` profile.
    public struct Configuration {
        struct Keys {
            static let appGroup = "AppGroup"
            
            static let prefersResolvedAddresses = "PrefersResolvedAddresses"

            static let resolvedAddresses = "ResolvedAddresses"

            static let endpointProtocols = "EndpointProtocols"
            
            static let cipherAlgorithm = "CipherAlgorithm"
            
            static let digestAlgorithm = "DigestAlgorithm"
            
            static let ca = "CA"
            
            static let mtu = "MTU"
            
            static let renegotiatesAfter = "RenegotiatesAfter"
            
            static let debug = "Debug"
            
            static let debugLogKey = "DebugLogKey"
            
            static let debugLogFormat = "DebugLogFormat"
        }
        
        /// - Seealso: `TunnelKitProvider.ConfigurationBuilder.appGroup`
        public let appGroup: String
        
        /// - Seealso: `TunnelKitProvider.ConfigurationBuilder.prefersResolvedAddresses`
        public let prefersResolvedAddresses: Bool
        
        /// - Seealso: `TunnelKitProvider.ConfigurationBuilder.resolvedAddresses`
        public let resolvedAddresses: [String]?

        /// - Seealso: `TunnelKitProvider.ConfigurationBuilder.endpointProtocols`
        public let endpointProtocols: [EndpointProtocol]
        
        /// - Seealso: `TunnelKitProvider.ConfigurationBuilder.cipher`
        public let cipher: Cipher
        
        /// - Seealso: `TunnelKitProvider.ConfigurationBuilder.digest`
        public let digest: Digest
        
        /// - Seealso: `TunnelKitProvider.ConfigurationBuilder.ca`
        public let ca: Certificate?
        
        /// - Seealso: `TunnelKitProvider.ConfigurationBuilder.mtu`
        public let mtu: NSNumber
        
        /// - Seealso: `TunnelKitProvider.ConfigurationBuilder.renegotiatesAfterSeconds`
        public let renegotiatesAfterSeconds: Int?
        
        /// - Seealso: `TunnelKitProvider.ConfigurationBuilder.shouldDebug`
        public let shouldDebug: Bool
        
        /// - Seealso: `TunnelKitProvider.ConfigurationBuilder.debugLogKey`
        public let debugLogKey: String?
        
        /// - Seealso: `TunnelKitProvider.ConfigurationBuilder.debugLogFormat`
        public let debugLogFormat: String?
        
        // MARK: Shortcuts

        var defaults: UserDefaults? {
            return UserDefaults(suiteName: appGroup)
        }
        
        var existingLog: [String]? {
            guard shouldDebug, let key = debugLogKey else {
                return nil
            }
            return defaults?.array(forKey: key) as? [String]
        }
        
        // MARK: API
        
        /**
         Parses a new `TunnelKitProvider.Configuration` object from a provider configuration map.
         
         - Parameter from: The map to parse.
         - Returns: The parsed `TunnelKitProvider.Configuration` object.
         - Throws: `ProviderError.configuration` if `providerConfiguration` is incomplete.
         */
        public static func parsed(from providerConfiguration: [String: Any]) throws -> Configuration {
            let builder = try ConfigurationBuilder(providerConfiguration: providerConfiguration)
            return builder.build()
        }
        
        /**
         Returns a dictionary representation of this configuration for use with `NETunnelProviderProtocol.providerConfiguration`.

         - Returns: The dictionary representation of `self`.
         */
        public func generatedProviderConfiguration() -> [String: Any] {
            let S = Keys.self
            
            var dict: [String: Any] = [
                S.appGroup: appGroup,
                S.prefersResolvedAddresses: prefersResolvedAddresses,
                S.endpointProtocols: endpointProtocols.map {
                    "\($0.socketType.rawValue):\($0.port)"
                },
                S.cipherAlgorithm: cipher.rawValue,
                S.digestAlgorithm: digest.rawValue,
                S.mtu: mtu,
                S.debug: shouldDebug
            ]
            if let ca = ca {
                dict[S.ca] = ca.pem
            }
            if let resolvedAddresses = resolvedAddresses {
                dict[S.resolvedAddresses] = resolvedAddresses
            }
            if let renegotiatesAfterSeconds = renegotiatesAfterSeconds {
                dict[S.renegotiatesAfter] = renegotiatesAfterSeconds
            }
            if let debugLogKey = debugLogKey {
                dict[S.debugLogKey] = debugLogKey
            }
            if let debugLogFormat = debugLogFormat {
                dict[S.debugLogFormat] = debugLogFormat
            }
            return dict
        }
        
        /**
         Generates a `NETunnelProviderProtocol` from this configuration.
         
         - Parameter bundleIdentifier: The provider bundle identifier required to locate the tunnel extension.
         - Parameter endpoint: The `TunnelKitProvider.AuthenticatedEndpoint` the tunnel will connect to.
         - Returns: The generated `NETunnelProviderProtocol` object.
         - Throws: `ProviderError.configuration` if unable to store the `endpoint.password` to the `appGroup` keychain.
         */
        public func generatedTunnelProtocol(withBundleIdentifier bundleIdentifier: String, endpoint: AuthenticatedEndpoint) throws -> NETunnelProviderProtocol {
            let protocolConfiguration = NETunnelProviderProtocol()
            
            let keychain = Keychain(group: appGroup)
            do {
                try keychain.set(password: endpoint.password, for: endpoint.username, label: Bundle.main.bundleIdentifier)
            } catch _ {
                throw ProviderError.credentials(field: "keychain.set()")
            }
            
            protocolConfiguration.providerBundleIdentifier = bundleIdentifier
            protocolConfiguration.serverAddress = endpoint.hostname
            protocolConfiguration.username = endpoint.username
            protocolConfiguration.passwordReference = try? keychain.passwordReference(for: endpoint.username)
            protocolConfiguration.providerConfiguration = generatedProviderConfiguration()
            
            return protocolConfiguration
        }
        
        func print(appVersion: String?) {
            if let appVersion = appVersion {
                log.info("App version: \(appVersion)")
            }
            
//            log.info("Address: \(endpoint.hostname):\(endpoint.port)")
            log.info("Protocols: \(endpointProtocols)")
            log.info("Cipher: \(cipher.rawValue)")
            log.info("Digest: \(digest.rawValue)")
            if let _ = ca {
                log.info("CA verification: enabled")
            } else {
                log.info("CA verification: disabled")
            }
            log.info("MTU: \(mtu)")
            if let renegotiatesAfterSeconds = renegotiatesAfterSeconds {
                log.info("Renegotiation: \(renegotiatesAfterSeconds) seconds")
            } else {
                log.info("Renegotiation: never")
            }
            log.info("Debug: \(shouldDebug)")
        }
    }
}

// MARK: Modification

extension TunnelKitProvider.Configuration: Equatable {

    /**
     Returns a `TunnelKitProvider.ConfigurationBuilder` to use this configuration as a starting point for a new one.

     - Returns: An editable `TunnelKitProvider.ConfigurationBuilder` initialized with this configuration.
     */
    public func builder() -> TunnelKitProvider.ConfigurationBuilder {
        var builder = TunnelKitProvider.ConfigurationBuilder(appGroup: appGroup)
        builder.endpointProtocols = endpointProtocols
        builder.cipher = cipher
        builder.digest = digest
        builder.ca = ca
        builder.mtu = mtu
        builder.renegotiatesAfterSeconds = renegotiatesAfterSeconds
        builder.shouldDebug = shouldDebug
        builder.debugLogKey = debugLogKey
        return builder
    }

    /// :nodoc:
    public static func ==(lhs: TunnelKitProvider.Configuration, rhs: TunnelKitProvider.Configuration) -> Bool {
        return (
            (lhs.endpointProtocols == rhs.endpointProtocols) &&
            (lhs.cipher == rhs.cipher) &&
            (lhs.digest == rhs.digest) &&
            (lhs.ca == rhs.ca) &&
            (lhs.mtu == rhs.mtu) &&
            (lhs.renegotiatesAfterSeconds == rhs.renegotiatesAfterSeconds)
        )
    }
}
