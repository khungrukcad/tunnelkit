//
//  SessionProxy+Configuration.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 23/08/2018.
//  Copyright © 2018 Davide De Rosa. All rights reserved.
//

import Foundation

extension SessionProxy {

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
    
    /// The way to create a `SessionProxy.Configuration` object for a `SessionProxy`.
    public struct ConfigurationBuilder {
        
        /// An username.
        public let username: String
        
        /// A password.
        public let password: String
        
        /// The cipher algorithm for data encryption.
        public var cipher: Cipher
        
        /// The digest algorithm for HMAC.
        public var digest: Digest
        
        /// The path to the optional CA for TLS negotiation (PEM format).
        public var caPath: String?
    
        /// Sends periodical keep-alive packets if set.
        public var keepAliveInterval: TimeInterval?
        
        /// The number of seconds after which a renegotiation should be initiated. If `nil`, the client will never initiate a renegotiation.
        public var renegotiatesAfter: TimeInterval?
        
        /// :nodoc:
        public init(username: String, password: String) {
            self.username = username
            self.password = password
            cipher = .aes128cbc
            digest = .sha1
            caPath = nil
            keepAliveInterval = nil
            renegotiatesAfter = nil
        }

        /**
         Builds a `SessionProxy.Configuration` object.
         
         - Returns: A `SessionProxy.Configuration` object with this builder.
         */
        public func build() -> Configuration {
            return Configuration(
                username: username,
                password: password,
                cipher: cipher,
                digest: digest,
                caPath: caPath,
                keepAliveInterval: keepAliveInterval,
                renegotiatesAfter: renegotiatesAfter
            )
        }
    }
    
    /// The immutable configuration for `SessionProxy`.
    public struct Configuration {

        /// - Seealso: `SessionProxy.ConfigurationBuilder.username`
        public let username: String
        
        /// - Seealso: `SessionProxy.ConfigurationBuilder.password`
        public let password: String
        
        /// - Seealso: `SessionProxy.ConfigurationBuilder.cipher`
        public let cipher: Cipher
        
        /// - Seealso: `SessionProxy.ConfigurationBuilder.digest`
        public let digest: Digest
        
        /// - Seealso: `SessionProxy.ConfigurationBuilder.caPath`
        public let caPath: String?

        /// - Seealso: `SessionProxy.ConfigurationBuilder.keepAliveInterval`
        public let keepAliveInterval: TimeInterval?

        /// - Seealso: `SessionProxy.ConfigurationBuilder.renegotiatesAfter`
        public let renegotiatesAfter: TimeInterval?
    }
}
