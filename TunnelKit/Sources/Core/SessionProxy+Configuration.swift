//
//  SessionProxy+Configuration.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 23/08/2018.
//  Copyright © 2018 Davide De Rosa. All rights reserved.
//

import Foundation

extension SessionProxy {

    /// The way to create a `SessionProxy.Configuration` object for a `SessionProxy`.
    public struct ConfigurationBuilder {
        
        /// An username.
        public let username: String
        
        /// A password.
        public let password: String
        
        /// The cipher algorithm for data encryption. Must follow OpenSSL nomenclature, e.g. "AES-128-CBC".
        public var cipherName: String
        
        /// The digest algorithm for HMAC. Must follow OpenSSL nomenclature, e.g. "SHA-1".
        public var digestName: String
        
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
            cipherName = "AES-128-CBC"
            digestName = "SHA-1"
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
                cipherName: cipherName,
                digestName: digestName,
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
        
        /// - Seealso: `SessionProxy.ConfigurationBuilder.cipherName`
        public let cipherName: String
        
        /// - Seealso: `SessionProxy.ConfigurationBuilder.digestName`
        public let digestName: String
        
        /// - Seealso: `SessionProxy.ConfigurationBuilder.caPath`
        public let caPath: String?

        /// - Seealso: `SessionProxy.ConfigurationBuilder.keepAliveInterval`
        public let keepAliveInterval: TimeInterval?

        /// - Seealso: `SessionProxy.ConfigurationBuilder.renegotiatesAfter`
        public let renegotiatesAfter: TimeInterval?
    }
}
