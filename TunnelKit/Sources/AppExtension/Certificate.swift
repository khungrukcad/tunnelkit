//
//  Certificate.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 22/08/2018.
//  Copyright © 2018 Davide De Rosa. All rights reserved.
//

import Foundation

/// Represents a TLS certificate in PEM format.
public struct Certificate: Equatable {

    /// The content of the certificates in PEM format (ASCII).
    public let pem: String
    
    /// :nodoc:
    public init(pem: String) {
        self.pem = pem
    }
    
    func write(to url: URL) throws {
        try pem.write(to: url, atomically: true, encoding: .ascii)
    }

    // MARK: Equatable
    
    /// :nodoc:
    public static func ==(lhs: Certificate, rhs: Certificate) -> Bool {
        return lhs.pem == rhs.pem
    }
}
