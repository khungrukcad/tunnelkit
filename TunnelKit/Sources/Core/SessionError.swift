//
//  SessionError.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 23/08/2018.
//  Copyright © 2018 Davide De Rosa. All rights reserved.
//

import Foundation

/// The possible errors raised/thrown during `SessionProxy` operation.
public enum SessionError: Error {
    
    /// The negotiation timed out.
    case negotiationTimeout
    
    /// The peer failed to verify.
    case peerVerification
    
    /// The VPN session id is missing.
    case missingSessionId
    
    /// The VPN session id doesn't match.
    case sessionMismatch
    
    /// The connection key is wrong or wasn't expected.
    case badKey
    
    /// The TLS negotiation failed.
    case tlsError
    
    /// The control packet has an incorrect prefix payload.
    case wrongControlDataPrefix
    
    /// The provided credentials failed authentication.
    case badCredentials
    
    /// The reply to PUSH_REQUEST is malformed.
    case malformedPushReply
    
    /// A write operation failed at the link layer (e.g. network unreachable).
    case failedLinkWrite
    
    /// The server couldn't ping back before timeout.
    case pingTimeout
}
