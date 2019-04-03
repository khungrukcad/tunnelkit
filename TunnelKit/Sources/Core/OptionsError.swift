//
//  OptionsError.swift
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

/// Error raised by the options parser, with details about the line that triggered it.
public enum OptionsError: Error {
    
    /// Option syntax is incorrect.
    case malformed(option: String)
    
    /// The file misses a required option.
    case missingConfiguration(option: String)
    
    /// The file includes an unsupported option.
    case unsupportedConfiguration(option: String)
    
    /// Passphrase required to decrypt private keys.
    case encryptionPassphrase
    
    /// Encryption passphrase is incorrect or key is corrupt.
    case unableToDecrypt(error: Error)
}
