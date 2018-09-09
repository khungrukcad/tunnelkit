//
//  ControlChannelSerializer.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 9/10/18.
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

import Foundation
import SwiftyBeaver

private let log = SwiftyBeaver.self

protocol ControlChannelSerializer {
    func reset()
    
    func serialize(packet: ControlPacket) throws -> Data

    func deserialize(data: Data, from: Int) throws -> ControlPacket
}

extension ControlChannel {
    class PlainSerializer: ControlChannelSerializer {
        func reset() {
            // TODO
        }
        
        func serialize(packet: ControlPacket) throws -> Data {
            // TODO
            throw SessionError.pingTimeout
        }
        
        func deserialize(data: Data, from: Int) throws -> ControlPacket {
            // TODO
            throw SessionError.pingTimeout
        }
    }
}
