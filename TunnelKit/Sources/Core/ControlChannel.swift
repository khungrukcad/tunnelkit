//
//  ControlChannel.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 9/9/18.
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
import __TunnelKitNative

// TODO: make all private

class ControlChannel {
    private(set) var queue: BidirectionalState<[ControlPacket]>

    private(set) var packetId: BidirectionalState<UInt32>

    private var pendingAcks: Set<UInt32>

    private var plainBuffer: ZeroingData

    private var dataCount: BidirectionalState<Int>

    init() {
        queue = BidirectionalState(withResetValue: [])
        packetId = BidirectionalState(withResetValue: 0)
        pendingAcks = []
        plainBuffer = Z(count: TLSBoxMaxBufferLength)
        dataCount = BidirectionalState(withResetValue: 0)
    }
    
    func addPendingAck(_ packetId: UInt32) {
        pendingAcks.insert(packetId)
    }
    
    func removePendingAcks(_ packetIds: [UInt32]) {
        pendingAcks.subtract(packetIds)
    }
    
    func hasPendingAcks() -> Bool {
        return !pendingAcks.isEmpty
    }
    
    func currentControlData(withTLS tls: TLSBox) throws -> ZeroingData {
        var length = 0
        try tls.pullRawPlainText(plainBuffer.mutableBytes, length: &length)
        return plainBuffer.withOffset(0, count: length)
    }
    
    func addReceivedDataCount(_ count: Int) {
        dataCount.inbound += count
    }

    func addSentDataCount(_ count: Int) {
        dataCount.outbound += count
    }
    
    func currentDataCount() -> (Int, Int) {
        return dataCount.pair
    }
    
    func reset() {
        plainBuffer.zero()
        queue.reset()
        pendingAcks.removeAll()
        packetId.reset()
        dataCount.reset()
    }
}
