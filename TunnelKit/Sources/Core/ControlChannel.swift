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
import SwiftyBeaver

private let log = SwiftyBeaver.self

class ControlChannel {
    private let serializer: ControlChannelSerializer
    
    private(set) var sessionId: Data?
    
    var remoteSessionId: Data?

    private var queue: BidirectionalState<[ControlPacket]>

    private var currentPacketId: BidirectionalState<UInt32>

    private var pendingAcks: Set<UInt32>

    private var plainBuffer: ZeroingData

    private var dataCount: BidirectionalState<Int>
    
    convenience init() {
        self.init(serializer: PlainSerializer())
    }
    
    private init(serializer: ControlChannelSerializer) {
        self.serializer = serializer
        sessionId = nil
        remoteSessionId = nil
        queue = BidirectionalState(withResetValue: [])
        currentPacketId = BidirectionalState(withResetValue: 0)
        pendingAcks = []
        plainBuffer = Z(count: TLSBoxMaxBufferLength)
        dataCount = BidirectionalState(withResetValue: 0)
    }
    
    func reset(forNewSession: Bool) throws {
        if forNewSession {
            try sessionId = SecureRandom.data(length: PacketSessionIdLength)
            remoteSessionId = nil
        }
        queue.reset()
        currentPacketId.reset()
        pendingAcks.removeAll()
        plainBuffer.zero()
        dataCount.reset()
    }
    
    func readInboundPacket(withCode code: PacketCode, key: UInt8, sessionId inboundSessionId: Data, packetId: UInt32, payload: Data?) -> [ControlPacket] {
        let packet = ControlPacket(code: code, key: key, sessionId: inboundSessionId, packetId: packetId, payload: payload)
        queue.inbound.append(packet)
        queue.inbound.sort { $0.packetId < $1.packetId }
        
        var toHandle: [ControlPacket] = []
        for queuedPacket in queue.inbound {
            if queuedPacket.packetId < currentPacketId.inbound {
                queue.inbound.removeFirst()
                continue
            }
            if queuedPacket.packetId != currentPacketId.inbound {
                continue
            }
            
            toHandle.append(queuedPacket)
            
            currentPacketId.inbound += 1
            queue.inbound.removeFirst()
        }
        return toHandle
    }
    
    func enqueueOutboundPackets(withCode code: PacketCode, key: UInt8, payload: Data, maxPacketSize: Int) {
        guard let sessionId = sessionId else {
            fatalError("Missing sessionId, do reset(forNewSession: true) first")
        }

        let oldIdOut = currentPacketId.outbound
        var queuedCount = 0
        var offset = 0
        
        repeat {
            let subPayloadLength = min(maxPacketSize, payload.count - offset)
            let subPayloadData = payload.subdata(offset: offset, count: subPayloadLength)
            let packet = ControlPacket(code: code, key: key, sessionId: sessionId, packetId: currentPacketId.outbound, payload: subPayloadData)
            
            queue.outbound.append(packet)
            currentPacketId.outbound += 1
            offset += maxPacketSize
            queuedCount += subPayloadLength
        } while (offset < payload.count)
        
        assert(queuedCount == payload.count)
        
        // packet count
        let packetCount = currentPacketId.outbound - oldIdOut
        if (packetCount > 1) {
            log.debug("Enqueued \(packetCount) control packets [\(oldIdOut)-\(currentPacketId.outbound - 1)]")
        } else {
            log.debug("Enqueued 1 control packet [\(oldIdOut)]")
        }
    }
    
    func writeOutboundPackets() -> [Data] {
        var rawList: [Data] = []
        for packet in queue.outbound {
            if let sentDate = packet.sentDate {
                let timeAgo = -sentDate.timeIntervalSinceNow
                guard (timeAgo >= CoreConfiguration.retransmissionLimit) else {
                    log.debug("Skip control packet with id \(packet.packetId) (sent on \(sentDate), \(timeAgo) seconds ago)")
                    continue
                }
            }
            
            log.debug("Send control packet with code \(packet.code.rawValue)")
            
            if let payload = packet.payload {
                if CoreConfiguration.logsSensitiveData {
                    log.debug("Control packet has payload (\(payload.count) bytes): \(payload.toHex())")
                } else {
                    log.debug("Control packet has payload (\(payload.count) bytes)")
                }
            }
            
            let raw = packet.serialized()
            rawList.append(raw)
            packet.sentDate = Date()

            // track pending acks for sent packets
            pendingAcks.insert(packet.packetId)
        }
//        log.verbose("Packets now pending ack: \(pendingAcks)")
        return rawList
    }
    
    func hasPendingAcks() -> Bool {
        return !pendingAcks.isEmpty
    }
    
    func readAcks(_ packetIds: [UInt32], acksRemoteSessionId: Data) throws {
        guard let sessionId = sessionId else {
            throw SessionError.missingSessionId
        }
        guard acksRemoteSessionId == sessionId else {
            log.error("Ack session mismatch (\(acksRemoteSessionId.toHex()) != \(sessionId.toHex()))")
            throw SessionError.sessionMismatch
        }
        
        // drop queued out packets if ack-ed
        for (i, packet) in queue.outbound.enumerated() {
            if packetIds.contains(packet.packetId) {
                queue.outbound.remove(at: i)
            }
        }
        
        // remove ack-ed packets from pending
        pendingAcks.subtract(packetIds)
        
//        log.verbose("Packets still pending ack: \(pendingAcks)")
    }
    
    func writeAcks(withKey key: UInt8, ackPacketIds: [UInt32], ackRemoteSessionId: Data) throws -> Data {
        guard let sessionId = sessionId else {
            throw SessionError.missingSessionId
        }
        let ackPacket = ControlPacket(key: key, sessionId: sessionId, ackIds: ackPacketIds as [NSNumber], ackRemoteSessionId: ackRemoteSessionId)
        return ackPacket.serialized()
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
}
