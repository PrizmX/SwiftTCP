import Foundation

/// Single-threaded (actor-serial) TCP engine. One 4-tuple never migrates.
actor TCPEventLoop {
    nonisolated let id: Int
    nonisolated let executor: LoopExecutor

    private var pcbs: [FlowKey: TCPControlBlock] = [:]
    private var pcbPool: [TCPControlBlock] = []
    private let pcbPoolLimit = 512
    private let txPool = TXBufferPool()
    private var pollTask: Task<Void, Never>?
    private var pollTarget: ContinuousClock.Instant?
    private let sink: any PacketSink
    private let streams: any TCPStreamHandler
    private let config: TCPStackConfig
    private var sendWaiters: [FlowKey: [CheckedContinuation<Void, Never>]] = [:]

    nonisolated var unownedExecutor: UnownedSerialExecutor {
        executor.asUnownedSerialExecutor()
    }

    init(id: Int, config: TCPStackConfig, sink: any PacketSink, streams: any TCPStreamHandler) {
        self.id = id
        self.executor = LoopExecutor(label: "swifttcp.loop.\(id)")
        self.sink = sink
        self.streams = streams
        self.config = config
    }

    func connectionCount() -> Int { pcbs.count }

    func ingestBatch(_ packets: [InboundTCPPacket]) {
        let now = ContinuousClock().now
        var outbound: [OutboundPacket] = []
        outbound.reserveCapacity(packets.count)
        var established: [FlowKey] = []
        var delivered: [(FlowKey, Data)] = []
        var closed: [FlowKey] = []
        for packet in packets {
            let result = process(segment: packet.segment, data: packet.data, now: now)
            outbound.append(contentsOf: result.outbound)
            established.append(contentsOf: result.established)
            delivered.append(contentsOf: result.delivered)
            closed.append(contentsOf: result.closed)
            resumeSendWaitersIfNeeded(packet.flow)
        }
        let coalesced = Self.coalescePureAcks(outbound)
        emit(
            outbound: coalesced,
            established: established,
            delivered: delivered,
            closed: closed
        )
        tick(now: now)
        armPoll()
    }

    @discardableResult
    func send(flow: FlowKey, data: Data) async -> Int {
        var offset = 0
        while offset < data.count {
            guard let pcb = pcbs[flow], pcb.canAppSend else { return offset }
            if pcb.sendAvailable == 0 {
                await waitForSendSpace(flow)
                continue
            }
            let take = min(data.count - offset, pcb.sendAvailable)
            let slice = take == data.count && offset == 0
                ? data
                : data.subdata(in: offset..<(offset + take))
            commit(pcb.onAppSend(slice), pcb: pcb)
            offset += take
        }
        armPoll()
        return offset
    }

    func applyPMTU(flow: FlowKey, mtu: Int) {
        pcbs[flow]?.applyPMTU(mtu: mtu)
    }

    func sendBatch(_ items: [(FlowKey, Data)]) {
        var outbound: [OutboundPacket] = []
        var established: [FlowKey] = []
        var delivered: [(FlowKey, Data)] = []
        var closed: [FlowKey] = []
        outbound.reserveCapacity(items.count)
        for (flow, data) in items {
            guard let pcb = pcbs[flow] else { continue }
            let result = apply(pcb.onAppSend(data), pcb: pcb)
            outbound.append(contentsOf: result.outbound)
            established.append(contentsOf: result.established)
            delivered.append(contentsOf: result.delivered)
            closed.append(contentsOf: result.closed)
        }
        emit(
            outbound: Self.coalescePureAcks(outbound),
            established: established,
            delivered: delivered,
            closed: closed
        )
        armPoll()
    }

    func close(flow: FlowKey) {
        guard let pcb = pcbs[flow] else { return }
        commit(pcb.onAppClose(), pcb: pcb)
        armPoll()
    }

    func creditAppReceive(flow: FlowKey, bytes: Int) {
        guard bytes > 0, let pcb = pcbs[flow] else { return }
        let before = pcb.rcvWnd
        pcb.creditAppReceive(bytes)
        if pcb.rcvWnd > before {
            commit([pcb.emitAck(), .cancel(.delayedAck)], pcb: pcb)
        }
    }

    /// Active open toward `flow.dst`. PCB identity is the guest-originated 4-tuple
    /// (`src` = guest) so later SYN-ACK / data match the same key as TUN ingest.
    func connect(flow: FlowKey) {
        guard pcbs[flow] == nil, pcbs.count < config.maxConnections else { return }
        let pcb = makePCB(flow: flow)
        pcbs[flow] = pcb
        commit(pcb.onAppConnect(), pcb: pcb)
        armPoll()
    }

    func shutdown() {
        pollTask?.cancel()
        pollTask = nil
        pollTarget = nil
        let flows = Array(pcbs.keys)
        for flow in flows {
            guard let pcb = pcbs[flow] else { continue }
            commit(pcb.onTimeout(.lifetime), pcb: pcb)
        }
        let waiters = sendWaiters
        sendWaiters.removeAll()
        for pending in waiters.values {
            for waiter in pending { waiter.resume() }
        }
    }

    private struct OutboundPacket {
        var data: Data
        var family: UInt8
        var flow: FlowKey
        var isPureAck: Bool
    }

    private struct ActionEffects {
        var outbound: [OutboundPacket] = []
        var established: [FlowKey] = []
        var delivered: [(FlowKey, Data)] = []
        var closed: [FlowKey] = []
    }

    /// Keep the last pure ACK per flow in a batch; data/SYN/FIN/RST stay in order.
    private static func coalescePureAcks(_ items: [OutboundPacket]) -> [OutboundPacket] {
        var lastAckIndex: [FlowKey: Int] = [:]
        for (i, item) in items.enumerated() where item.isPureAck {
            lastAckIndex[item.flow] = i
        }
        guard !lastAckIndex.isEmpty else { return items }
        return items.enumerated().compactMap { i, item in
            if item.isPureAck, lastAckIndex[item.flow] != i { return nil }
            return item
        }
    }

    private func process(segment: TCPSegment, data: Data, now: ContinuousClock.Instant) -> ActionEffects {
        let payload = Self.payloadView(data, offset: segment.payloadOffset, length: segment.payloadLength)
        let key = segment.flow
        let pcb: TCPControlBlock
        if let existing = pcbs[key] {
            pcb = existing
        } else if segment.hasSYN && !segment.hasRST {
            guard pcbs.count < config.maxConnections else {
                return rstForUnknown(segment: segment, payloadLength: payload.count)
            }
            let created = makePCB(flow: key)
            pcbs[key] = created
            pcb = created
        } else if !segment.hasRST {
            return rstForUnknown(segment: segment, payloadLength: payload.count)
        } else {
            return ActionEffects()
        }
        return apply(pcb.onSegment(segment, payload: payload, now: now), pcb: pcb)
    }

    /// Zero-copy payload slice: wraps the original `Data`'s bytes (the bench
    /// generator produces malloc/pooled `Data`, so this must NOT memcpy — the
    /// returned `Data` retains the backing storage via its deallocator).
    private static func payloadView(_ data: Data, offset: Int, length: Int) -> Data {
        guard length > 0, offset >= 0, offset + length <= data.count else { return Data() }
        return PacketBuffer(wrapping: data).retainedPayload(offset: offset, length: length)
    }

    /// RFC 793: a segment that matches no TCB elicits RST (except RST itself).
    private func rstForUnknown(segment: TCPSegment, payloadLength: Int) -> ActionEffects {
        let extra = (segment.hasSYN ? 1 : 0) + (segment.hasFIN ? 1 : 0)
        let segLen = UInt32(payloadLength) &+ UInt32(extra)
        let flags: TCPFlags
        let seq: UInt32
        let ack: UInt32
        if segment.hasACK {
            flags = .rst
            seq = segment.ack
            ack = 0
        } else {
            flags = .rst.union(.ack)
            seq = 0
            ack = segment.seq &+ segLen
        }
        let tx = PacketBuilder.tcp(
            flow: segment.flow.reversed,
            seq: seq,
            ack: ack,
            flags: flags,
            window: 0,
            pool: txPool
        )
        var result = ActionEffects()
        result.outbound.append(
            OutboundPacket(
                data: tx.asSharedData(),
                family: AddressFamily.of(segment.flow.src.version),
                flow: segment.flow,
                isPureAck: false
            )
        )
        return result
    }

    private func apply(_ actions: [TCPAction], pcb: TCPControlBlock) -> ActionEffects {
        var result = ActionEffects()
        for action in actions {
            switch action {
            case .send(let flags, let seq, let ack, let window, let payload, let options):
                let tx = PacketBuilder.tcp(
                    flow: pcb.flow.reversed,
                    seq: seq,
                    ack: ack,
                    flags: flags,
                    window: pcb.advertisedWindow,
                    options: options,
                    payload: payload,
                    pool: txPool
                )
                let pureAck = flags.contains(.ack)
                    && !flags.contains(.syn)
                    && !flags.contains(.fin)
                    && !flags.contains(.rst)
                    && payload.isEmpty
                result.outbound.append(
                    OutboundPacket(
                        data: tx.asSharedData(),
                        family: AddressFamily.of(pcb.flow.src.version),
                        flow: pcb.flow,
                        isPureAck: pureAck
                    )
                )
            case .sendFromBuffer(let flags, let seq, let ack, let window, let offset, let length, let options):
                guard let ring = pcb.sendBuffer else { break }
                let tx = PacketBuilder.tcp(
                    flow: pcb.flow.reversed,
                    seq: seq,
                    ack: ack,
                    flags: flags,
                    window: pcb.advertisedWindow,
                    options: options,
                    payloadFrom: ring,
                    offset: offset,
                    count: length,
                    pool: txPool
                )
                result.outbound.append(
                    OutboundPacket(
                        data: tx.asSharedData(),
                        family: AddressFamily.of(pcb.flow.src.version),
                        flow: pcb.flow,
                        isPureAck: false
                    )
                )
            case .deliver(let data):
                result.delivered.append((pcb.flow, data))
                if !streams.consumesOnData {
                    pcb.appBuffered += data.count
                    pcb.updateRcvWnd()
                }
            case .established:
                result.established.append(pcb.flow)
            case .closed:
                pcb.deadlines.clearAll()
                pcbs.removeValue(forKey: pcb.flow)
                resumeSendWaiters(pcb.flow)
                recycle(pcb)
                result.closed.append(pcb.flow)
            case .reset:
                break
            case .schedule, .cancel:
                break
            }
        }
        return result
    }

    private func commit(_ actions: [TCPAction], pcb: TCPControlBlock) {
        let result = apply(actions, pcb: pcb)
        emit(
            outbound: result.outbound,
            established: result.established,
            delivered: result.delivered,
            closed: result.closed
        )
    }

    /// `PacketSink` / `TCPStreamHandler` are synchronous so a batch stays on this
    /// loop. Actor sinks (NW forwarder) hop internally without blocking ingest.
    private func emit(
        outbound: [OutboundPacket],
        established: [FlowKey],
        delivered: [(FlowKey, Data)],
        closed: [FlowKey]
    ) {
        if !outbound.isEmpty {
            sink.writeBatch(outbound.map { ($0.data, $0.family) })
        }
        for flow in established { streams.onEstablished(flow: flow) }
        for item in delivered { streams.onData(flow: item.0, data: item.1) }
        for flow in closed { streams.onClosed(flow: flow) }
    }

    /// Fire every PCB deadline `<= now`. One pass over this EventLoop's table.
    private func tick(now: ContinuousClock.Instant) {
        var due: [(FlowKey, TCPTimerKind)] = []
        for pcb in pcbs.values {
            for kind in pcb.deadlines.expired(now: now) {
                due.append((pcb.flow, kind))
            }
        }
        for (flow, kind) in due {
            guard let pcb = pcbs[flow] else { continue }
            pcb.deadlines.clear(kind)
            commit(pcb.onTimeout(kind, now: now), pcb: pcb)
        }
    }

    /// Single sleeper for the loop: sleep until the earliest PCB deadline (smoltcp `poll_delay`).
    /// The task is only (re)built when the earliest deadline moves earlier; otherwise
    /// churning `pollTask` every batch dominated small-batch TX (create+cancel per send).
    private func armPoll() {
        let now = ContinuousClock().now
        guard let earliest = pcbs.values.compactMap({ $0.deadlines.earliest }).min() else {
            pollTask?.cancel()
            pollTask = nil
            pollTarget = nil
            return
        }
        if pollTask != nil, let target = pollTarget, target <= earliest {
            return
        }
        pollTask?.cancel()
        pollTarget = earliest
        var delay = now.duration(to: earliest)
        if delay < .zero { delay = .zero }
        if delay == .zero { delay = .milliseconds(1) }
        pollTask = Task {
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            self.onPollWake()
        }
    }

    private func onPollWake() {
        pollTask = nil
        pollTarget = nil
        tick(now: ContinuousClock().now)
        armPoll()
    }

    private func makePCB(flow: FlowKey) -> TCPControlBlock {
        if let pcb = pcbPool.popLast() {
            pcb.resetForReuse(
                flow: flow,
                iss: UInt32.random(in: 1...UInt32.max / 2),
                window: config.receiveWindow,
                algorithm: config.algorithm,
                timerConfig: config.timers,
                tfo: config.tfo,
                maxMss: config.maxMss
            )
            return pcb
        }
        let created = TCPControlBlock(
            flow: flow,
            state: .listen,
            window: config.receiveWindow,
            algorithm: config.algorithm,
            timerConfig: config.timers,
            maxMss: config.maxMss
        )
        created.tfoEnabled = config.tfo
        return created
    }

    private func recycle(_ pcb: TCPControlBlock) {
        guard pcbPool.count < pcbPoolLimit else { return }
        pcb.prepareForPool()
        pcbPool.append(pcb)
    }

    private func waitForSendSpace(_ flow: FlowKey) async {
        await withCheckedContinuation { continuation in
            sendWaiters[flow, default: []].append(continuation)
        }
    }

    private func resumeSendWaiters(_ flow: FlowKey) {
        let waiters = sendWaiters.removeValue(forKey: flow) ?? []
        for waiter in waiters { waiter.resume() }
    }

    private func resumeSendWaitersIfNeeded(_ flow: FlowKey) {
        if pcbs[flow] == nil || (pcbs[flow]?.sendAvailable ?? 0) > 0 {
            resumeSendWaiters(flow)
        }
    }
}
