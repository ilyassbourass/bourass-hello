import Foundation
import Compression

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public class FastDNSTunnel: ObservableObject {
    @Published public var isConnected = false
    @Published public var statusMessage = "Disconnected"
    @Published public var assignedIP = ""
    @Published public var sessionID = ""
    @Published public var bytesSent: Int64 = 0
    @Published public var bytesReceived: Int64 = 0

    public var serverIP: String = "105.73.34.105" // Operator resolver 105.73.34.105 or ns3 213.160.77.162
    public var serverPort: UInt16 = 53
    public var zone: String = "dns3.marocdns.uk"
    public var subId: String = FastDNSCrypto.defaultSubId
    public var installId: String = FastDNSCrypto.defaultInstallId

    private var subKey: Data = Data()
    private var hsKey: Data = Data()
    private var sessionKey: Data?
    
    private var sockfd: Int32 = -1
    private let socketLock = NSLock()
    private var pollThread: Thread?
    private var isRunning = false

    private var uplinkSeq: UInt16 = UInt16.random(in: 1...1000)
    private var pollSeq: UInt32 = 0

    // Registry for active TCP streams: (localPort, remotePort, remoteIP) -> VirtualTCPStream
    private var tcpStreams: [String: VirtualTCPStream] = [:]
    private let streamLock = NSLock()

    // DNS resolution callback registry: txId -> (Semaphore, IP String)
    private var dnsWaiters: [UInt16: (DispatchSemaphore, String?)] = [:]
    private let dnsLock = NSLock()

    public init() {}

    public func connect() {
        guard !isConnected else { return }
        statusMessage = "Deriving cryptographic keys..."

        subKey = FastDNSCrypto.deriveSubKey(subId: subId)
        hsKey = FastDNSCrypto.deriveHandshakeKey(subKey: subKey, installId: installId)

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.performConnect()
        }
    }

    public func disconnect() {
        isRunning = false
        socketLock.lock()
        if sockfd >= 0 {
            close(sockfd)
            sockfd = -1
        }
        socketLock.unlock()

        DispatchQueue.main.async {
            self.isConnected = false
            self.statusMessage = "Disconnected"
        }
    }

    private func performConnect() {
        let targets = [serverIP, "105.73.34.105", "213.160.77.162"].filter { !$0.isEmpty }
        var uniqueTargets: [String] = []
        for t in targets {
            if !uniqueTargets.contains(t) {
                uniqueTargets.append(t)
            }
        }

        var activeFd: Int32 = -1
        var connectedIP = ""

        for target in uniqueTargets {
            DispatchQueue.main.async {
                self.statusMessage = "Connecting to \(target):\(self.serverPort)..."
            }

            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else { continue }

            var tv = timeval(tv_sec: 5, tv_usec: 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = serverPort.bigEndian
            inet_pton(AF_INET, target, &addr.sin_addr)

            let connectRes = withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    Darwin.connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }

            if connectRes == 0 {
                activeFd = fd
                connectedIP = target
                break
            } else {
                close(fd)
            }
        }

        guard activeFd >= 0 else {
            DispatchQueue.main.async { self.statusMessage = "TCP Connection failed" }
            return
        }

        self.sockfd = activeFd
        self.serverIP = connectedIP

        // 1. Build Handshake DNS Query
        DispatchQueue.main.async { self.statusMessage = "Sending Handshake..." }
        let certPart1 = String(FastDNSCrypto.certHex.prefix(32))
        let certPart2 = String(FastDNSCrypto.certHex.suffix(32))
        let qname = "0-handshake-batch-lz4.\(subId).\(installId).0.110.\(certPart1).\(certPart2).\(zone)."
        
        guard let dnsReq = buildDNSQuery(qname: qname, qtype: 10) else {
            close(fd)
            DispatchQueue.main.async { self.statusMessage = "Failed to build DNS query" }
            return
        }

        var reqLen = UInt16(dnsReq.count).bigEndian
        var msgData = Data(bytes: &reqLen, count: 2)
        msgData.append(dnsReq)

        guard sendAll(fd: fd, data: msgData) else {
            close(fd)
            DispatchQueue.main.async { self.statusMessage = "Handshake send failed" }
            return
        }

        // 2. Read Handshake Response
        guard let respLenData = recvExact(fd: fd, count: 2) else {
            close(fd)
            DispatchQueue.main.async { self.statusMessage = "No handshake response" }
            return
        }
        let respLen = Int(respLenData.withUnsafeBytes { $0.load(as: UInt16.self).bigEndian })
        guard let respData = recvExact(fd: fd, count: respLen) else {
            close(fd)
            DispatchQueue.main.async { self.statusMessage = "Handshake response truncated" }
            return
        }

        guard let rdata = extractNULLRecord(dnsData: respData), rdata.count > 29, rdata[0] == 0xF1 else {
            close(fd)
            DispatchQueue.main.async { self.statusMessage = "Invalid handshake payload" }
            return
        }

        let iv = rdata.subdata(in: 1..<13)
        let ctTag = rdata.subdata(in: 13..<rdata.count)

        do {
            let plain = try FastDNSCrypto.aesGCMDecrypt(key: hsKey, iv: iv, ciphertextAndTag: ctTag)
            guard let json = try JSONSerialization.jsonObject(with: plain) as? [String: Any],
                  let sid = json["sid"] as? String,
                  let ip = json["ip"] as? String else {
                throw FastDNSCryptoError.decryptionFailed
            }

            self.sessionID = sid
            self.assignedIP = ip
            self.sessionKey = FastDNSCrypto.deriveSessionKey(subKey: subKey, installId: installId, sid: sid)

            DispatchQueue.main.async {
                self.isConnected = true
                self.statusMessage = "Tunnel Active (\(ip))"
            }

            self.isRunning = true
            self.pollThread = Thread(target: self, selector: #selector(pollLoop), object: nil)
            self.pollThread?.start()

        } catch {
            close(fd)
            DispatchQueue.main.async { self.statusMessage = "Handshake decryption failed" }
        }
    }

    private func sendAll(fd: Int32, data: Data) -> Bool {
        return data.withUnsafeBytes { ptr -> Bool in
            guard let base = ptr.baseAddress else { return false }
            var sent = 0
            while sent < data.count {
                let s = send(fd, base.advanced(by: sent), data.count - sent, 0)
                if s <= 0 { return false }
                sent += s
            }
            return true
        }
    }

    private func recvExact(fd: Int32, count: Int) -> Data? {
        var data = Data(count: count)
        let success = data.withUnsafeMutableBytes { ptr -> Bool in
            guard let base = ptr.baseAddress else { return false }
            var recvd = 0
            while recvd < count {
                let r = recv(fd, base.advanced(by: recvd), count - recvd, 0)
                if r <= 0 { return false }
                recvd += r
            }
            return true
        }
        return success ? data : nil
    }

    public func sendBatch(batchBytes: Data) {
        socketLock.lock()
        defer { socketLock.unlock() }
        guard sockfd >= 0, let sKey = sessionKey else { return }

        uplinkSeq = (uplinkSeq &+ 1)
        guard let compressed = compressLZ4(data: batchBytes) else { return }

        let chunkSize = 80
        let totalChunks = UInt8((compressed.count + chunkSize - 1) / chunkSize)

        for idx in 0..<Int(totalChunks) {
            let start = idx * chunkSize
            let end = min(start + chunkSize, compressed.count)
            let chunkSlice = compressed.subdata(in: start..<end)

            var iv = Data(count: 12)
            _ = iv.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 12, $0.baseAddress!) }

            guard let ctTag = try? FastDNSCrypto.aesGCMEncrypt(key: sKey, iv: iv, plaintext: chunkSlice) else { continue }
            var encChunk = Data([0xF1])
            encChunk.append(iv)
            encChunk.append(ctTag)

            var header = Data()
            var seqBE = uplinkSeq.bigEndian
            header.append(Data(bytes: &seqBE, count: 2))
            header.append(UInt8(idx))
            header.append(totalChunks)
            header.append(encChunk)

            let b32 = FastDNSCrypto.base32Encode(header)
            var labels: [String] = []
            var strIndex = b32.startIndex
            while strIndex < b32.endIndex {
                let nextIndex = b32.index(strIndex, offsetBy: 60, limitedBy: b32.endIndex) ?? b32.endIndex
                labels.append(String(b32[strIndex..<nextIndex]))
                strIndex = nextIndex
            }

            let qname = "0-\(labels.joined(separator: ".")).s\(sessionID).\(zone)."
            guard let dnsReq = buildDNSQuery(qname: qname, qtype: 10) else { continue }

            var reqLen = UInt16(dnsReq.count).bigEndian
            var msg = Data(bytes: &reqLen, count: 2)
            msg.append(dnsReq)

            if sendAll(fd: sockfd, data: msg) {
                if let ackLenData = recvExact(fd: sockfd, count: 2) {
                    let ackLen = Int(ackLenData.withUnsafeBytes { $0.load(as: UInt16.self).bigEndian })
                    _ = recvExact(fd: sockfd, count: ackLen)
                }
                DispatchQueue.main.async {
                    self.bytesSent += Int64(batchBytes.count)
                }
            }
        }
    }

    @objc private func pollLoop() {
        while isRunning {
            usleep(120000) // 120ms poll interval

            socketLock.lock()
            guard sockfd >= 0, let sKey = sessionKey else {
                socketLock.unlock()
                break
            }

            pollSeq &+= 1
            let randVal = UInt32.random(in: 100000...999999)
            let qname = "0-poll.39928.\(pollSeq).\(randVal).s\(assignedIP).\(zone)."
            guard let dnsReq = buildDNSQuery(qname: qname, qtype: 10) else {
                socketLock.unlock()
                continue
            }

            var reqLen = UInt16(dnsReq.count).bigEndian
            var msg = Data(bytes: &reqLen, count: 2)
            msg.append(dnsReq)

            guard sendAll(fd: sockfd, data: msg),
                  let respLenData = recvExact(fd: sockfd, count: 2) else {
                socketLock.unlock()
                break
            }

            let respLen = Int(respLenData.withUnsafeBytes { $0.load(as: UInt16.self).bigEndian })
            guard let respData = recvExact(fd: sockfd, count: respLen) else {
                socketLock.unlock()
                break
            }
            socketLock.unlock()

            if let rdata = extractNULLRecord(dnsData: respData),
               rdata.count > 29, rdata[0] == 0xF1 {
                let iv = rdata.subdata(in: 1..<13)
                let ctTag = rdata.subdata(in: 13..<rdata.count)
                if let plain = try? FastDNSCrypto.aesGCMDecrypt(key: sKey, iv: iv, ciphertextAndTag: ctTag),
                   let decomp = decompressLZ4(data: plain) {
                    handleDownlinkData(decomp)
                }
            }
        }
    }

    private func handleDownlinkData(_ data: Data) {
        var pos = 0
        while pos + 2 <= data.count {
            let plen = Int(data.subdata(in: pos..<pos+2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian })
            pos += 2
            if pos + plen <= data.count {
                let rawIP = data.subdata(in: pos..<pos+plen)
                dispatchIPPacket(rawIP)
                pos += plen
                DispatchQueue.main.async {
                    self.bytesReceived += Int64(plen)
                }
            }
        }
    }

    private func dispatchIPPacket(_ rawIP: Data) {
        guard rawIP.count >= 20 else { return }
        let proto = rawIP[9]

        if proto == 6 { // TCP
            guard rawIP.count >= 40 else { return }
            let ihl = Int(rawIP[0] & 0x0F) * 4
            let srcIP = "\(rawIP[12]).\(rawIP[13]).\(rawIP[14]).\(rawIP[15])"
            let srcPort = rawIP.subdata(in: ihl..<ihl+2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }
            let dstPort = rawIP.subdata(in: ihl+2..<ihl+4).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }

            let streamKey = "\(dstPort):\(srcPort):\(srcIP)"
            streamLock.lock()
            let stream = tcpStreams[streamKey]
            streamLock.unlock()

            stream?.onPacket(rawIP: rawIP, ihl: ihl)

        } else if proto == 17 { // UDP (DNS response)
            guard rawIP.count >= 28 else { return }
            let ihl = Int(rawIP[0] & 0x0F) * 4
            let dnsPayload = rawIP.subdata(in: ihl+8..<rawIP.count)
            guard dnsPayload.count >= 12 else { return }
            let txId = dnsPayload.subdata(in: 0..<2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }

            dnsLock.lock()
            if let (sem, _) = dnsWaiters[txId] {
                // Parse DNS A record
                let resolved = parseDNSARecord(dnsPayload: dnsPayload)
                dnsWaiters[txId] = (sem, resolved)
                sem.signal()
            }
            dnsLock.unlock()
        }
    }

    public func resolveDomain(_ domain: String, timeout: Double = 5.0) -> String? {
        let txId = UInt16.random(in: 1000...65000)
        let sem = DispatchSemaphore(value: 0)
        dnsLock.lock()
        dnsWaiters[txId] = (sem, nil)
        dnsLock.unlock()

        guard let dnsReq = buildStandardDNSQuery(domain: domain, txId: txId) else { return nil }
        guard let myIPBytes = parseIPv4(assignedIP) else { return nil }

        // Build IP/UDP/DNS packet to 8.8.8.8:53
        let srcPort = UInt16.random(in: 50000...60000)
        var udp = Data()
        var sPortBE = srcPort.bigEndian; udp.append(Data(bytes: &sPortBE, count: 2))
        var dPortBE = UInt16(53).bigEndian; udp.append(Data(bytes: &dPortBE, count: 2))
        var uLenBE = UInt16(8 + dnsReq.count).bigEndian; udp.append(Data(bytes: &uLenBE, count: 2))
        var zeroChecksum = UInt16(0); udp.append(Data(bytes: &zeroChecksum, count: 2))
        udp.append(dnsReq)

        var ip = Data([0x45, 0x00])
        var totalLenBE = UInt16(20 + udp.count).bigEndian; ip.append(Data(bytes: &totalLenBE, count: 2))
        var idBE = UInt16.random(in: 1...65535).bigEndian; ip.append(Data(bytes: &idBE, count: 2))
        ip.append(Data([0x40, 0x00, 0x40, 17, 0x00, 0x00]))
        ip.append(myIPBytes)
        ip.append(Data([8, 8, 8, 8]))
        // Calculate IP checksum
        let chk = calculateChecksum(ip)
        ip[10] = UInt8(chk >> 8)
        ip[11] = UInt8(chk & 0xFF)
        ip.append(udp)

        var batch = Data()
        var pktLenBE = UInt16(ip.count).bigEndian
        batch.append(Data(bytes: &pktLenBE, count: 2))
        batch.append(ip)

        sendBatch(batchBytes: batch)

        _ = sem.wait(timeout: .now() + timeout)

        dnsLock.lock()
        let result = dnsWaiters.removeValue(forKey: txId)?.1
        dnsLock.unlock()
        return result
    }

    public func registerStream(_ stream: VirtualTCPStream) {
        streamLock.lock()
        tcpStreams[stream.key] = stream
        streamLock.unlock()
    }

    public func unregisterStream(_ stream: VirtualTCPStream) {
        streamLock.lock()
        tcpStreams.removeValue(forKey: stream.key)
        streamLock.unlock()
    }

    // MARK: - Compression
    private func compressLZ4(data: Data) -> Data? {
        let outCap = data.count + 512
        var output = Data(count: outCap)
        let inCount = data.count
        let count = output.withUnsafeMutableBytes { outBuf in
            data.withUnsafeBytes { inBuf in
                compression_encode_buffer(
                    outBuf.bindMemory(to: UInt8.self).baseAddress!,
                    outCap,
                    inBuf.bindMemory(to: UInt8.self).baseAddress!,
                    inCount,
                    nil,
                    COMPRESSION_LZ4
                )
            }
        }
        guard count > 0 else { return nil }
        output.count = count
        return output
    }

    private func decompressLZ4(data: Data) -> Data? {
        let maxOutputSize = 65536
        var output = Data(count: maxOutputSize)
        let inCount = data.count
        let count = output.withUnsafeMutableBytes { outBuf in
            data.withUnsafeBytes { inBuf in
                compression_decode_buffer(
                    outBuf.bindMemory(to: UInt8.self).baseAddress!,
                    maxOutputSize,
                    inBuf.bindMemory(to: UInt8.self).baseAddress!,
                    inCount,
                    nil,
                    COMPRESSION_LZ4
                )
            }
        }
        guard count > 0 else { return nil }
        output.count = count
        return output
    }

    // MARK: - DNS Helpers
    private func buildDNSQuery(qname: String, qtype: UInt16) -> Data? {
        var data = Data()
        var txId = UInt16.random(in: 1...65535).bigEndian; data.append(Data(bytes: &txId, count: 2))
        var flags = UInt16(0x0100).bigEndian; data.append(Data(bytes: &flags, count: 2)) // RD=1
        var qdcount = UInt16(1).bigEndian; data.append(Data(bytes: &qdcount, count: 2))
        var ancount = UInt16(0).bigEndian; data.append(Data(bytes: &ancount, count: 2))
        var nscount = UInt16(0).bigEndian; data.append(Data(bytes: &nscount, count: 2))
        var arcount = UInt16(0).bigEndian; data.append(Data(bytes: &arcount, count: 2))

        let labels = qname.trimmingCharacters(in: CharacterSet(charactersIn: ".")).split(separator: ".")
        for label in labels {
            guard let ldata = label.data(using: .ascii), ldata.count <= 63 else { return nil }
            data.append(UInt8(ldata.count))
            data.append(ldata)
        }
        data.append(0x00) // Root label

        var qt = qtype.bigEndian; data.append(Data(bytes: &qt, count: 2))
        var qc = UInt16(1).bigEndian; data.append(Data(bytes: &qc, count: 2)) // IN class
        return data
    }

    private func buildStandardDNSQuery(domain: String, txId: UInt16) -> Data? {
        var data = Data()
        var tId = txId.bigEndian; data.append(Data(bytes: &tId, count: 2))
        var flags = UInt16(0x0100).bigEndian; data.append(Data(bytes: &flags, count: 2))
        var qdcount = UInt16(1).bigEndian; data.append(Data(bytes: &qdcount, count: 2))
        var zero = UInt16(0); data.append(Data(bytes: &zero, count: 2))
        data.append(Data(bytes: &zero, count: 2))
        data.append(Data(bytes: &zero, count: 2))

        for label in domain.split(separator: ".") {
            guard let ldata = label.data(using: .ascii) else { return nil }
            data.append(UInt8(ldata.count))
            data.append(ldata)
        }
        data.append(0x00)
        var qt = UInt16(1).bigEndian; data.append(Data(bytes: &qt, count: 2)) // A
        var qc = UInt16(1).bigEndian; data.append(Data(bytes: &qc, count: 2)) // IN
        return data
    }

    private func extractNULLRecord(dnsData: Data) -> Data? {
        guard dnsData.count > 12 else { return nil }
        var pos = 12
        // Skip Question section
        while pos < dnsData.count {
            let len = Int(dnsData[pos])
            if len == 0 { pos += 1; break }
            if (len & 0xC0) == 0xC0 { pos += 2; break }
            pos += 1 + len
        }
        pos += 4 // QTYPE + QCLASS
        guard pos + 10 <= dnsData.count else { return nil }

        // Answer Section: Name (pointer or labels)
        if (dnsData[pos] & 0xC0) == 0xC0 { pos += 2 }
        else {
            while pos < dnsData.count && dnsData[pos] != 0 { pos += 1 + Int(dnsData[pos]) }
            pos += 1
        }
        guard pos + 10 <= dnsData.count else { return nil }
        let rtype = dnsData.subdata(in: pos..<pos+2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }
        pos += 8 // TYPE(2) + CLASS(2) + TTL(4)
        let rdlength = Int(dnsData.subdata(in: pos..<pos+2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian })
        pos += 2
        guard pos + rdlength <= dnsData.count else { return nil }
        return rtype == 10 ? dnsData.subdata(in: pos..<pos+rdlength) : nil
    }

    private func parseDNSARecord(dnsPayload: Data) -> String? {
        guard dnsPayload.count > 12 else { return nil }
        var pos = 12
        while pos < dnsPayload.count {
            let len = Int(dnsPayload[pos])
            if len == 0 { pos += 1; break }
            if (len & 0xC0) == 0xC0 { pos += 2; break }
            pos += 1 + len
        }
        pos += 4 // Skip QTYPE + QCLASS
        while pos < dnsPayload.count {
            if (dnsPayload[pos] & 0xC0) == 0xC0 { pos += 2 }
            else {
                while pos < dnsPayload.count && dnsPayload[pos] != 0 { pos += 1 + Int(dnsPayload[pos]) }
                pos += 1
            }
            guard pos + 10 <= dnsPayload.count else { return nil }
            let rtype = dnsPayload.subdata(in: pos..<pos+2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }
            pos += 8
            let rdlen = Int(dnsPayload.subdata(in: pos..<pos+2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian })
            pos += 2
            if rtype == 1 && rdlen == 4 && pos + 4 <= dnsPayload.count {
                let ip = "\(dnsPayload[pos]).\(dnsPayload[pos+1]).\(dnsPayload[pos+2]).\(dnsPayload[pos+3])"
                return ip
            }
            pos += rdlen
        }
        return nil
    }

    private func parseIPv4(_ ipStr: String) -> Data? {
        var addr = in_addr()
        guard inet_pton(AF_INET, ipStr, &addr) == 1 else { return nil }
        var data = Data(count: 4)
        data.withUnsafeMutableBytes { $0.storeBytes(of: addr.s_addr, as: UInt32.self) }
        return data
    }

    private func calculateChecksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i < data.count - 1 {
            let word = UInt32(data[i]) << 8 | UInt32(data[i+1])
            sum += word
            i += 2
        }
        if i < data.count {
            sum += UInt32(data[i]) << 8
        }
        while (sum >> 16) > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return UInt16(~sum & 0xFFFF)
    }
}

// MARK: - Virtual TCP Stream Class
public class VirtualTCPStream {
    public let tunnel: FastDNSTunnel
    public let targetIP: String
    public let targetPort: UInt16
    public let localPort: UInt16
    public let key: String

    private var clientSeq: UInt32 = UInt32.random(in: 10000...1000000)
    private var serverSeq: UInt32 = 0
    private let connSem = DispatchSemaphore(value: 0)
    private var isClosed = false

    public var onDataReceived: ((Data) -> Void)?
    public var onClosed: (() -> Void)?

    public init(tunnel: FastDNSTunnel, targetIP: String, targetPort: UInt16) {
        self.tunnel = tunnel
        self.targetIP = targetIP
        self.targetPort = targetPort
        self.localPort = UInt16.random(in: 30000...60000)
        self.key = "\(localPort):\(targetPort):\(targetIP)"
        self.tunnel.registerStream(self)
    }

    public func connect(timeout: Double = 6.0) -> Bool {
        // Send SYN
        sendTCPPacket(flags: 0x02, payload: Data()) // SYN
        let res = connSem.wait(timeout: .now() + timeout)
        guard res == .success else {
            close()
            return false
        }
        // Send ACK
        clientSeq &+= 1
        sendTCPPacket(flags: 0x10, payload: Data()) // ACK
        return true
    }

    public func sendData(_ data: Data) {
        guard !isClosed else { return }
        sendTCPPacket(flags: 0x18, payload: data) // PSH + ACK
        clientSeq &+= UInt32(data.count)
    }

    public func onPacket(rawIP: Data, ihl: Int) {
        let tcpHeader = rawIP.subdata(in: ihl..<ihl+20)
        let seq = tcpHeader.subdata(in: 4..<8).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        let flags = tcpHeader[13]
        let dataOffset = Int((tcpHeader[12] >> 4) & 0x0F) * 4
        let payload = rawIP.subdata(in: ihl+dataOffset..<rawIP.count)

        if (flags & 0x12) == 0x12 { // SYN+ACK
            serverSeq = seq &+ 1
            connSem.signal()
        } else if (flags & 0x10) != 0 { // ACK / PSH-ACK
            if payload.count > 0 && !isClosed {
                serverSeq = seq &+ UInt32(payload.count)
                sendTCPPacket(flags: 0x10, payload: Data()) // ACK
                onDataReceived?(payload)
            }
        }
        if (flags & 0x01) != 0 { // FIN
            serverSeq = seq &+ 1
            sendTCPPacket(flags: 0x11, payload: Data()) // FIN-ACK
            close()
        } else if (flags & 0x04) != 0 { // RST
            close()
        }
    }

    private func sendTCPPacket(flags: UInt8, payload: Data) {
        guard let myIPBytes = parseIPv4(tunnel.assignedIP),
              let dstIPBytes = parseIPv4(targetIP) else { return }

        var tcp = Data()
        var sPortBE = localPort.bigEndian; tcp.append(Data(bytes: &sPortBE, count: 2))
        var dPortBE = targetPort.bigEndian; tcp.append(Data(bytes: &dPortBE, count: 2))
        var seqBE = clientSeq.bigEndian; tcp.append(Data(bytes: &seqBE, count: 4))
        var ackBE = serverSeq.bigEndian; tcp.append(Data(bytes: &ackBE, count: 4))
        tcp.append(Data([0x50, flags])) // Data offset (5 words = 20B) + Flags
        var winBE = UInt16(65535).bigEndian; tcp.append(Data(bytes: &winBE, count: 2))
        var zero = UInt16(0); tcp.append(Data(bytes: &zero, count: 2)) // Checksum
        tcp.append(Data(bytes: &zero, count: 2)) // Urgent
        tcp.append(payload)

        // TCP Checksum with pseudo-header
        var pseudo = Data()
        pseudo.append(myIPBytes)
        pseudo.append(dstIPBytes)
        pseudo.append(Data([0x00, 6]))
        var tcpLenBE = UInt16(tcp.count).bigEndian
        pseudo.append(Data(bytes: &tcpLenBE, count: 2))
        pseudo.append(tcp)
        let tcpChk = calculateChecksum(pseudo)
        tcp[16] = UInt8(tcpChk >> 8)
        tcp[17] = UInt8(tcpChk & 0xFF)

        // IPv4 Header
        var ip = Data([0x45, 0x00])
        var totalLenBE = UInt16(20 + tcp.count).bigEndian; ip.append(Data(bytes: &totalLenBE, count: 2))
        var idBE = UInt16.random(in: 1...65535).bigEndian; ip.append(Data(bytes: &idBE, count: 2))
        ip.append(Data([0x40, 0x00, 0x40, 6, 0x00, 0x00]))
        ip.append(myIPBytes)
        ip.append(dstIPBytes)
        let ipChk = calculateChecksum(ip)
        ip[10] = UInt8(ipChk >> 8)
        ip[11] = UInt8(ipChk & 0xFF)
        ip.append(tcp)

        var batch = Data()
        var pktLenBE = UInt16(ip.count).bigEndian
        batch.append(Data(bytes: &pktLenBE, count: 2))
        batch.append(ip)

        tunnel.sendBatch(batchBytes: batch)
    }

    public func close() {
        if !isClosed {
            isClosed = true
            tunnel.unregisterStream(self)
            onClosed?()
        }
    }

    private func parseIPv4(_ ipStr: String) -> Data? {
        var addr = in_addr()
        guard inet_pton(AF_INET, ipStr, &addr) == 1 else { return nil }
        var data = Data(count: 4)
        data.withUnsafeMutableBytes { $0.storeBytes(of: addr.s_addr, as: UInt32.self) }
        return data
    }

    private func calculateChecksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i < data.count - 1 {
            let word = UInt32(data[i]) << 8 | UInt32(data[i+1])
            sum += word
            i += 2
        }
        if i < data.count {
            sum += UInt32(data[i]) << 8
        }
        while (sum >> 16) > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return UInt16(~sum & 0xFFFF)
    }
}
