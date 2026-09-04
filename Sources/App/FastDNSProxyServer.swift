import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public class FastDNSProxyServer: ObservableObject {
    public let tunnel: FastDNSTunnel
    @Published public var isRunning = false
    @Published public var activeConnections = 0
    @Published public var lastError: String = ""
    public let port: UInt16 = 1080

    private var listenFd: Int32 = -1
    private var serverThread: Thread?
    private var isTerminating = false

    // Thread-safe DNS Cache with common pre-populated domains
    private var dnsCache: [String: String] = [
        "www.google.com": "142.250.200.14",
        "google.com": "142.250.200.14",
        "duckduckgo.com": "52.142.124.215",
        "www.duckduckgo.com": "52.142.124.215",
        "wikipedia.org": "198.35.26.96",
        "www.wikipedia.org": "198.35.26.96",
        "api.ipify.org": "64.185.227.155"
    ]
    private let dnsCacheLock = NSLock()

    public init(tunnel: FastDNSTunnel) {
        self.tunnel = tunnel
    }

    public func start() {
        guard listenFd < 0 else { return }

        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            DispatchQueue.main.async { self.lastError = "Socket creation failed" }
            return
        }

        var opt: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, socklen_t(MemoryLayout<Int32>.size))
        #if canImport(Darwin)
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, socklen_t(MemoryLayout<Int32>.size))
        #endif

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)

        let bindRes = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.bind(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        guard bindRes == 0 else {
            close(fd)
            DispatchQueue.main.async { self.lastError = "Port 1080 bind failed" }
            return
        }

        guard Darwin.listen(fd, 32) == 0 else {
            close(fd)
            DispatchQueue.main.async { self.lastError = "Listen failed" }
            return
        }

        self.listenFd = fd
        self.isTerminating = false

        DispatchQueue.main.async {
            self.isRunning = true
            self.lastError = ""
        }

        serverThread = Thread { [weak self] in
            self?.acceptLoop(listenFd: fd)
        }
        serverThread?.name = "FastDNS-Proxy-Server"
        serverThread?.start()
    }

    public func stop() {
        isTerminating = true
        if listenFd >= 0 {
            close(listenFd)
            listenFd = -1
        }
        DispatchQueue.main.async {
            self.isRunning = false
            self.activeConnections = 0
        }
    }

    private func acceptLoop(listenFd: Int32) {
        while !isTerminating {
            var clientAddr = sockaddr_in()
            var clientLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let clientFd = withUnsafeMutablePointer(to: &clientAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    Darwin.accept(listenFd, sockPtr, &clientLen)
                }
            }

            guard clientFd >= 0 else {
                if isTerminating { break }
                usleep(10000)
                continue
            }

            var opt: Int32 = 1
            #if canImport(Darwin)
            setsockopt(clientFd, SOL_SOCKET, SO_NOSIGPIPE, &opt, socklen_t(MemoryLayout<Int32>.size))
            #endif
            var tv = timeval(tv_sec: 15, tv_usec: 0)
            setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(clientFd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.handleClient(clientFd: clientFd)
            }
        }
    }

    private func handleClient(clientFd: Int32) {
        DispatchQueue.main.async { self.activeConnections += 1 }
        defer {
            close(clientFd)
            DispatchQueue.main.async { self.activeConnections = max(0, self.activeConnections - 1) }
        }

        var buf = [UInt8](repeating: 0, count: 2048)
        let n = Darwin.recv(clientFd, &buf, buf.count, 0)
        guard n > 0 else { return }

        let initialData = Data(buf[0..<n])

        if initialData.count >= 2 && initialData[0] == 0x05 {
            // SOCKS5 Protocol
            handleSOCKS5(clientFd: clientFd, initial: initialData)
        } else if let header = String(data: initialData, encoding: .utf8), header.hasPrefix("CONNECT ") {
            // HTTP CONNECT Tunnel
            handleHTTPConnect(clientFd: clientFd, header: header)
        } else if let header = String(data: initialData, encoding: .utf8),
                  (header.hasPrefix("GET ") || header.hasPrefix("POST ") || header.hasPrefix("HEAD ")) {
            // Standard HTTP Proxy request
            handleHTTPDirect(clientFd: clientFd, header: header, initialData: initialData)
        }
    }

    // MARK: - SOCKS5 Handler
    private func handleSOCKS5(clientFd: Int32, initial: Data) {
        // Send Method Selection: Version 5, No Auth (0x00)
        let methodResp: [UInt8] = [0x05, 0x00]
        guard sendRaw(fd: clientFd, bytes: methodResp) else { return }

        // Read SOCKS5 Request
        var reqBuf = [UInt8](repeating: 0, count: 512)
        let rn = Darwin.recv(clientFd, &reqBuf, reqBuf.count, 0)
        guard rn >= 4, reqBuf[0] == 0x05, reqBuf[1] == 0x01 else { return } // CONNECT only

        let atyp = reqBuf[3]
        var targetIP: String?
        var portPos = 4

        if atyp == 0x01 && rn >= 10 { // IPv4
            targetIP = "\(reqBuf[4]).\(reqBuf[5]).\(reqBuf[6]).\(reqBuf[7])"
            portPos = 8
        } else if atyp == 0x03 { // Domain
            let dlen = Int(reqBuf[4])
            if rn >= 5 + dlen + 2 {
                let domainData = Data(reqBuf[5..<5+dlen])
                if let domain = String(data: domainData, encoding: .ascii) {
                    targetIP = resolveHost(domain)
                }
                portPos = 5 + dlen
            }
        }

        guard let ip = targetIP, rn >= portPos + 2 else {
            let failResp: [UInt8] = [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
            _ = sendRaw(fd: clientFd, bytes: failResp)
            return
        }

        let portBytes = Data(reqBuf[portPos..<portPos+2])
        let targetPort = portBytes.withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }

        let stream = VirtualTCPStream(tunnel: self.tunnel, targetIP: ip, targetPort: targetPort)
        guard stream.connect() else {
            let failResp: [UInt8] = [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
            _ = sendRaw(fd: clientFd, bytes: failResp)
            return
        }

        let successResp: [UInt8] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        guard sendRaw(fd: clientFd, bytes: successResp) else {
            stream.close()
            return
        }

        bridgeStream(clientFd: clientFd, stream: stream)
    }

    // MARK: - HTTP CONNECT Handler
    private func handleHTTPConnect(clientFd: Int32, header: String) {
        let lines = header.components(separatedBy: "\r\n")
        guard let firstLine = lines.first else { return }
        let parts = firstLine.split(separator: " ")
        guard parts.count >= 2 else { return }

        let hostPort = parts[1].split(separator: ":")
        let host = String(hostPort[0])
        let port: UInt16 = hostPort.count > 1 ? (UInt16(hostPort[1]) ?? 443) : 443

        guard let targetIP = resolveHost(host) else {
            let resp = "HTTP/1.1 502 Bad Gateway\r\n\r\n"
            _ = sendRaw(fd: clientFd, bytes: Array(resp.utf8))
            return
        }

        let stream = VirtualTCPStream(tunnel: self.tunnel, targetIP: targetIP, targetPort: port)
        guard stream.connect() else {
            let resp = "HTTP/1.1 504 Gateway Timeout\r\n\r\n"
            _ = sendRaw(fd: clientFd, bytes: Array(resp.utf8))
            return
        }

        let okResp = "HTTP/1.1 200 Connection Established\r\n\r\n"
        guard sendRaw(fd: clientFd, bytes: Array(okResp.utf8)) else {
            stream.close()
            return
        }

        bridgeStream(clientFd: clientFd, stream: stream)
    }

    // MARK: - Standard HTTP Direct Handler
    private func handleHTTPDirect(clientFd: Int32, header: String, initialData: Data) {
        var host = ""
        var port: UInt16 = 80
        for line in header.components(separatedBy: "\r\n") {
            if line.lowercased().hasPrefix("host:") {
                let parts = line.split(separator: ":")
                if parts.count >= 2 {
                    host = parts[1].trimmingCharacters(in: .whitespaces)
                    if parts.count >= 3 {
                        port = UInt16(parts[2].trimmingCharacters(in: .whitespaces)) ?? 80
                    }
                }
                break
            }
        }

        guard !host.isEmpty, let targetIP = resolveHost(host) else { return }

        let stream = VirtualTCPStream(tunnel: self.tunnel, targetIP: targetIP, targetPort: port)
        guard stream.connect() else { return }

        stream.sendData(initialData)
        bridgeStream(clientFd: clientFd, stream: stream)
    }

    // MARK: - Bidirectional Bridge
    private func bridgeStream(clientFd: Int32, stream: VirtualTCPStream) {
        let isDone = DispatchSemaphore(value: 0)
        var doneOnce = false
        let finish = {
            if !doneOnce {
                doneOnce = true
                stream.close()
                isDone.signal()
            }
        }

        stream.onDataReceived = { data in
            data.withUnsafeBytes { ptr in
                guard let base = ptr.baseAddress else { return }
                var sent = 0
                while sent < data.count {
                    let s = Darwin.send(clientFd, base.advanced(by: sent), data.count - sent, 0)
                    if s <= 0 { finish(); break }
                    sent += s
                }
            }
        }

        stream.onClosed = { finish() }

        // Reader loop from client socket into FastDNS stream
        DispatchQueue.global(qos: .userInitiated).async {
            var buf = [UInt8](repeating: 0, count: 4096)
            while !doneOnce {
                let n = Darwin.recv(clientFd, &buf, buf.count, 0)
                if n <= 0 {
                    finish()
                    break
                }
                stream.sendData(Data(buf[0..<n]))
            }
        }

        _ = isDone.wait(timeout: .now() + 60.0)
    }

    // MARK: - Host Resolver with Cache
    private func resolveHost(_ host: String) -> String? {
        var addr = in_addr()
        if inet_pton(AF_INET, host, &addr) == 1 {
            return host // Already IPv4
        }

        dnsCacheLock.lock()
        if let cached = dnsCache[host] {
            dnsCacheLock.unlock()
            return cached
        }
        dnsCacheLock.unlock()

        // Query over FastDNS tunnel
        if let resolved = self.tunnel.resolveDomain(host) {
            dnsCacheLock.lock()
            dnsCache[host] = resolved
            dnsCacheLock.unlock()
            return resolved
        }

        return nil
    }

    private func sendRaw(fd: Int32, bytes: [UInt8]) -> Bool {
        return bytes.withUnsafeBytes { ptr -> Bool in
            guard let base = ptr.baseAddress else { return false }
            var sent = 0
            while sent < bytes.count {
                let s = Darwin.send(fd, base.advanced(by: sent), bytes.count - sent, 0)
                if s <= 0 { return false }
                sent += s
            }
            return true
        }
    }
}
