import Foundation
import Network

public class FastDNSProxyServer: ObservableObject {
    public let tunnel: FastDNSTunnel
    private var listener: NWListener?
    @Published public var isRunning = false
    @Published public var activeConnections = 0
    public let port: UInt16 = 1080

    public init(tunnel: FastDNSTunnel) {
        self.tunnel = tunnel
    }

    public func start() {
        guard listener == nil else { return }
        do {
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            listener = try NWListener(using: params, on: NWEndpoint.Port(rawValue: port)!)
            listener?.newConnectionHandler = { [weak self] connection in
                self?.handleConnection(connection)
            }
            listener?.stateUpdateHandler = { [weak self] state in
                DispatchQueue.main.async {
                    switch state {
                    case .ready:
                        self?.isRunning = true
                    case .failed, .cancelled:
                        self?.isRunning = false
                    default:
                        break
                    }
                }
            }
            listener?.start(queue: DispatchQueue.global(qos: .userInitiated))
        } catch {
            print("Failed to start proxy listener: \(error)")
        }
    }

    public func stop() {
        listener?.cancel()
        listener = nil
        DispatchQueue.main.async {
            self.isRunning = false
        }
    }

    private func handleConnection(_ connection: NWConnection) {
        connection.start(queue: DispatchQueue.global(qos: .userInitiated))
        DispatchQueue.main.async { self.activeConnections += 1 }

        // Read initial greeting / handshake
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1024) { [weak self] data, _, _, error in
            guard let self = self, let data = data, error == nil else {
                connection.cancel()
                DispatchQueue.main.async { self?.activeConnections -= 1 }
                return
            }

            if data.count >= 2 && data[0] == 0x05 {
                // SOCKS5 Protocol
                self.handleSOCKS5(connection: connection, greeting: data)
            } else if let str = String(data: data, encoding: .utf8), str.hasPrefix("CONNECT ") {
                // HTTP CONNECT Tunnel
                self.handleHTTPConnect(connection: connection, header: str)
            } else {
                connection.cancel()
                DispatchQueue.main.async { self.activeConnections -= 1 }
            }
        }
    }

    // MARK: - SOCKS5 Handler
    private func handleSOCKS5(connection: NWConnection, greeting: Data) {
        // Send SOCKS5 Greeting response: version 5, no authentication
        connection.send(content: Data([0x05, 0x00]), completion: .contentProcessed { [weak self] error in
            guard let self = self, error == nil else {
                connection.cancel()
                DispatchQueue.main.async { self?.activeConnections -= 1 }
                return
            }

            // Receive SOCKS5 Request
            connection.receive(minimumIncompleteLength: 4, maximumLength: 512) { [weak self] reqData, _, _, reqErr in
                guard let self = self, let req = reqData, req.count >= 4, reqErr == nil else {
                    connection.cancel()
                    DispatchQueue.main.async { self?.activeConnections -= 1 }
                    return
                }

                let cmd = req[1]
                guard cmd == 0x01 else { // CONNECT only
                    connection.send(content: Data([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]), completion: .contentProcessed { _ in
                        connection.cancel()
                        DispatchQueue.main.async { self.activeConnections -= 1 }
                    })
                    return
                }

                let atyp = req[3]
                var targetIP: String?
                var portPos = 4

                if atyp == 0x01 && req.count >= 10 { // IPv4
                    targetIP = "\(req[4]).\(req[5]).\(req[6]).\(req[7])"
                    portPos = 8
                } else if atyp == 0x03 { // Domain
                    let dlen = Int(req[4])
                    if req.count >= 5 + dlen + 2 {
                        let domainData = req.subdata(in: 5..<5+dlen)
                        if let domain = String(data: domainData, encoding: .ascii) {
                            targetIP = self.tunnel.resolveDomain(domain)
                        }
                        portPos = 5 + dlen
                    }
                }

                guard let ip = targetIP, req.count >= portPos + 2 else {
                    connection.send(content: Data([0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]), completion: .contentProcessed { _ in
                        connection.cancel()
                        DispatchQueue.main.async { self.activeConnections -= 1 }
                    })
                    return
                }

                let targetPort = req.subdata(in: portPos..<portPos+2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }

                // Create virtual TCP stream over FastDNS tunnel
                let stream = VirtualTCPStream(tunnel: self.tunnel, targetIP: ip, targetPort: targetPort)
                if !stream.connect() {
                    connection.send(content: Data([0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]), completion: .contentProcessed { _ in
                        connection.cancel()
                        DispatchQueue.main.async { self.activeConnections -= 1 }
                    })
                    return
                }

                // SOCKS5 success
                connection.send(content: Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]), completion: .contentProcessed { error in
                    guard error == nil else {
                        stream.close()
                        connection.cancel()
                        DispatchQueue.main.async { self.activeConnections -= 1 }
                        return
                    }
                    self.bridge(connection: connection, stream: stream)
                })
            }
        })
    }

    // MARK: - HTTP CONNECT Handler
    private func handleHTTPConnect(connection: NWConnection, header: String) {
        // e.g. "CONNECT example.com:443 HTTP/1.1\r\n..."
        let lines = header.components(separatedBy: "\r\n")
        guard let firstLine = lines.first else {
            connection.cancel()
            DispatchQueue.main.async { self.activeConnections -= 1 }
            return
        }

        let parts = firstLine.split(separator: " ")
        guard parts.count >= 2 else {
            connection.cancel()
            DispatchQueue.main.async { self.activeConnections -= 1 }
            return
        }

        let hostPort = parts[1].split(separator: ":")
        let host = String(hostPort[0])
        let port: UInt16 = hostPort.count > 1 ? (UInt16(hostPort[1]) ?? 443) : 443

        guard let targetIP = self.tunnel.resolveDomain(host) else {
            let resp = "HTTP/1.1 502 Bad Gateway\r\n\r\n".data(using: .utf8)!
            connection.send(content: resp, completion: .contentProcessed { _ in
                connection.cancel()
                DispatchQueue.main.async { self.activeConnections -= 1 }
            })
            return
        }

        let stream = VirtualTCPStream(tunnel: self.tunnel, targetIP: targetIP, targetPort: port)
        if !stream.connect() {
            let resp = "HTTP/1.1 504 Gateway Timeout\r\n\r\n".data(using: .utf8)!
            connection.send(content: resp, completion: .contentProcessed { _ in
                connection.cancel()
                DispatchQueue.main.async { self.activeConnections -= 1 }
            })
            return
        }

        // HTTP 200 Connection Established
        let okResp = "HTTP/1.1 200 Connection Established\r\n\r\n".data(using: .utf8)!
        connection.send(content: okResp, completion: .contentProcessed { [weak self] error in
            guard let self = self, error == nil else {
                stream.close()
                connection.cancel()
                DispatchQueue.main.async { self?.activeConnections -= 1 }
                return
            }
            self.bridge(connection: connection, stream: stream)
        })
    }

    // MARK: - Bidirectional Relay
    private func bridge(connection: NWConnection, stream: VirtualTCPStream) {
        // From FastDNS tunnel to local client
        stream.onDataReceived = { data in
            connection.send(content: data, completion: .contentProcessed { _ in })
        }

        stream.onClosed = {
            connection.cancel()
            DispatchQueue.main.async { self.activeConnections = max(0, self.activeConnections - 1) }
        }

        // From local client to FastDNS tunnel
        func readLoop() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, isComplete, error in
                if let data = data, !data.isEmpty {
                    stream.sendData(data)
                }
                if isComplete || error != nil {
                    stream.close()
                    connection.cancel()
                    DispatchQueue.main.async { self.activeConnections = max(0, self.activeConnections - 1) }
                } else {
                    readLoop()
                }
            }
        }
        readLoop()
    }
}
