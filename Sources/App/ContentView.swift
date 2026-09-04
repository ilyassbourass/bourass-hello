import SwiftUI
import WebKit
import Network

struct ContentView: View {
    @StateObject private var tunnel = FastDNSTunnel()
    @State private var proxy: FastDNSProxyServer?
    @State private var selectedTab = 0
    @State private var useCarrierResolver = true
    @State private var urlString = "https://www.google.com"
    @State private var currentURL = URL(string: "https://www.google.com")!
    @State private var triggerReload = false

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color(red: 0.04, green: 0.05, blue: 0.12), Color(red: 0.08, green: 0.10, blue: 0.22)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(spacing: 0) {
                // Top Tab Selector
                HStack(spacing: 12) {
                    TabButton(title: "⚡ Tunnel", isSelected: selectedTab == 0) {
                        withAnimation(.spring(response: 0.3)) { selectedTab = 0 }
                    }
                    TabButton(title: "🌐 Browser", isSelected: selectedTab == 1) {
                        withAnimation(.spring(response: 0.3)) { selectedTab = 1 }
                    }
                }
                .padding(.horizontal, 24)
                .padding(.top, 12)
                .padding(.bottom, 16)

                if selectedTab == 0 {
                    TunnelDashboardView(tunnel: tunnel, useCarrierResolver: $useCarrierResolver)
                        .transition(.opacity)
                } else {
                    BrowserContainerView(
                        urlString: $urlString,
                        currentURL: $currentURL,
                        triggerReload: $triggerReload,
                        tunnel: tunnel
                    )
                    .transition(.opacity)
                }

                Spacer(minLength: 8)

                // Signature Footer
                VStack(spacing: 2) {
                    Text("BOURASS")
                        .font(.system(size: 15, weight: .heavy, design: .rounded))
                        .tracking(8)
                        .foregroundStyle(
                            LinearGradient(
                                colors: [Color(red: 1.0, green: 0.84, blue: 0.35), Color(red: 1.0, green: 0.6, blue: 0.1)],
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                    Text("FastDNS Carrier Bypass • inwi 0 DH")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(.white.opacity(0.4))
                }
                .padding(Edge.Set.bottom, 12)
            }
        }
        .onAppear {
            let p = FastDNSProxyServer(tunnel: tunnel)
            self.proxy = p
        }
        .onChange(of: tunnel.isConnected) { _, connected in
            if connected {
                proxy?.start()
            } else {
                proxy?.stop()
            }
        }
    }
}

// MARK: - Tab Button Component
struct TabButton: View {
    let title: String
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 15, weight: .bold, design: .rounded))
                .foregroundColor(isSelected ? .black : .white.opacity(0.7))
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(
                    isSelected
                        ? AnyView(LinearGradient(colors: [.white, Color(red: 1.0, green: 0.85, blue: 0.4)], startPoint: .leading, endPoint: .trailing))
                        : AnyView(Color.white.opacity(0.08))
                )
                .cornerRadius(12)
        }
    }
}

// MARK: - Tunnel Dashboard
struct TunnelDashboardView: View {
    @ObservedObject var tunnel: FastDNSTunnel
    @Binding var useCarrierResolver: Bool

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Status Header Card
                VStack(spacing: 12) {
                    HStack {
                        Circle()
                            .fill(tunnel.isConnected ? Color.green : Color.orange)
                            .frame(width: 12, height: 12)
                            .shadow(color: tunnel.isConnected ? Color.green.opacity(0.8) : Color.orange.opacity(0.5), radius: 6)

                        Text(tunnel.isConnected ? "TUNNEL ACTIVE" : "DISCONNECTED")
                            .font(.system(size: 13, weight: .bold, design: .monospaced))
                            .foregroundColor(.white)

                        Spacer()

                        Text(tunnel.assignedIP.isEmpty ? "0.0.0.0" : tunnel.assignedIP)
                            .font(.system(size: 13, weight: .bold, design: .monospaced))
                            .foregroundColor(Color(red: 1.0, green: 0.85, blue: 0.4))
                    }

                    Text(tunnel.statusMessage)
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(.white.opacity(0.7))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(18)
                .background(Color.white.opacity(0.06))
                .cornerRadius(16)
                .padding(.horizontal, 20)

                // Metrics Grid
                HStack(spacing: 12) {
                    MetricCard(title: "Uplink", value: formatBytes(tunnel.bytesSent), icon: "arrow.up.circle.fill", color: .cyan)
                    MetricCard(title: "Downlink", value: formatBytes(tunnel.bytesReceived), icon: "arrow.down.circle.fill", color: .green)
                }
                .padding(.horizontal, 20)

                // Configuration / Info Card
                VStack(spacing: 14) {
                    Toggle(isOn: $useCarrierResolver) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Direct inwi Resolver")
                                .font(.system(size: 15, weight: .semibold))
                                .foregroundColor(.white)
                            Text("105.73.34.105:53 (Bypass carrier data block)")
                                .font(.system(size: 12))
                                .foregroundColor(.white.opacity(0.5))
                        }
                    }
                    .tint(Color(red: 1.0, green: 0.85, blue: 0.4))
                    .onChange(of: useCarrierResolver) { _, enabled in
                        tunnel.serverIP = enabled ? "105.73.34.105" : "213.160.77.162"
                    }

                    Divider().background(Color.white.opacity(0.1))

                    InfoRow(label: "DNS Server", value: tunnel.serverIP + ":53")
                    InfoRow(label: "Zone", value: tunnel.zone)
                    InfoRow(label: "Local SOCKS5", value: "127.0.0.1:1080")
                    if !tunnel.sessionID.isEmpty {
                        InfoRow(label: "Session ID", value: String(tunnel.sessionID.prefix(12)) + "...")
                    }
                }
                .padding(18)
                .background(Color.white.opacity(0.06))
                .cornerRadius(16)
                .padding(.horizontal, 20)

                // Connect / Disconnect Action Button
                Button(action: {
                    let impact = UIImpactFeedbackGenerator(style: .medium)
                    impact.impactOccurred()
                    if tunnel.isConnected {
                        tunnel.disconnect()
                    } else {
                        tunnel.connect()
                    }
                }) {
                    HStack(spacing: 10) {
                        Image(systemName: tunnel.isConnected ? "stop.fill" : "bolt.fill")
                        Text(tunnel.isConnected ? "Disconnect Tunnel" : "Connect FastDNS")
                    }
                    .font(.system(size: 17, weight: .bold, design: .rounded))
                    .foregroundColor(tunnel.isConnected ? .white : .black)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 16)
                    .background(
                        tunnel.isConnected
                            ? AnyView(Color.red.opacity(0.85))
                            : AnyView(LinearGradient(colors: [.white, Color(red: 1.0, green: 0.85, blue: 0.4)], startPoint: .leading, endPoint: .trailing))
                    )
                    .cornerRadius(16)
                    .shadow(color: tunnel.isConnected ? Color.red.opacity(0.3) : Color(red: 1.0, green: 0.85, blue: 0.4).opacity(0.3), radius: 10)
                }
                .padding(.horizontal, 24)
                .padding(.top, 6)
            }
            .padding(.top, 4)
        }
    }

    private func formatBytes(_ bytes: Int64) -> String {
        if bytes < 1024 { return "\(bytes) B" }
        if bytes < 1024 * 1024 { return String(format: "%.1f KB", Double(bytes) / 1024.0) }
        return String(format: "%.2f MB", Double(bytes) / (1024.0 * 1024.0))
    }
}

// MARK: - Metric Card
struct MetricCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(color)
                    .font(.system(size: 18))
                Spacer()
                Text(title)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(.white.opacity(0.6))
            }
            Text(value)
                .font(.system(size: 20, weight: .bold, design: .monospaced))
                .foregroundColor(.white)
        }
        .padding(16)
        .frame(maxWidth: .infinity)
        .background(Color.white.opacity(0.06))
        .cornerRadius(14)
    }
}

// MARK: - Info Row
struct InfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .font(.system(size: 13))
                .foregroundColor(.white.opacity(0.6))
            Spacer()
            Text(value)
                .font(.system(size: 13, weight: .medium, design: .monospaced))
                .foregroundColor(.white)
        }
    }
}

// MARK: - In-App Browser Container
struct BrowserContainerView: View {
    @Binding var urlString: String
    @Binding var currentURL: URL
    @Binding var triggerReload: Bool
    @ObservedObject var tunnel: FastDNSTunnel

    var body: some View {
        VStack(spacing: 8) {
            // URL Bar
            HStack(spacing: 8) {
                HStack {
                    Image(systemName: "lock.shield.fill")
                        .foregroundColor(tunnel.isConnected ? .green : .gray)
                        .font(.system(size: 12))
                    TextField("Enter URL or search...", text: $urlString)
                        .font(.system(size: 14))
                        .foregroundColor(.white)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        .onSubmit {
                            loadCurrentURL()
                        }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color.white.opacity(0.10))
                .cornerRadius(10)

                Button(action: {
                    triggerReload = true
                }) {
                    Image(systemName: "arrow.clockwise")
                        .foregroundColor(.white)
                        .padding(8)
                        .background(Color.white.opacity(0.10))
                        .cornerRadius(8)
                }
            }
            .padding(.horizontal, 16)

            // Quick Shortcuts
            HStack(spacing: 8) {
                QuickNavButton(title: "Google") { navigate(to: "https://www.google.com") }
                QuickNavButton(title: "Wikipedia") { navigate(to: "https://www.wikipedia.org") }
                QuickNavButton(title: "DuckDuckGo") { navigate(to: "https://duckduckgo.com") }
                QuickNavButton(title: "ipify") { navigate(to: "https://api.ipify.org") }
            }
            .padding(.horizontal, 16)

            // WebView
            ProxyWebView(url: currentURL, triggerReload: $triggerReload)
                .cornerRadius(12)
                .padding(.horizontal, 12)
                .overlay(
                    Group {
                        if !tunnel.isConnected {
                            ZStack {
                                Color.black.opacity(0.85)
                                VStack(spacing: 12) {
                                    Image(systemName: "antenna.radiowaves.left.and.right.slash")
                                        .font(.system(size: 38))
                                        .foregroundColor(Color(red: 1.0, green: 0.85, blue: 0.4))
                                    Text("Tunnel Disconnected")
                                        .font(.headline)
                                        .foregroundColor(.white)
                                    Text("Connect FastDNS to browse at 0 DH balance.")
                                        .font(.caption)
                                        .foregroundColor(.white.opacity(0.7))
                                }
                            }
                            .cornerRadius(12)
                            .padding(.horizontal, 12)
                        }
                    }
                )
        }
    }

    private func loadCurrentURL() {
        var text = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        if !text.hasPrefix("http://") && !text.hasPrefix("https://") {
            if text.contains(".") && !text.contains(" ") {
                text = "https://" + text
            } else {
                text = "https://www.google.com/search?q=" + (text.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? text)
            }
        }
        if let target = URL(string: text) {
            currentURL = target
            urlString = text
        }
    }

    private func navigate(to target: String) {
        urlString = target
        loadCurrentURL()
    }
}

// MARK: - Quick Navigation Pill
struct QuickNavButton: View {
    let title: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(.white.opacity(0.8))
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(Color.white.opacity(0.08))
                .cornerRadius(6)
        }
    }
}

// MARK: - WKWebView with Proxy configuration
struct ProxyWebView: UIViewRepresentable {
    let url: URL
    @Binding var triggerReload: Bool

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        if #available(iOS 17.0, *) {
            let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: 1080)
            let proxyConfig = ProxyConfiguration(socksv5Proxy: endpoint)
            config.websiteDataStore.proxyConfigurations = [proxyConfig]
        }
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.load(URLRequest(url: url))
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        if triggerReload {
            uiView.reload()
            DispatchQueue.main.async {
                triggerReload = false
            }
        } else if let cur = uiView.url?.absoluteString, cur != url.absoluteString, !url.absoluteString.isEmpty {
            uiView.load(URLRequest(url: url))
        }
    }
}

#Preview {
    ContentView()
}
