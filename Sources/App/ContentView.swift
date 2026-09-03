import SwiftUI

struct ContentView: View {
    @State private var tapped = false

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color(red: 0.05, green: 0.06, blue: 0.14), Color(red: 0.11, green: 0.12, blue: 0.28)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(spacing: 28) {
                Spacer()

                Text("👋")
                    .font(.system(size: 72))

                Text(tapped ? "Hello, Bourass!" : "Welcome")
                    .font(.system(size: 34, weight: .bold, design: .rounded))
                    .foregroundColor(.white)

                Text(tapped ? "Button tapped. Your first iPhone app works." : "Tap the button to say hello.")
                    .font(.body)
                    .foregroundColor(.white.opacity(0.7))
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)

                Button(action: {
                    withAnimation(.spring()) { tapped.toggle() }
                }) {
                    Text(tapped ? "Tapped ✓" : "Say Hello")
                        .font(.headline)
                        .foregroundColor(.black)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(
                            LinearGradient(colors: [.white, Color(red: 1.0, green: 0.85, blue: 0.4)], startPoint: .leading, endPoint: .trailing)
                        )
                        .cornerRadius(16)
                        .shadow(radius: 10)
                }
                .padding(.horizontal, 40)

                Spacer()

                Text("BOURASS")
                    .font(.system(size: 20, weight: .heavy, design: .rounded))
                    .tracking(8)
                    .foregroundStyle(
                        LinearGradient(colors: [Color(red: 1.0, green: 0.84, blue: 0.35), Color(red: 1.0, green: 0.6, blue: 0.1)], startPoint: .leading, endPoint: .trailing)
                    )
                    .padding(Edge.Set.bottom, 24)
            }
        }
    }
}

#Preview {
    ContentView()
}
