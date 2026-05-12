import SwiftUI

struct GlobalSettingsView: View {
    @AppStorage("excludeAPNs") private var excludeAPNs = false
    @AppStorage("excludeCellularServices") private var excludeCellularServices = false
    @AppStorage("excludeLocalNetworks") private var excludeLocalNetworks = true

    @State private var manualCaptcha: Bool = ManualCaptchaSetting.isEnabled

    var body: some View {
        Form {
            Section(header: Text("Captcha")) {
                Toggle(isOn: $manualCaptcha) {
                    VStack(alignment: .leading) {
                        Text("Solve captcha manually")
                        Text("Show the VK challenge in a browser sheet instead of running the auto solver. Disables the kill switch (includeAllNetworks) for the session — required so the captcha page can load while the tunnel is still coming up.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                .onChange(of: manualCaptcha) { newValue in
                    ManualCaptchaSetting.isEnabled = newValue
                }
            }

            Section(header: Text("General")) {
                NavigationLink(destination: AboutView()) {
                    Label(
                        title: { Text("About") },
                        icon: { Image(systemName: "info.circle").foregroundColor(.secondary) }
                    )
                }
                
                NavigationLink(destination: LogView()) {
                    Label(
                        title: { Text("Logs") },
                        icon: { Image(systemName: "doc.text.magnifyingglass").foregroundColor(.secondary) }
                    )
                }
            }

            Section(header: Text("Routing")) {
                Toggle(isOn: $excludeLocalNetworks) {
                    VStack(alignment: .leading) {
                        Text("Allow LAN Access")
                        Text("Access local network devices without routing through VPN")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                Toggle(isOn: $excludeAPNs) {
                    VStack(alignment: .leading) {
                        Text("Bypass APNs")
                        Text("Send push notifications directly, bypassing the tunnel")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                Toggle(isOn: $excludeCellularServices) {
                    VStack(alignment: .leading) {
                        Text("Bypass Cellular")
                        Text("Exclude calls, SMS, and voicemail from the tunnel")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
    }
}
