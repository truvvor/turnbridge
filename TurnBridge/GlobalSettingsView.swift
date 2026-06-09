import SwiftUI

struct GlobalSettingsView: View {
    @AppStorage("excludeAPNs") private var excludeAPNs = false
    @AppStorage("excludeCellularServices") private var excludeCellularServices = false
    @AppStorage("excludeLocalNetworks") private var excludeLocalNetworks = true

    @State private var captchaMode: CaptchaMode = ManualCaptchaSetting.mode
    @State private var captchaQuota: Int = ManualCaptchaSetting.quota
    @State private var remoteCaptchaURL: String = RemoteCaptchaSetting.url
    @State private var remoteCaptchaAPIKey: String = RemoteCaptchaSetting.apiKey

    var body: some View {
        Form {
            Section(header: Text("Captcha"),
                    footer: Text(captchaModeFooter)) {
                Picker("Solve mode", selection: $captchaMode) {
                    Text("Auto only").tag(CaptchaMode.off)
                    Text("Manual fallback").tag(CaptchaMode.fallback)
                    Text("Manual always").tag(CaptchaMode.forced)
                }
                .onChange(of: captchaMode) { newValue in
                    ManualCaptchaSetting.mode = newValue
                }

                NavigationLink(destination: CapturedCaptchasView()) {
                    Label(
                        title: { Text("Captured Captchas") },
                        icon: { Image(systemName: "tray.full").foregroundColor(.secondary) }
                    )
                }
            }

            Section(header: Text("Captcha quota"),
                    footer: Text(captchaQuotaFooter)) {
                Stepper(value: $captchaQuota,
                        in: ManualCaptchaSetting.quotaRange,
                        step: 1) {
                    HStack {
                        Text("Solve on device")
                        Spacer()
                        Text("\(captchaQuota)")
                            .foregroundColor(.secondary)
                    }
                }
                .onChange(of: captchaQuota) { newValue in
                    ManualCaptchaSetting.quota = newValue
                }
            }

            Section(header: Text("Remote captcha service")) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Offload captcha solving to a server after the first 5 sessions are up. Each configured backend contributes one extra per-IP rate-limit budget.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                TextField("Server URL (https://…)", text: $remoteCaptchaURL)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .onSubmit { RemoteCaptchaSetting.url = remoteCaptchaURL }
                    .onChange(of: remoteCaptchaURL) { newValue in
                        RemoteCaptchaSetting.url = newValue
                    }
                SecureField("API key", text: $remoteCaptchaAPIKey)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .onSubmit { RemoteCaptchaSetting.apiKey = remoteCaptchaAPIKey }
                    .onChange(of: remoteCaptchaAPIKey) { newValue in
                        RemoteCaptchaSetting.apiKey = newValue
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

    private var captchaQuotaFooter: String {
        switch captchaQuota {
        case 0:
            return "Never solve on this device. Every captcha goes straight to the remote captcha-service. Requires a working remote URL + key above; without it, sessions fall back to recycled identities."
        case 1:
            return "Solve only the first captcha on this device (needed to bring up the first WG session); every subsequent challenge offloads to the remote captcha-service. Recommended — VK rate-limits success_token per source IP for ~1 minute after each solve."
        default:
            return "Solve up to \(captchaQuota) captchas on this device before offloading to the remote captcha-service. Higher values let more bootstrap identities use your mobile IP but expose you to back-to-back prompts on the same IP."
        }
    }

    private var captchaModeFooter: String {
        switch captchaMode {
        case .off:
            return "Run the on-device solver and the remote /cred cluster. When both fail, recycle a previously-acquired identity. Zero browser prompts."
        case .fallback:
            return "Try the on-device solver and the remote /cred cluster first. Only when both fail does iOS open a Safari sheet for you to solve. Realistically ~15-20% of identities at N=60 will fall through."
        case .forced:
            return "Bypass the auto solver entirely — every captcha opens a Safari sheet for you to solve. Disables the kill switch (includeAllNetworks) so the page can load while the tunnel comes up. Brutal at N=60."
        }
    }
}
