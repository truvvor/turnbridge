import SwiftUI

struct SettingsView: View {
    @ObservedObject var store: ProfileStore
    var profileID: UUID
    var isNewProfile: Bool = false

    @Environment(\.dismiss) private var dismiss
    @State private var draft: VPNProfile?
    @State private var showDeleteConfirmation = false

    private var profile: VPNProfile {
        draft ?? store.profiles.first(where: { $0.id == profileID }) ?? VPNProfile()
    }

    var body: some View {
        Form {
            Section(header: Text("Profile")) {
                TextField("Profile Name", text: binding(\.name))
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
            }

            Section(header: Text("Proxy Settings"),
                    footer: Text("One VK call-join URL per line. Multiple links round-robin across sessions — gives more captcha-rate-limit budget if VK keys it on (source-IP, link).")) {
                TextEditor(text: binding(\.vkLink))
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                    .frame(minHeight: 60)

                TextField("Peer Address (IP:Port)", text: binding(\.peerAddr))
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                TextField("Listen Address (IP:Port)", text: binding(\.listenAddr))
                    .autocapitalization(.none)
                    .disableAutocorrection(true)

                // Connections: TextField for direct numeric entry +
                // Stepper for ±1 nudges. Range expanded from the
                // previous 1...16 cap to 1...100 because VK rate-
                // limits per TURN allocation, so throughput scales
                // ~linearly with N; the parallel captcha solver
                // keeps startup latency tolerable even at 100.
                // Clamped binding rejects out-of-range values so a
                // typo like 9999 silently saves as 100.
                HStack {
                    Text("Connections (n)")
                    Spacer()
                    TextField("", value: clampedNValue(min: 1, max: 100),
                              format: .number)
                        .keyboardType(.numberPad)
                        .multilineTextAlignment(.trailing)
                        .frame(width: 60)
                    Stepper("", value: clampedNValue(min: 1, max: 100),
                            in: 1...100)
                        .labelsHidden()
                }

                // Stream Aggregation: ports the 17-byte
                // [sessionID, streamID] handshake from
                // kiper292/wireguard-turn-android. Lets a compatible
                // server-side aggregator (kiper292/vk-turn-proxy fork
                // deployed alongside the WG server) fuse the N
                // parallel TURN allocations into a single stable
                // endpoint for WireGuard.
                //
                // REQUIRES the matching server. If toggled on without
                // a compatible aggregator, the 17-byte preamble lands
                // in the WG packet stream and breaks the very first
                // handshake. Default off.
                Toggle("Stream Aggregation", isOn: binding(\.streamAggregation))
                Text("Requires kiper292/vk-turn-proxy on the WG server. Leave off if you don't run a compatible aggregator.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Section(header: Text("WireGuard Config")) {
                TextEditor(text: binding(\.wgQuickConfig))
                    .font(.system(.footnote, design: .monospaced))
                    .frame(minHeight: 150)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
            }

            Section {
                Button(role: .destructive, action: {
                    showDeleteConfirmation = true
                }) {
                    HStack {
                        Spacer()
                        Text("Delete Profile")
                        Spacer()
                    }
                }
            }
        }
        .navigationTitle(isNewProfile ? "New Profile" : "Settings")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button(action: { dismiss() }) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.title2)
                        .foregroundColor(.primary)
                }
            }
        }
        .onAppear {
            if draft == nil {
                draft = store.profiles.first(where: { $0.id == profileID })
            }
        }
        .alert("Delete Profile?", isPresented: $showDeleteConfirmation) {
            Button("Delete", role: .destructive) {
                store.deleteProfile(profileID)
                dismiss()
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("Profile \"\(profile.name)\" will be permanently deleted.")
        }
        .onDisappear {
            guard let draft else { return }
            if store.profiles.contains(where: { $0.id == profileID }) {
                store.selectedProfile = draft
            }
        }
    }

    private func binding<T>(_ keyPath: WritableKeyPath<VPNProfile, T>) -> Binding<T> {
        Binding(
            get: { profile[keyPath: keyPath] },
            set: { newValue in
                if draft == nil {
                    draft = store.profiles.first(where: { $0.id == profileID })
                }
                draft?[keyPath: keyPath] = newValue
            }
        )
    }

    /// `binding(\.nValue)` with a setter that clamps to [min, max].
    /// SwiftUI invokes the setter on every keystroke for a TextField
    /// with `.number` format, so a partial entry like "1" while the
    /// user is typing "10" gets clamped to 1 (still valid) and the
    /// follow-up "10" overwrites it as expected. The clamp only
    /// matters at commit time when the user enters something out
    /// of range.
    private func clampedNValue(min lo: Int, max hi: Int) -> Binding<Int> {
        let base = binding(\.nValue)
        return Binding(
            get: { base.wrappedValue },
            set: { newValue in
                if newValue < lo {
                    base.wrappedValue = lo
                } else if newValue > hi {
                    base.wrappedValue = hi
                } else {
                    base.wrappedValue = newValue
                }
            }
        )
    }
}
