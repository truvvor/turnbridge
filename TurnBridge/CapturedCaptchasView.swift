import SwiftUI

/// Browser for the captcha trap directory. The network extension drops
/// a folder per FAILED captcha solve into the App Group container
/// (<container>/captcha_trap/<timestamp>_<label>_<hex>/) with the raw
/// VK response JSON, the decoded image bytes, and a notes log.
///
/// Without this view those folders would only be accessible by digging
/// into the extension's sandbox, which iOS doesn't expose to the Files
/// app — so the user would have no way to actually look at unsolved
/// captchas. This screen lists every captured entry, lets the user
/// preview the image inline, and exports the whole folder via the
/// share sheet for offline analysis.
struct CapturedCaptchasView: View {
    @State private var entries: [Entry] = []
    @State private var selectedEntry: Entry?

    private static let appGroupID = "group.com.truvvor.turnbridge"

    struct Entry: Identifiable, Equatable {
        let id: URL
        let name: String
        let createdAt: Date
        let reason: String
        let imageURL: URL?
        let responseURL: URL?
        let notesURL: URL?
    }

    var body: some View {
        Group {
            if entries.isEmpty {
                ContentUnavailableView(
                    "No captured captchas yet",
                    systemImage: "tray",
                    description: Text("Failed slider solves drop their image and raw VK response here. If you've connected without seeing ERROR_LIMIT/slider failures, the trap stays empty.")
                )
            } else {
                List {
                    ForEach(entries) { entry in
                        Button(action: { selectedEntry = entry }) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(entry.name)
                                    .font(.system(.subheadline, design: .monospaced))
                                    .foregroundColor(.primary)
                                HStack {
                                    Text(entry.reason)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    Spacer()
                                    Text(entry.createdAt, style: .time)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                    }
                    .onDelete(perform: deleteEntries)
                }
            }
        }
        .navigationTitle("Captured Captchas")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button(action: refresh) {
                    Image(systemName: "arrow.clockwise")
                }
            }
        }
        .onAppear(perform: refresh)
        .sheet(item: $selectedEntry) { entry in
            NavigationStack {
                CapturedCaptchaDetail(entry: entry)
            }
        }
    }

    private func refresh() {
        guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: Self.appGroupID) else {
            entries = []
            return
        }
        let trapDir = container.appendingPathComponent("captcha_trap", isDirectory: true)
        guard let contents = try? FileManager.default.contentsOfDirectory(
            at: trapDir,
            includingPropertiesForKeys: [.creationDateKey],
            options: [.skipsHiddenFiles]
        ) else {
            entries = []
            return
        }

        entries = contents
            .filter { (try? $0.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true }
            .map { url -> Entry in
                let created = (try? url.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? Date.distantPast
                let imageURL = locateImage(in: url)
                let responseURL = url.appendingPathComponent("getContent_response.json")
                let notesURL = url.appendingPathComponent("notes.log")
                let reason = parseReason(notesURL: notesURL)
                return Entry(
                    id: url,
                    name: url.lastPathComponent,
                    createdAt: created,
                    reason: reason,
                    imageURL: FileManager.default.fileExists(atPath: imageURL?.path ?? "") ? imageURL : nil,
                    responseURL: FileManager.default.fileExists(atPath: responseURL.path) ? responseURL : nil,
                    notesURL: FileManager.default.fileExists(atPath: notesURL.path) ? notesURL : nil
                )
            }
            .sorted { $0.createdAt > $1.createdAt }
    }

    private func locateImage(in dir: URL) -> URL? {
        guard let contents = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else {
            return nil
        }
        return contents.first { url in
            let name = url.lastPathComponent.lowercased()
            return name.hasPrefix("image.")
        }
    }

    private func parseReason(notesURL: URL) -> String {
        guard let content = try? String(contentsOf: notesURL, encoding: .utf8) else {
            return "?"
        }
        for line in content.split(separator: "\n") {
            if line.hasPrefix("reason:") {
                return line
                    .dropFirst("reason:".count)
                    .trimmingCharacters(in: .whitespaces)
            }
        }
        return "?"
    }

    private func deleteEntries(at offsets: IndexSet) {
        for index in offsets {
            let entry = entries[index]
            try? FileManager.default.removeItem(at: entry.id)
        }
        refresh()
    }
}

private struct CapturedCaptchaDetail: View {
    let entry: CapturedCaptchasView.Entry
    @Environment(\.dismiss) private var dismiss
    @State private var showShareSheet = false

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                if let imageURL = entry.imageURL,
                   let data = try? Data(contentsOf: imageURL),
                   let image = UIImage(data: data) {
                    Image(uiImage: image)
                        .resizable()
                        .scaledToFit()
                        .frame(maxHeight: 280)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                } else {
                    Text("(no image in this entry — only the raw response)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                if let notesURL = entry.notesURL,
                   let notes = try? String(contentsOf: notesURL, encoding: .utf8) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("notes.log")
                            .font(.caption.bold())
                            .foregroundColor(.secondary)
                        Text(notes)
                            .font(.system(.caption, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                    }
                    .padding(10)
                    .background(Color.secondary.opacity(0.1))
                    .cornerRadius(8)
                }

                if let responseURL = entry.responseURL,
                   let response = try? String(contentsOf: responseURL, encoding: .utf8) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("getContent_response.json")
                            .font(.caption.bold())
                            .foregroundColor(.secondary)
                        Text(response.count > 4000 ? String(response.prefix(4000)) + "\n…(truncated)" : response)
                            .font(.system(.caption, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                    }
                    .padding(10)
                    .background(Color.secondary.opacity(0.1))
                    .cornerRadius(8)
                }
            }
            .padding()
        }
        .navigationTitle(entry.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button(action: { showShareSheet = true }) {
                    Image(systemName: "square.and.arrow.up")
                }
            }
            ToolbarItem(placement: .navigationBarLeading) {
                Button("Done") { dismiss() }
            }
        }
        .sheet(isPresented: $showShareSheet) {
            if let imageURL = entry.imageURL {
                ShareSheet(items: [imageURL])
            }
        }
    }
}

private struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
