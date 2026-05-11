import Foundation
import NetworkExtension
import UIKit

@MainActor
final class CaptchaManager: ObservableObject {

    static let shared = CaptchaManager()

    @Published var pending: CaptchaIPC.PendingRequest?

    private var registered = false

    private init() {}

    func start() {
        guard !registered else { return }
        registered = true

        // Darwin notification fired from the extension.
        let name = CaptchaIPC.requestDarwinNotification as CFString
        let observer = Unmanaged.passUnretained(self).toOpaque()
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            observer,
            { _, observer, _, _, _ in
                guard let observer = observer else { return }
                let mgr = Unmanaged<CaptchaManager>.fromOpaque(observer).takeUnretainedValue()
                Task { @MainActor in mgr.refresh() }
            },
            name,
            nil,
            .deliverImmediately
        )

        // Also refresh on becoming active in case the notification arrived while
        // the app was suspended.
        NotificationCenter.default.addObserver(
            forName: UIApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }

        refresh()
    }

    func refresh() {
        guard let defaults = UserDefaults(suiteName: CaptchaIPC.appGroupID),
              let data = defaults.data(forKey: CaptchaIPC.requestUserDefaultsKey),
              let req  = try? JSONDecoder().decode(CaptchaIPC.PendingRequest.self, from: data) else {
            pending = nil
            return
        }
        // Drop stale requests (5 minutes).
        if Date().timeIntervalSince1970 - req.createdAt > 300 {
            clearPending()
            return
        }
        if pending?.requestId != req.requestId {
            SharedLogger.info("Captcha UI: picked up pending request \(req.requestId)", source: .app)
        }
        pending = req
    }

    func submit(token: String) async {
        guard let req = pending else { return }
        await sendMessage(.init(type: "captcha_answer",
                                requestId: req.requestId,
                                successToken: token,
                                reason: nil))
        clearPending()
    }

    func cancel(reason: String = "user cancelled") async {
        guard let req = pending else { return }
        await sendMessage(.init(type: "captcha_cancel",
                                requestId: req.requestId,
                                successToken: nil,
                                reason: reason))
        clearPending()
    }

    // MARK: - Private

    private func clearPending() {
        UserDefaults(suiteName: CaptchaIPC.appGroupID)?
            .removeObject(forKey: CaptchaIPC.requestUserDefaultsKey)
        pending = nil
    }

    private func sendMessage(_ msg: CaptchaIPC.AppMessage) async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            guard let session = managers.first?.connection as? NETunnelProviderSession else {
                SharedLogger.warning("Captcha UI: no active tunnel session to deliver answer", source: .app)
                return
            }
            let payload = try JSONEncoder().encode(msg)
            try session.sendProviderMessage(payload) { reply in
                if let reply = reply, let text = String(data: reply, encoding: .utf8) {
                    SharedLogger.debug("Captcha UI: extension reply \(text)", source: .app)
                }
            }
        } catch {
            SharedLogger.error("Captcha UI: failed to deliver answer: \(error.localizedDescription)", source: .app)
        }
    }
}
