import Foundation
import NetworkExtension
import UIKit
import Combine
import WebKit

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

        // Cancel notification fired from the extension when the tunnel
        // stops: the pending prompt is unanswerable, drop it so the
        // sheet dismisses instead of trapping the user on a dead page.
        let cancelName = CaptchaIPC.cancelDarwinNotification as CFString
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            observer,
            { _, observer, _, _, _ in
                guard let observer = observer else { return }
                let mgr = Unmanaged<CaptchaManager>.fromOpaque(observer).takeUnretainedValue()
                Task { @MainActor in mgr.refresh() }
            },
            cancelName,
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
            guard let self = self else { return }
            Task { @MainActor in self.refresh() }
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

    /// WebView extracted just the success_token (legacy or fallback
    /// when the in-WebView retry failed). The extension will do the
    /// VK API retry itself — VK may reject because of session
    /// mismatch.
    ///
    /// clearPending() runs BEFORE sendMessage so the sheet dismisses
    /// the instant the WebView reports a result, even if the IPC
    /// (NETunnelProviderSession.sendProviderMessage) is slow or
    /// hangs for some reason. We've observed sheets getting stuck
    /// on "Got response, finishing…" when the IPC took its time;
    /// users had no way out except kill the app.
    func submit(token: String) async {
        guard let req = pending else { return }
        let (cookiesJson, userAgent) = await harvestVKBrowserState()
        let msg = CaptchaIPC.AppMessage(type: "captcha_answer",
                                        requestId: req.requestId,
                                        successToken: token,
                                        reason: nil,
                                        responseJson: nil,
                                        cookiesJson: cookiesJson,
                                        userAgent: userAgent)
        clearPending()
        await sendMessage(msg)
    }

    /// WebView solved the captcha AND replayed the failing VK API
    /// call in the same browser session. This is what we want: VK
    /// sees a single coherent session for both the solve and the
    /// redemption, no fingerprint switch.
    func submit(response: String) async {
        guard let req = pending else { return }
        let (cookiesJson, userAgent) = await harvestVKBrowserState()
        let msg = CaptchaIPC.AppMessage(type: "captcha_answer",
                                        requestId: req.requestId,
                                        successToken: nil,
                                        reason: nil,
                                        responseJson: response,
                                        cookiesJson: cookiesJson,
                                        userAgent: userAgent)
        clearPending()
        await sendMessage(msg)
    }

    func cancel(reason: String = "user cancelled") async {
        guard let req = pending else { return }
        let msg = CaptchaIPC.AppMessage(type: "captcha_cancel",
                                        requestId: req.requestId,
                                        successToken: nil,
                                        reason: reason,
                                        responseJson: nil,
                                        cookiesJson: nil,
                                        userAgent: nil)
        clearPending()
        await sendMessage(msg)
    }

    /// Pull the VK cookies + Safari UA out of the WebView's data store
    /// so the extension can forward them to Go and on to the remote
    /// captcha-service. The store is the SAME default store
    /// CaptchaWKWebView uses (config.websiteDataStore = .default()), so
    /// by the time submit fires every cookie set during the solve is
    /// present here. Filters to *.vk.com / *.vk.ru / *.vk.id — those
    /// are the only domains the server cares about and forwarding
    /// non-VK cookies would leak unrelated session state. Returns
    /// (nil, nil) on a clean failure path so the call still ships the
    /// solve result; the server can fall back to cookie-less solving.
    private func harvestVKBrowserState() async -> (String?, String) {
        let userAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
        let store = WKWebsiteDataStore.default().httpCookieStore
        let cookies: [HTTPCookie] = await withCheckedContinuation { cont in
            store.getAllCookies { cs in cont.resume(returning: cs) }
        }
        let vkCookies = cookies.filter {
            let d = $0.domain.lowercased()
            return d.hasSuffix(".vk.com") || d == "vk.com"
                || d.hasSuffix(".vk.ru")  || d == "vk.ru"
                || d.hasSuffix(".vk.id")  || d == "vk.id"
        }.map { c in
            return [
                "name":   c.name,
                "value":  c.value,
                "domain": c.domain,
                "path":   c.path,
            ]
        }
        guard !vkCookies.isEmpty,
              let data = try? JSONSerialization.data(withJSONObject: vkCookies),
              let json = String(data: data, encoding: .utf8) else {
            SharedLogger.debug("Captcha UI: no VK cookies harvested for /cred", source: .app)
            return (nil, userAgent)
        }
        SharedLogger.info("Captcha UI: harvested \(vkCookies.count) VK cookie(s) for /cred", source: .app)
        return (json, userAgent)
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
