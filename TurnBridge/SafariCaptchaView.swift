import SwiftUI
import AuthenticationServices

// SafariCaptchaView / SafariCaptchaSolver — EXPERIMENTAL real-Safari
// captcha path. NOT wired into the build target by default (it is not
// referenced from project.pbxproj). Add it to the TurnBridge target
// and flip `ManualCaptchaSetting.useSafariEngine` to try it.
//
// WHY THIS EXISTS
// ---------------
// The primary manual path (CaptchaWebView) uses WKWebView. WKWebView is
// real WebKit on a real GPU, so its Canvas/WebGL/AudioContext
// fingerprints are close to Safari — but it is an *embedded* webview,
// and a determined fingerprinter still has tells (no `window.safari`,
// no ITP behaviour, app-scoped cookie policy, etc). ASWebAuthentication-
// Session runs the page in the SAME process Safari uses
// (com.apple.SafariViewService), with the SAME fingerprint and, when
// `prefersEphemeralWebBrowserSession == false`, the user's real Safari
// cookies. To VK it is essentially Safari. That is the strongest
// answer to "we keep getting flagged as a bot".
//
// THE HARD LIMITATION (read before relying on this)
// -------------------------------------------------
// ASWebAuthenticationSession (and SFSafariViewController) give you NO
// JavaScript injection and NO per-navigation callbacks. You cannot hook
// fetch/XHR to grab `success_token`, and you cannot do the in-session
// `getAnonymousToken` replay that CaptchaWebView does. The ONLY thing
// the system hands back is the final URL whose scheme matches
// `callbackURLScheme`.
//
// So this path only captures the token if VK's captcha flow ENDS by
// redirecting to a URL we can recognise. There are two ways to make
// that true; both need a one-time setup outside this file:
//   1. Register a `redirect_uri` with the VK captcha request that
//      points at an https URL / Universal Link you control, have that
//      endpoint 302 to `turnbridge://captcha?success_token=...`, and
//      set `callbackURLScheme = "turnbridge"`. ASWebAuth then returns
//      that URL and we parse the token here.
//   2. If VK ever reflects `success_token` straight into the redirect
//      target (the CaptchaWebView code already opportunistically scans
//      navigations for `?success_token=`), point the callback scheme at
//      whatever that target is.
//
// Until one of those is in place this compiles and presents, but will
// not complete a solve — keep CaptchaWebView as the shipping path.

enum SafariCaptchaError: Error {
    case userCancelled
    case noToken
    case presentationFailed
    case sessionStartFailed
}

@MainActor
final class SafariCaptchaSolver: NSObject {

    private var session: ASWebAuthenticationSession?
    private let presentationAnchor: ASPresentationAnchor

    /// `anchor` is any window in the active scene; pass the app's key
    /// window. The closure receives the extracted success_token, or an
    /// error (cancellation / no-token / start failure).
    init(anchor: ASPresentationAnchor) {
        self.presentationAnchor = anchor
        super.init()
    }

    /// Present the captcha at `redirectURI` in the real Safari service.
    /// `callbackScheme` MUST match the scheme the flow ultimately
    /// redirects to (see the header note). Shares Safari cookies by
    /// default so the session looks aged, not freshly minted.
    func solve(redirectURI: String,
               callbackScheme: String = "turnbridge",
               ephemeral: Bool = false,
               completion: @escaping (Result<String, Error>) -> Void) {
        guard let url = URL(string: redirectURI) else {
            completion(.failure(SafariCaptchaError.presentationFailed))
            return
        }

        let session = ASWebAuthenticationSession(
            url: url,
            callbackURLScheme: callbackScheme
        ) { callbackURL, error in
            if let error = error {
                let ns = error as NSError
                if ns.domain == ASWebAuthenticationSessionError.errorDomain,
                   ns.code == ASWebAuthenticationSessionError.canceledLogin.rawValue {
                    completion(.failure(SafariCaptchaError.userCancelled))
                } else {
                    completion(.failure(error))
                }
                return
            }
            guard let callbackURL = callbackURL,
                  let token = Self.token(from: callbackURL), !token.isEmpty else {
                completion(.failure(SafariCaptchaError.noToken))
                return
            }
            completion(.success(token))
        }

        // false == reuse Safari's cookie jar -> aged vk.com session,
        // the whole point of using this over WKWebView.
        session.prefersEphemeralWebBrowserSession = ephemeral
        session.presentationContextProvider = self

        self.session = session
        if !session.start() {
            completion(.failure(SafariCaptchaError.sessionStartFailed))
        }
    }

    func cancel() {
        session?.cancel()
        session = nil
    }

    /// Pull success_token out of either the query string or the URL
    /// fragment of the callback URL.
    static func token(from url: URL) -> String? {
        if let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let item = comps.queryItems?.first(where: { $0.name == "success_token" }),
           let v = item.value {
            return v
        }
        if let fragment = url.fragment {
            for part in fragment.split(separator: "&") {
                let kv = part.split(separator: "=", maxSplits: 1).map(String.init)
                if kv.count == 2, kv[0] == "success_token" {
                    return kv[1].removingPercentEncoding ?? kv[1]
                }
            }
        }
        return nil
    }
}

extension SafariCaptchaSolver: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        presentationAnchor
    }
}
