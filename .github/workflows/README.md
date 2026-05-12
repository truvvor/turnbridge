# CI: Build & TestFlight

Workflow `testflight.yml` archives the iOS app on the self-hosted
`Mac-mini-GK` runner (`self-hosted`, `macOS`, `ARM64`) and uploads the build
to TestFlight via the App Store Connect API.

## One-time setup

### 1. Apple Developer / App Store Connect

1. In **Apple Developer → Certificates, Identifiers & Profiles**, register
   both bundle IDs and enable the required capabilities:
   - `com.netlab.TurnBridge` — App Groups (`group.com.netlab.TurnBridge`),
     Network Extensions.
   - `com.netlab.TurnBridge.network-extension` — App Groups
     (`group.com.netlab.TurnBridge`), Network Extensions
     (Packet Tunnel Provider).
2. In **App Store Connect → My Apps**, create the app record for
   `com.netlab.TurnBridge` (needed before the first TestFlight upload).
3. In **App Store Connect → Users and Access → Integrations → App Store
   Connect API**, create an API key with the **App Manager** role. Save the
   downloaded `.p8` file — it is shown only once.

### 2. Self-hosted runner (Mac-mini-GK)

Make sure the runner has:

- Xcode (matching the project's deployment target, iOS 16.6+) installed and
  selected: `sudo xcode-select -s /Applications/Xcode.app`.
- Command line tools and a logged-in Apple ID in Xcode is **not** required —
  signing is driven by the App Store Connect API key.
- Homebrew + Go (`brew install go`) — the `WireGuardKitGo` build phase needs
  it. The script looks in `/opt/homebrew/bin`.
- The runner user must be able to access the login keychain non-interactively
  (no password prompt). If Xcode prompts for the keychain on first run,
  unlock it once manually or store the password with `security
  set-key-partition-list`.

### 3. GitHub repository secrets

In `truvvor/turnbridge` → **Settings → Secrets and variables → Actions**, add:

| Secret               | Value                                                         |
| -------------------- | ------------------------------------------------------------- |
| `APPLE_TEAM_ID`      | 10-character Team ID (e.g. `ABCDE12345`)                      |
| `ASC_ISSUER_ID`      | Issuer ID UUID from App Store Connect → Integrations           |
| `ASC_KEY_ID`         | 10-character Key ID from the same page                         |
| `ASC_KEY_P8_BASE64`  | `base64 -i AuthKey_<KEY_ID>.p8` output (single line, no wrap) |

On macOS, generate the base64 secret with:

```bash
base64 -i AuthKey_XXXXXXXXXX.p8 | pbcopy
```

## Triggering

- Manually: **Actions → Build & TestFlight → Run workflow**, choose `upload`
  to send to TestFlight or `build-only` to just produce the IPA artifact.
- Automatically: every push to `claude/build-project-br5tJ` (excluding doc /
  asset only changes) runs the workflow and uploads.

## Build number

`CFBundleVersion` is overridden to `100 + GITHUB_RUN_NUMBER` so each run is
strictly higher than the previous one. To raise the floor (e.g. after
manually uploading some builds outside CI), set repo variable
`TESTFLIGHT_BUILD_BASE` to a larger number.

`MARKETING_VERSION` (1.2.6 today) stays as committed in
`TurnBridge.xcodeproj/project.pbxproj` — bump it there when releasing a new
TestFlight version family.

## Notes

- Code signing uses Xcode automatic signing with `-allowProvisioningUpdates`
  + the App Store Connect API key. The ASC API key is enough — no `.p12`
  cert or provisioning profile secrets needed.
- `ENABLE_USER_SCRIPT_SANDBOXING=NO` is passed at archive time because the
  WireGuardKitGo build phase writes outside of its declared inputs/outputs.
- The IPA is also published as a workflow artifact (`TurnBridge-ipa`) so you
  can download an unsigned-for-AppStore copy without re-running the upload
  step.
