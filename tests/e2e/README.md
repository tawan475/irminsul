# Sign-in end-to-end test

`src/signin/e2e.rs` runs irminsul's real "Sign in with the tracker" (`TrackerAuth`, its loopback
listener, uploads) against a tracker you run locally, with headless Chrome playing the user on the
tracker's `/link` page (`tracker-browser.mjs`). It is `#[ignore]`d, so CI and `check.py` never run it,
and it does nothing unless `IRMINSUL_E2E_TRACKER` is set. It signs up a made-up user on that tracker
and uploads a synthetic capture (UID 811111111); it never touches the OS credential store, `app.ron`
or irminsul's data directory.

1. Start the tracker (`genshin-data-tracker/apps/tracker`, local D1 migrated) on, say, port 5181.
2. Have Node and a `node_modules` with `puppeteer-core` somewhere, and Chrome installed.
3. Run:

```sh
IRMINSUL_E2E_TRACKER=http://localhost:5181/api \
IRMINSUL_E2E_PUPPETEER=<dir>/node_modules \
IRMINSUL_E2E_CHROME="C:/Program Files/Google/Chrome/Application/chrome.exe" \
cargo test --bin irminsul signin::e2e -- --ignored --test-threads=1 --nocapture
```

`IRMINSUL_E2E_CHROME` defaults to the path above. The steps print as they pass: discovery, sign in
(Allow), the Devices row and Configure's link, a uid-mode upload creating the account, two refreshes
(local expiry and a 401 from the tracker), retargeting on the website, a deleted target, a capture
without a UID, sign out (the old refresh token gets `invalid_grant`, the old access token
`session_revoked`), and Cancel on the consent page reaching irminsul as `access_denied`.
