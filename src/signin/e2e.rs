//! "Sign in with the tracker" against a real tracker, end to end: the real
//! [`TrackerAuth`] and loopback on this side, the tracker's real Worker and
//! `/link` page (driven by headless Chrome) on the other.
//!
//! Ignored by default and skipped unless `IRMINSUL_E2E_TRACKER` names the
//! API of a tracker *you* run locally (it signs up a made-up user there).
//! How to run it: `tests/e2e/README.md`. Nothing here touches the OS
//! credential store ([`MemoryStore`]), `app.ron` or the data directory, and
//! every user and UID it makes up is synthetic.

use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;

use super::*;

/// The made-up UID of the synthetic capture.
const E2E_UID: &str = "811111111";
const DEVICE: &str = "E2E-TEST-PC";

struct Env {
    base: String,
    origin: String,
    profile: PathBuf,
}

impl Env {
    /// `None` (the test does nothing) unless a tracker was named.
    fn from_env() -> Option<Self> {
        let base = normalize_base(&std::env::var("IRMINSUL_E2E_TRACKER").ok()?);
        let origin = origin_of(&base).expect("IRMINSUL_E2E_TRACKER is not an http(s) URL");
        let profile = std::env::temp_dir().join(format!(
            "irminsul-e2e-{}",
            random_url_safe(6).unwrap().replace(['-', '_'], "x")
        ));
        Some(Self {
            base,
            origin,
            profile,
        })
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // Chrome may still hold a file for a moment after it exits.
        for _ in 0..10 {
            if !self.profile.exists() || std::fs::remove_dir_all(&self.profile).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }
}

/// Run one command of `tests/e2e/tracker-browser.mjs` (blocking) and read
/// its JSON line (`ok: false` with the error when it failed).
fn browser_raw(profile: &std::path::Path, args: &[&str]) -> serde_json::Value {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e/tracker-browser.mjs");
    let chrome = std::env::var("IRMINSUL_E2E_CHROME")
        .unwrap_or_else(|_| "C:/Program Files/Google/Chrome/Application/chrome.exe".to_string());
    let output = match Command::new("node")
        .arg(script)
        // Not as arguments: a `node` shim on Windows may pass them through
        // cmd.exe, which splits the authorize link at its `&`s.
        .env("IRMINSUL_E2E_ARGS", serde_json::json!(args).to_string())
        .env("IRMINSUL_E2E_PROFILE", profile)
        .env("IRMINSUL_E2E_CHROME", chrome)
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            return serde_json::json!({ "ok": false, "error": format!("could not run node: {e}") });
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().last().unwrap_or_default();
    serde_json::from_str(line).unwrap_or_else(|_| {
        serde_json::json!({
            "ok": false,
            "error": format!(
                "the browser script printed no JSON: {stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            ),
        })
    })
}

fn browser_blocking(profile: &std::path::Path, args: &[&str]) -> serde_json::Value {
    let json = browser_raw(profile, args);
    assert_eq!(
        json["ok"],
        true,
        "browser {:?} failed: {json}",
        args.first()
    );
    json
}

async fn browser(profile: &std::path::Path, args: &[&str]) -> serde_json::Value {
    let profile = profile.to_path_buf();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        browser_blocking(&profile, &args)
    })
    .await
    .unwrap()
}

/// A request from the signed-in browser: `(status, body)`.
async fn site(
    env: &Env,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (u64, serde_json::Value) {
    let body = body.map(|b| b.to_string());
    let mut args = vec!["api", env.origin.as_str(), method, path];
    if let Some(body) = &body {
        args.push(body);
    }
    let answer = browser(&env.profile, &args).await;
    (answer["status"].as_u64().unwrap(), answer["body"].clone())
}

fn client() -> reqwest::Client {
    crate::http_client_builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

struct Signer {
    auth: TrackerAuth,
    store: Arc<MemoryStore>,
    /// The consent page's report, once the browser has been to the callback.
    consent: mpsc::Receiver<serde_json::Value>,
}

/// A [`TrackerAuth`] whose "browser" is headless Chrome pressing `choice`
/// (`allow` or `cancel`) on the tracker's consent page.
fn signer(env: &Env, choice: &'static str) -> Signer {
    let store = Arc::new(MemoryStore::default());
    let (tx, consent) = mpsc::channel();
    let profile = env.profile.clone();
    let opener: Opener = Arc::new(move |link: String| {
        let tx = tx.clone();
        let profile = profile.clone();
        std::thread::spawn(move || {
            let report = browser_raw(&profile, &["consent", &link, choice]);
            let _ = tx.send(report);
        });
    });
    let auth = TrackerAuth::new(
        &env.base,
        store.clone(),
        DEVICE.to_string(),
        opener,
        Arc::new(|| {}),
    );
    Signer {
        auth,
        store,
        consent,
    }
}

impl Signer {
    fn stored(&self, origin: &str) -> Option<String> {
        self.store.tokens.lock().unwrap().get(origin).cloned()
    }

    fn status(&self) -> AuthStatus {
        self.auth.status().borrow().clone()
    }

    fn whoami(&self) -> Whoami {
        match self.status() {
            AuthStatus::SignedIn {
                whoami: Some(whoami),
                error: None,
            } => whoami,
            other => panic!("not signed in with a whoami: {other:?}"),
        }
    }

    /// Sign in with the browser's help and return its report of the
    /// consent page. A browser failure ends the sign-in at once rather than
    /// leaving the loopback waiting out its ten minutes.
    async fn sign_in(&self, client: &reqwest::Client) -> serde_json::Value {
        let signing = tokio::spawn({
            let auth = self.auth.clone();
            let client = client.clone();
            async move { auth.sign_in(&client).await }
        });
        // The browser reports once the callback page has shown, which is
        // after the code exchange; give it a little longer than its own waits.
        let deadline = Instant::now() + Duration::from_secs(120);
        let report = loop {
            if let Ok(report) = self.consent.try_recv() {
                break report;
            }
            if Instant::now() > deadline {
                self.auth.cancel_sign_in();
                panic!("the browser never reported");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        if report["ok"] != true {
            self.auth.cancel_sign_in();
            let _ = signing.await;
            panic!("the browser failed on the consent page: {report}");
        }
        signing.await.unwrap();
        report
    }

    async fn access_token(&self) -> Option<String> {
        let session = self.auth.inner.session.lock().await;
        session.access.as_ref().map(|a| a.token.clone())
    }
}

/// A made-up user for this run.
fn made_up_user() -> (String, String) {
    let suffix = random_url_safe(6).unwrap().replace(['-', '_'], "x");
    (format!("e2e_{suffix}"), format!("E2e-pass-{suffix}-0000"))
}

/// A synthetic GOOD capture: no inventory, only the made-up UID.
fn capture() -> String {
    serde_json::json!({
        "format": "GOOD",
        "version": 2,
        "source": "Irminsul",
        "characters": [],
        "weapons": [],
        "artifacts": [],
        "materials": { "Mora": 1000 },
        "gi_player": { "uid": E2E_UID.parse::<u64>().unwrap(), "ar": 30, "wl": 3 },
    })
    .to_string()
}

fn accounts_of(body: &serde_json::Value) -> Vec<serde_json::Value> {
    body.as_array()
        .or_else(|| body.get("accounts").and_then(|a| a.as_array()))
        .cloned()
        .unwrap_or_else(|| panic!("not an account list: {body}"))
}

/// The session id in a `configUrl` (`/app/settings?device=<sid>#devices`).
fn sid_of(config_url: &str) -> u64 {
    let url = Url::parse(config_url).unwrap();
    url.query_pairs()
        .find(|(k, _)| k == "device")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or_else(|| panic!("no session id in {config_url}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a local tracker: IRMINSUL_E2E_TRACKER, see tests/e2e/README.md"]
async fn e2e_sign_in_upload_refresh_retarget_and_sign_out() {
    let Some(env) = Env::from_env() else {
        eprintln!("IRMINSUL_E2E_TRACKER is not set; nothing to do");
        return;
    };
    let client = client();
    let (username, password) = made_up_user();

    // 0. A made-up user signs up on the website.
    let made = browser(
        &env.profile,
        &["session", &env.origin, &username, &password],
    )
    .await;
    eprintln!("step 0: website user ready ({})", made["how"]);

    // 1. Discovery: irminsul's reader accepts the tracker's real answer.
    let body = client
        .get(endpoint(&env.base, "oauth/irminsul"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let discovery = parse_discovery(&body, &env.base).expect("discovery");
    let raw: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(raw["client_id"], CLIENT_ID);
    assert_eq!(raw["version"], 1);
    eprintln!("step 1: discovery ok ({})", discovery.authorize_url);

    // 2. Sign in: the browser allows on /link, lands on the loopback, the
    //    code is exchanged and whoami comes with the tokens.
    let s = signer(&env, "allow");
    s.auth.load(&client).await;
    assert_eq!(s.status(), AuthStatus::SignedOut { notice: None });
    let report = s.sign_in(&client).await;
    assert_eq!(report["callbackPath"], "/callback", "{report}");
    assert_eq!(
        report["callbackParams"],
        serde_json::json!(["code", "state"])
    );
    assert_eq!(report["heading"], "Signed in", "{report}");
    assert!(
        report["consent"].as_str().unwrap().contains(DEVICE),
        "{report}"
    );
    let whoami = s.whoami();
    assert_eq!(whoami.scope, UploadScope::Uid);
    assert_eq!(whoami.user, username);
    assert_eq!(whoami.account_id, None);
    assert_eq!(whoami.uid, None);
    assert_eq!(
        whoami.dashboard_url.as_deref(),
        Some(format!("{}/app", env.origin).as_str())
    );
    let config_url = whoami.config_url.clone().expect("whoami has a configUrl");
    assert!(config_url.starts_with(&env.origin), "{config_url}");
    let sid = sid_of(&config_url);
    let refresh_1 = s.stored(&env.origin).expect("a stored refresh token");
    eprintln!("step 2: signed in as {username}, session {sid}, uid mode");

    // The website lists the session as this PC.
    let (status, sessions) = site(&env, "GET", "/api/auth/sessions", None).await;
    assert_eq!(status, 200, "{sessions}");
    let row = sessions
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"].as_u64() == Some(sid))
        .unwrap_or_else(|| panic!("session {sid} not listed: {sessions}"))
        .clone();
    assert_eq!(row["method"], "irminsul", "{row}");
    assert_eq!(row["deviceName"], DEVICE, "{row}");
    assert_eq!(row["upload"], serde_json::json!({ "mode": "uid" }), "{row}");
    eprintln!("step 2b: Devices lists it as {}", row["userAgent"]);

    // Configure's link opens that row on the website.
    let shown = browser(
        &env.profile,
        &["page", &config_url, &format!("#device-{sid}")],
    )
    .await;
    assert!(
        shown["text"]
            .as_str()
            .unwrap()
            .contains(&format!("Irminsul on {DEVICE}")),
        "{shown}"
    );
    eprintln!("step 2c: configUrl opens {}", shown["url"]);

    // 3. A Bearer upload in uid mode creates the account for the UID.
    s.auth
        .upload(
            &client,
            &env.base,
            capture(),
            Some(1_790_000_000_000),
            Duration::from_secs(30),
        )
        .await
        .expect("first upload");
    let (status, accounts) = site(&env, "GET", "/api/accounts", None).await;
    assert_eq!(status, 200, "{accounts}");
    let accounts = accounts_of(&accounts);
    assert_eq!(accounts.len(), 1, "{accounts:?}");
    assert_eq!(accounts[0]["uid"], E2E_UID, "{accounts:?}");
    let account_id = accounts[0]["id"].as_i64().unwrap();
    eprintln!("step 3: upload made account {account_id} for UID {E2E_UID}");

    // 4. Refresh, twice: once because the access token is about to lapse
    //    (irminsul's own clock), once because the tracker refuses the one
    //    it holds (401 token_expired -> refresh -> retry).
    {
        let mut session = s.auth.inner.session.lock().await;
        session.access.as_mut().unwrap().expires_at = Instant::now();
    }
    s.auth.refresh_whoami(&client).await;
    let refresh_2 = s.stored(&env.origin).unwrap();
    assert_ne!(refresh_1, refresh_2, "the refresh token rotates");
    assert_eq!(s.whoami().scope, UploadScope::Uid);
    {
        let mut session = s.auth.inner.session.lock().await;
        session.access.as_mut().unwrap().token = "not.a.token".to_string();
    }
    s.auth
        .upload(
            &client,
            &env.base,
            capture(),
            Some(1_790_000_100_000),
            Duration::from_secs(30),
        )
        .await
        .expect("upload after the tracker refused the access token");
    let refresh_3 = s.stored(&env.origin).unwrap();
    assert_ne!(refresh_2, refresh_3, "the 401 refreshed");
    let (_, accounts) = site(&env, "GET", "/api/accounts", None).await;
    assert_eq!(
        accounts_of(&accounts).len(),
        1,
        "the second upload used the same account"
    );
    eprintln!("step 4: two refreshes, second upload to the same account");

    // 5. The target changes on the website; whoami says so.
    let (status, answer) = site(
        &env,
        "PATCH",
        &format!("/api/auth/sessions/{sid}"),
        Some(serde_json::json!({ "upload": { "mode": "account", "account_id": account_id } })),
    )
    .await;
    assert_eq!(status, 200, "{answer}");
    s.auth.refresh_whoami(&client).await;
    let whoami = s.whoami();
    assert_eq!(whoami.scope, UploadScope::Account);
    assert_eq!(whoami.account_id, Some(account_id));
    assert_eq!(whoami.uid.as_deref(), Some(E2E_UID));
    // The account the upload made has no name; the label says its UID.
    assert_eq!(whoami.account_name, None);
    assert_eq!(whoami.target_label(), format!("UID {E2E_UID}"));
    assert_eq!(whoami.config_url.as_deref(), Some(config_url.as_str()));
    assert_eq!(
        whoami.dashboard_url.as_deref(),
        Some(format!("{}/app/a/{account_id}", env.origin).as_str())
    );
    eprintln!("step 5: retargeted to {}", whoami.target_label());
    // And an upload in account mode goes there.
    s.auth
        .upload(
            &client,
            &env.base,
            capture(),
            Some(1_790_000_200_000),
            Duration::from_secs(30),
        )
        .await
        .expect("upload in account mode");

    // An answer the tracker refuses keeps the sign-in and says why.
    let err = s
        .auth
        .upload(
            &client,
            &env.base,
            "{\"format\":\"nope\"}".to_string(),
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap_err();
    assert!(err.starts_with("HTTP 4"), "{err}");
    assert!(s.status().is_signed_in());
    eprintln!("step 5b: a refused upload reads: {err}");

    // The chosen account is deleted on the website: no target until one is
    // picked again, and uploads say where to pick it.
    let (status, answer) = site(&env, "DELETE", &format!("/api/accounts/{account_id}"), None).await;
    assert_eq!(status, 204, "{answer}");
    s.auth.refresh_whoami(&client).await;
    let whoami = s.whoami();
    assert_eq!(whoami.scope, UploadScope::Account);
    assert_eq!(whoami.target_label(), "Not chosen");
    assert_eq!(whoami.config_url.as_deref(), Some(config_url.as_str()));
    let err = s
        .auth
        .upload(&client, &env.base, capture(), None, Duration::from_secs(30))
        .await
        .unwrap_err();
    assert!(err.starts_with("HTTP 409"), "{err}");
    assert!(err.contains(&config_url), "{err}");
    assert!(s.status().is_signed_in());
    eprintln!("step 5c: target deleted -> 'Not chosen', upload: {err}");

    // Back to Auto by UID: a capture without a UID can't be routed (422
    // uid_required), one with it makes the account again.
    let (status, answer) = site(
        &env,
        "PATCH",
        &format!("/api/auth/sessions/{sid}"),
        Some(serde_json::json!({ "upload": { "mode": "uid" } })),
    )
    .await;
    assert_eq!(status, 200, "{answer}");
    s.auth.refresh_whoami(&client).await;
    assert_eq!(s.whoami().scope, UploadScope::Uid);
    let mut no_uid: serde_json::Value = serde_json::from_str(&capture()).unwrap();
    no_uid.as_object_mut().unwrap().remove("gi_player");
    let err = s
        .auth
        .upload(
            &client,
            &env.base,
            no_uid.to_string(),
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap_err();
    assert!(err.starts_with("HTTP 422"), "{err}");
    assert!(err.contains(&config_url), "{err}");
    s.auth
        .upload(
            &client,
            &env.base,
            capture(),
            Some(1_790_000_300_000),
            Duration::from_secs(30),
        )
        .await
        .expect("upload after going back to uid mode");
    let (_, accounts) = site(&env, "GET", "/api/accounts", None).await;
    let accounts = accounts_of(&accounts);
    assert_eq!(accounts.len(), 1, "{accounts:?}");
    assert_eq!(accounts[0]["uid"], E2E_UID);
    eprintln!("step 5d: back to uid mode; a capture without a UID: {err}");

    // 6. Sign out: revoked on the tracker, gone from the store, and the old
    //    tokens are dead.
    let last_refresh = s.stored(&env.origin).unwrap();
    let last_access = s.access_token().await.unwrap();
    s.auth.sign_out(&client).await;
    assert_eq!(s.status(), AuthStatus::SignedOut { notice: None });
    assert_eq!(s.stored(&env.origin), None);
    let refused = post_token(
        &client,
        &discovery.token_url,
        &serde_json::json!({
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": last_refresh,
        }),
    )
    .await;
    assert!(
        matches!(refused, Err(TokenError::InvalidGrant)),
        "{:?}",
        refused.err()
    );
    let whoami = client
        .get(endpoint(&env.base, "irminsul/whoami"))
        .bearer_auth(&last_access)
        .send()
        .await
        .unwrap();
    assert_eq!(whoami.status(), StatusCode::UNAUTHORIZED);
    let body = whoami.text().await.unwrap();
    assert_eq!(
        api_error_code(&body).as_deref(),
        Some("session_revoked"),
        "{body}"
    );
    let (_, sessions) = site(&env, "GET", "/api/auth/sessions", None).await;
    assert!(
        !sessions
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"].as_u64() == Some(sid)),
        "the ended session is still listed: {sessions}"
    );
    eprintln!("step 6: signed out; old refresh token invalid_grant, old access session_revoked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a local tracker: IRMINSUL_E2E_TRACKER, see tests/e2e/README.md"]
async fn e2e_cancel_on_the_consent_page_is_access_denied() {
    let Some(env) = Env::from_env() else {
        eprintln!("IRMINSUL_E2E_TRACKER is not set; nothing to do");
        return;
    };
    let client = client();
    let (username, password) = made_up_user();
    browser(
        &env.profile,
        &["session", &env.origin, &username, &password],
    )
    .await;

    let s = signer(&env, "cancel");
    s.auth.load(&client).await;
    let report = s.sign_in(&client).await;
    assert_eq!(report["callbackError"], "access_denied", "{report}");
    assert_eq!(report["heading"], "Not signed in", "{report}");
    assert_eq!(
        s.status(),
        AuthStatus::SignedOut {
            notice: Some("Sign-in cancelled on the tracker".to_string())
        }
    );
    assert_eq!(s.stored(&env.origin), None);
    // No irminsul session was made.
    let (_, sessions) = site(&env, "GET", "/api/auth/sessions", None).await;
    assert!(
        !sessions
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "irminsul"),
        "{sessions}"
    );
    eprintln!("cancel: the loopback heard access_denied; nothing stored");
}
