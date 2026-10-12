//! Tests for the tracker sign-in. Nothing here touches the real credential
//! store ([`MemoryStore`]) or a real tracker: [`FakeTracker`] is a small
//! in-process HTTP server that speaks the contract, and the "browser" is a
//! closure that plays the consent screen's part.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

// ---------------------------------------------------------------------------
// PKCE, state, URLs
// ---------------------------------------------------------------------------

#[test]
fn the_pkce_challenge_matches_rfc_7636_appendix_b() {
    // RFC 7636 appendix B: these 32 octets, base64url-encoded, are the
    // verifier, and its S256 challenge is the one given there.
    let octets: [u8; 32] = [
        116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37,
        77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121,
    ];
    let verifier = BASE64_URL_SAFE_NO_PAD.encode(octets);
    assert_eq!(verifier, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    assert_eq!(
        s256_challenge(&verifier),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    let pkce = Pkce::from_verifier(verifier);
    assert_eq!(
        pkce.challenge,
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn generated_verifiers_and_states_are_long_url_safe_and_fresh() {
    let url_safe = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    let a = Pkce::generate().unwrap();
    let b = Pkce::generate().unwrap();
    // RFC 7636: 43 to 128 characters of the unreserved alphabet.
    assert_eq!(a.verifier.len(), 43);
    assert!(url_safe(&a.verifier) && url_safe(&a.challenge));
    assert_ne!(a.verifier, b.verifier);
    assert_eq!(a.challenge, s256_challenge(&a.verifier));

    // The contract asks for 32+ url-safe characters of state.
    let state = random_url_safe(32).unwrap();
    assert!(state.len() >= 32 && url_safe(&state));
    assert_ne!(state, random_url_safe(32).unwrap());
}

#[test]
fn the_device_name_is_trimmed_bounded_and_never_empty() {
    assert_eq!(clean_device_name("  GAMING-PC \n"), "GAMING-PC");
    assert_eq!(clean_device_name(&"x".repeat(100)).chars().count(), 64);
    assert_eq!(clean_device_name("a\u{7}b"), "ab");
    assert_eq!(clean_device_name("   "), "this PC");
}

fn discovery_at(origin: &str) -> Discovery {
    Discovery {
        authorize_url: format!("{origin}/link"),
        token_url: format!("{origin}/api/oauth/token"),
        revoke_url: format!("{origin}/api/oauth/revoke"),
    }
}

#[test]
fn the_authorize_url_carries_every_contract_parameter() {
    let discovery = discovery_at("https://tracker.example");
    let url = authorize_url(
        &discovery,
        "http://127.0.0.1:50123/callback",
        "state-abc",
        "challenge-xyz",
        "My PC",
    )
    .unwrap();
    assert!(url.starts_with("https://tracker.example/link?"), "{url}");
    assert!(
        url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A50123%2Fcallback"),
        "{url}"
    );
    let parsed = Url::parse(&url).unwrap();
    let query: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
    assert_eq!(query["client_id"], "irminsul");
    assert_eq!(query["redirect_uri"], "http://127.0.0.1:50123/callback");
    assert_eq!(query["state"], "state-abc");
    assert_eq!(query["code_challenge"], "challenge-xyz");
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(query["device"], "My PC");
}

#[test]
fn discovery_must_keep_the_token_endpoints_on_the_trackers_own_origin() {
    let base = "https://tracker.example/api";
    let good = r#"{"authorize_url":"https://tracker.example/link","token_url":"https://tracker.example/api/oauth/token","revoke_url":"https://tracker.example/api/oauth/revoke","client_id":"irminsul","version":1}"#;
    assert_eq!(
        parse_discovery(good, base).unwrap(),
        discovery_at("https://tracker.example")
    );

    for (field, value) in [
        ("token_url", "https://evil.example/api/oauth/token"),
        ("revoke_url", "https://evil.example/api/oauth/revoke"),
        // Same host, another scheme or port is another origin.
        ("token_url", "http://tracker.example/api/oauth/token"),
        ("token_url", "https://tracker.example:8443/api/oauth/token"),
        ("authorize_url", "javascript:alert(1)"),
    ] {
        let mut json: serde_json::Value = serde_json::from_str(good).unwrap();
        json[field] = value.into();
        assert!(
            parse_discovery(&json.to_string(), base).is_err(),
            "{field} = {value} was accepted"
        );
    }
    assert!(parse_discovery("<html>", base).is_err());
    assert!(parse_discovery(r#"{"authorize_url":"https://tracker.example/link"}"#, base).is_err());
}

#[test]
fn addresses_normalize_and_name_their_origin_and_host() {
    assert_eq!(
        normalize_base(" https://t.example/api/ "),
        "https://t.example/api"
    );
    assert_eq!(
        origin_of("https://t.example/api").unwrap(),
        "https://t.example"
    );
    assert_eq!(
        origin_of("http://localhost:5173/api").unwrap(),
        "http://localhost:5173"
    );
    assert!(origin_of("not a url").is_err());
    assert!(origin_of("file:///etc/passwd").is_err());
    assert_eq!(
        host_of("https://t.example/api").as_deref(),
        Some("t.example")
    );
    assert_eq!(
        host_of("http://127.0.0.1:8787/api").as_deref(),
        Some("127.0.0.1:8787")
    );
}

// ---------------------------------------------------------------------------
// The callback
// ---------------------------------------------------------------------------

fn get(target: &str) -> String {
    format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
}

#[test]
fn a_callback_with_the_right_state_yields_the_code() {
    assert_eq!(
        parse_callback(&get("/callback?code=abc123&state=S1"), "S1"),
        Callback::Code("abc123".to_string())
    );
    // Order does not matter, and a repeated parameter cannot override.
    assert_eq!(
        parse_callback(&get("/callback?state=S1&code=abc&code=evil"), "S1"),
        Callback::Code("abc".to_string())
    );
}

#[test]
fn a_cancel_on_the_consent_screen_is_a_denial() {
    assert_eq!(
        parse_callback(&get("/callback?error=access_denied&state=S1"), "S1"),
        Callback::Denied
    );
    assert_eq!(
        parse_callback(&get("/callback?error=server_error&state=S1"), "S1"),
        Callback::Failed("server_error".to_string())
    );
    // An error code is never echoed raw.
    assert_eq!(
        parse_callback(&get("/callback?error=%3Cscript%3E&state=S1"), "S1"),
        Callback::Failed("script".to_string())
    );
}

#[test]
fn a_callback_for_another_state_is_refused_whatever_it_carries() {
    for target in [
        "/callback?code=abc&state=S2",
        "/callback?code=abc",
        "/callback?code=abc&state=",
        "/callback?error=access_denied&state=nope",
        "/callback?code=abc&state=S",
    ] {
        assert_eq!(
            parse_callback(&get(target), "S1"),
            Callback::StateMismatch,
            "{target}"
        );
    }
}

#[test]
fn junk_and_other_paths_are_not_the_callback() {
    for head in [
        "",
        "garbage",
        "\r\n\r\n",
        "GET\r\n\r\n",
        "POST /callback?code=abc&state=S1 HTTP/1.1\r\n\r\n",
        "GET /favicon.ico HTTP/1.1\r\n\r\n",
        "GET /callbackx?code=abc&state=S1 HTTP/1.1\r\n\r\n",
        "GET http://evil/callback?code=abc&state=S1 HTTP/1.1\r\n\r\n",
        "GET /callback?code=abc&state=S1 SPDY/3\r\n\r\n",
    ] {
        assert_eq!(parse_callback(head, "S1"), Callback::Other, "{head:?}");
    }
    assert_eq!(
        parse_callback(&get("/callback?state=S1"), "S1"),
        Callback::Malformed
    );
}

#[test]
fn the_callback_page_is_self_contained_and_escapes_its_text() {
    let page = callback_page(false, "<b>x</b> & \"y\"");
    assert!(page.contains("&lt;b&gt;x&lt;/b&gt; &amp; &quot;y&quot;"));
    assert!(!page.contains("<script"));
    assert!(!page.contains("http://") && !page.contains("https://"));
    assert!(callback_page(true, "ok").contains("Signed in"));
}

// ---------------------------------------------------------------------------
// Token answers
// ---------------------------------------------------------------------------

fn whoami_json(scope: &str) -> serde_json::Value {
    serde_json::json!({
        "scope": scope,
        "user": "traveler",
        "accountId": if scope == "account" { serde_json::json!(12) } else { serde_json::Value::Null },
        "accountName": if scope == "account" { serde_json::json!("Main") } else { serde_json::Value::Null },
        "uid": if scope == "account" { serde_json::json!("811111111") } else { serde_json::Value::Null },
        "server": if scope == "account" { serde_json::json!("ASIA") } else { serde_json::Value::Null },
        "dashboardUrl": "https://tracker.example/app",
        "configUrl": "https://tracker.example/app/settings/devices",
    })
}

#[test]
fn a_code_exchange_answer_carries_both_tokens_and_whoami() {
    let body = serde_json::json!({
        "token_type": "Bearer", "access_token": "AT", "expires_in": 900,
        "refresh_token": "RT", "refresh_expires_in": 2592000, "whoami": whoami_json("uid"),
    })
    .to_string();
    let tokens = parse_token_response(200, &body).unwrap();
    assert_eq!(tokens.access_token, "AT");
    assert_eq!(tokens.refresh_token, "RT");
    assert_eq!(tokens.expires_in, Duration::from_secs(900));
    let whoami = tokens.whoami.unwrap();
    assert_eq!(whoami.scope, UploadScope::Uid);
    assert_eq!(whoami.user, "traveler");
    assert_eq!(whoami.target_label(), "Auto (by UID)");
    assert_eq!(
        whoami.config_url.as_deref(),
        Some("https://tracker.example/app/settings/devices")
    );
}

#[test]
fn a_refresh_answer_without_whoami_is_still_a_grant() {
    let body =
        r#"{"token_type":"bearer","access_token":"AT2","expires_in":60,"refresh_token":"RT2"}"#;
    let tokens = parse_token_response(200, body).unwrap();
    assert_eq!(tokens.access_token, "AT2");
    assert_eq!(tokens.refresh_token, "RT2");
    assert!(tokens.whoami.is_none());
}

#[test]
fn oauth_errors_are_told_apart() {
    assert_eq!(
        parse_token_response(
            400,
            r#"{"error":"invalid_grant","error_description":"used"}"#
        )
        .err(),
        Some(TokenError::InvalidGrant)
    );
    assert_eq!(
        parse_token_response(403, r#"{"error":"account_suspended"}"#).err(),
        Some(TokenError::Suspended)
    );
    assert_eq!(
        parse_token_response(400, r#"{"error":"unsupported_grant_type"}"#).err(),
        Some(TokenError::Rejected {
            status: 400,
            error: "unsupported_grant_type".to_string()
        })
    );
    assert_eq!(
        parse_token_response(400, r#"{"error":{"code":"invalid_request","message":"x"}}"#).err(),
        Some(TokenError::Rejected {
            status: 400,
            error: "invalid_request".to_string()
        })
    );
    assert_eq!(
        parse_token_response(502, "<html>bad gateway</html>").err(),
        Some(TokenError::Rejected {
            status: 502,
            error: "unknown_error".to_string()
        })
    );
    // A 200 that is not a usable grant.
    for body in [
        "not json",
        r#"{"access_token":"AT"}"#,
        r#"{"refresh_token":"RT"}"#,
        r#"{"access_token":"","refresh_token":"RT"}"#,
        r#"{"token_type":"mac","access_token":"AT","refresh_token":"RT"}"#,
    ] {
        assert!(
            matches!(
                parse_token_response(200, body),
                Err(TokenError::Malformed(_))
            ),
            "{body}"
        );
    }
}

#[test]
fn whoami_keeps_only_web_links_and_reads_numeric_uids() {
    let mut json = whoami_json("account");
    json["uid"] = serde_json::json!(811111111);
    json["dashboardUrl"] = "javascript:alert(1)".into();
    json["configUrl"] = "file:///c:/x".into();
    let whoami = parse_whoami(&json).unwrap();
    assert_eq!(whoami.uid.as_deref(), Some("811111111"));
    assert_eq!(whoami.dashboard_url, None);
    assert_eq!(whoami.config_url, None);
    assert_eq!(whoami.target_label(), "Main (UID 811111111)");
    assert!(parse_whoami(&serde_json::json!({"user": "x"})).is_err());
}

#[test]
fn the_status_debug_output_never_shows_the_sign_in_link() {
    let status = AuthStatus::Waiting {
        link: Some("https://t.example/link?state=SECRETSTATE".to_string()),
    };
    let debug = format!("{status:?}");
    assert!(!debug.contains("SECRETSTATE"), "{debug}");
}

// ---------------------------------------------------------------------------
// The loopback listener
// ---------------------------------------------------------------------------

async fn raw_get(port: u16, target: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn the_loopback_serves_one_callback_and_closes() {
    let loopback = Loopback::bind().await.unwrap();
    let port = loopback.port();
    assert_eq!(
        loopback.redirect_uri(),
        format!("http://127.0.0.1:{port}/callback")
    );
    let waiter = tokio::spawn(async move {
        let hit = loopback.wait("S1", Duration::from_secs(10)).await.unwrap();
        let outcome = hit.outcome.clone();
        hit.answer(true).await;
        outcome
    });

    // A speculative connection that never sends anything does not hold up
    // the real request, and a favicon fetch is a 404 that does not end it.
    let _idle = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let favicon = raw_get(port, "/favicon.ico").await;
    assert!(favicon.starts_with("HTTP/1.1 404"), "{favicon}");

    let page = raw_get(port, "/callback?code=abc&state=S1").await;
    assert!(page.starts_with("HTTP/1.1 200 OK"), "{page}");
    assert!(page.contains("Content-Security-Policy: default-src 'none'"));
    assert!(page.contains("Signed in"));
    assert!(!page.contains("abc"), "the code is never echoed: {page}");

    assert_eq!(waiter.await.unwrap(), Callback::Code("abc".to_string()));
    // The port is closed once the callback was served.
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
}

#[tokio::test]
async fn the_loopback_gives_up_after_its_timeout() {
    let loopback = Loopback::bind().await.unwrap();
    let port = loopback.port();
    let result = loopback.wait("S1", Duration::from_millis(50)).await;
    assert!(result.is_err());
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
}

// ---------------------------------------------------------------------------
// A fake tracker
// ---------------------------------------------------------------------------

/// What the fake tracker knows and saw.
#[derive(Default)]
struct FakeState {
    /// code -> (challenge, redirect_uri)
    codes: HashMap<String, (String, String)>,
    access: Option<String>,
    refresh: Option<String>,
    counter: usize,
    /// The next whoami/import answers 401 token_expired once.
    expire_access: bool,
    /// The session was ended on the tracker (Devices → Sign out).
    revoked: bool,
    whoami_scope: String,
    /// Point discovery's token URL at another origin.
    foreign_token_url: bool,
    /// Every request: (method, path, authorization header).
    requests: Vec<(String, String, Option<String>)>,
    imports: Vec<String>,
    revoked_tokens: Vec<String>,
    /// Refresh grants answered.
    refresh_grants: usize,
    /// Every refresh token ever issued, to catch a reuse.
    issued_refresh: Vec<String>,
    /// whoami and import answer 403 `uploads_blocked`.
    block_uploads: bool,
}

struct FakeTracker {
    base: String,
    port: u16,
    state: Arc<StdMutex<FakeState>>,
}

struct FakeRequest {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl FakeTracker {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(StdMutex::new(FakeState {
            whoami_scope: "uid".to_string(),
            ..FakeState::default()
        }));
        let server_state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let state = Arc::clone(&server_state);
                tokio::spawn(async move { serve(stream, port, state).await });
            }
        });
        Self {
            base: format!("http://127.0.0.1:{port}/api"),
            port,
            state,
        }
    }

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap()
    }

    /// The consent screen's Allow: what `POST /api/oauth/authorize` does,
    /// done directly. Returns the redirect the page would navigate to.
    fn authorize(&self, link: &str) -> String {
        let url = Url::parse(link).unwrap();
        assert_eq!(url.path(), "/link");
        let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(query["client_id"], "irminsul");
        assert_eq!(query["code_challenge_method"], "S256");
        assert!(!query["device"].is_empty());
        let redirect = query["redirect_uri"].clone();
        assert!(redirect.starts_with("http://127.0.0.1:") && redirect.ends_with("/callback"));
        let mut state = self.state();
        state.counter += 1;
        let code = format!("code-{}", state.counter);
        state.codes.insert(
            code.clone(),
            (query["code_challenge"].clone(), redirect.clone()),
        );
        format!("{redirect}?code={code}&state={}", query["state"])
    }

    fn saw_bearer_anywhere(&self) -> bool {
        self.state()
            .requests
            .iter()
            .any(|(_, _, auth)| auth.is_some())
    }
}

async fn read_fake_request(stream: &mut TcpStream) -> Option<FakeRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_string();
    let target = request_line.next()?.to_string();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let mut body = buf[head_end..].to_vec();
    if let Some(len) = headers.get("content-length") {
        let len: usize = len.parse().ok()?;
        while body.len() < len {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    } else if headers
        .get("transfer-encoding")
        .is_some_and(|te| te.contains("chunked"))
    {
        while !body.windows(5).any(|w| w == b"0\r\n\r\n") {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    }
    let url = Url::parse(&format!("http://fake{target}")).ok()?;
    Some(FakeRequest {
        method,
        path: url.path().to_string(),
        query: url.query_pairs().into_owned().collect(),
        headers,
        body,
    })
}

async fn serve(mut stream: TcpStream, port: u16, state: Arc<StdMutex<FakeState>>) {
    let Some(request) = read_fake_request(&mut stream).await else {
        return;
    };
    let (status, body) = respond(&request, port, &state);
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn respond(
    request: &FakeRequest,
    port: u16,
    state: &Arc<StdMutex<FakeState>>,
) -> (&'static str, String) {
    let mut s = state.lock().unwrap();
    let auth = request.headers.get("authorization").cloned();
    s.requests
        .push((request.method.clone(), request.path.clone(), auth.clone()));
    let origin = format!("http://127.0.0.1:{port}");
    let json_body =
        || serde_json::from_slice::<serde_json::Value>(&request.body).unwrap_or_default();
    let bearer_ok = |s: &FakeState| {
        auth.as_deref()
            .and_then(|a| a.strip_prefix("Bearer "))
            .is_some_and(|token| Some(token) == s.access.as_deref())
    };

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/api/oauth/irminsul") => {
            let token_origin = if s.foreign_token_url {
                "http://127.0.0.2:1".to_string()
            } else {
                origin.clone()
            };
            (
                "200 OK",
                serde_json::json!({
                    "authorize_url": format!("{origin}/link"),
                    "token_url": format!("{token_origin}/api/oauth/token"),
                    "revoke_url": format!("{origin}/api/oauth/revoke"),
                    "client_id": "irminsul",
                    "version": 1,
                })
                .to_string(),
            )
        }
        ("POST", "/api/oauth/token") => {
            let body = json_body();
            let issue = |s: &mut FakeState, with_whoami: bool| {
                s.counter += 1;
                let access = format!("access-{}", s.counter);
                let refresh = format!("refresh-{}", s.counter);
                s.access = Some(access.clone());
                s.refresh = Some(refresh.clone());
                s.issued_refresh.push(refresh.clone());
                let mut answer = serde_json::json!({
                    "token_type": "Bearer", "access_token": access, "expires_in": 900,
                    "refresh_token": refresh, "refresh_expires_in": 2592000,
                });
                if with_whoami {
                    answer["whoami"] = whoami_json(&s.whoami_scope);
                }
                answer.to_string()
            };
            let invalid_grant =
                || r#"{"error":"invalid_grant","error_description":"no"}"#.to_string();
            match body["grant_type"].as_str() {
                Some("authorization_code") => {
                    let code = body["code"].as_str().unwrap_or_default();
                    let Some((challenge, redirect)) = s.codes.remove(code) else {
                        return ("400 Bad Request", invalid_grant());
                    };
                    let verifier = body["code_verifier"].as_str().unwrap_or_default();
                    if s256_challenge(verifier) != challenge
                        || body["redirect_uri"].as_str() != Some(redirect.as_str())
                        || body["client_id"].as_str() != Some("irminsul")
                    {
                        return ("400 Bad Request", invalid_grant());
                    }
                    s.revoked = false;
                    ("200 OK", issue(&mut s, true))
                }
                Some("refresh_token") => {
                    let presented = body["refresh_token"].as_str();
                    if s.revoked || presented.is_none() || presented != s.refresh.as_deref() {
                        // Like the tracker: presenting a rotated-away token
                        // ends the whole session.
                        if presented.is_some_and(|p| s.issued_refresh.iter().any(|t| t == p)) {
                            s.revoked = true;
                        }
                        return ("400 Bad Request", invalid_grant());
                    }
                    s.refresh_grants += 1;
                    ("200 OK", issue(&mut s, false))
                }
                _ => (
                    "400 Bad Request",
                    r#"{"error":"unsupported_grant_type"}"#.to_string(),
                ),
            }
        }
        ("POST", "/api/oauth/revoke") => {
            if let Some(token) = json_body()["token"].as_str() {
                s.revoked_tokens.push(token.to_string());
                if Some(token) == s.refresh.as_deref() {
                    s.revoked = true;
                }
            }
            ("200 OK", "{}".to_string())
        }
        (_, "/api/irminsul/whoami") | (_, "/api/irminsul/import") => {
            if s.revoked {
                return (
                    "401 Unauthorized",
                    r#"{"error":{"code":"session_revoked"}}"#.to_string(),
                );
            }
            if s.block_uploads {
                return (
                    "403 Forbidden",
                    r#"{"error":{"code":"uploads_blocked","message":"Uploads are blocked for this account"}}"#
                        .to_string(),
                );
            }
            if s.expire_access {
                s.expire_access = false;
                s.access = None;
                return (
                    "401 Unauthorized",
                    r#"{"error":{"code":"token_expired"}}"#.to_string(),
                );
            }
            if !bearer_ok(&s) {
                return (
                    "401 Unauthorized",
                    r#"{"error":{"code":"token_expired"}}"#.to_string(),
                );
            }
            if request.path.ends_with("whoami") {
                ("200 OK", whoami_json(&s.whoami_scope).to_string())
            } else {
                let body = String::from_utf8_lossy(&request.body).into_owned();
                assert!(
                    request
                        .headers
                        .get("content-type")
                        .is_some_and(|ct| ct.starts_with("multipart/form-data")),
                    "the import is multipart"
                );
                s.imports.push(body);
                ("200 OK", r#"{"status":"ok"}"#.to_string())
            }
        }
        _ => {
            let _ = &request.query;
            ("404 Not Found", r#"{"error":"not_found"}"#.to_string())
        }
    }
}

fn client() -> reqwest::Client {
    crate::http_client_builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

/// A "browser" for [`TrackerAuth`]'s opener: what the user does with the
/// page that opened.
#[derive(Clone, Copy)]
enum Browser {
    /// Allow on the consent screen.
    Allow,
    /// Cancel on the consent screen.
    Deny,
    /// Another page sends a callback with a forged state.
    ForgedState,
    /// Nothing ever comes back.
    Nothing,
}

struct Harness {
    auth: TrackerAuth,
    store: Arc<MemoryStore>,
    opened: Arc<AtomicUsize>,
}

fn harness(base: &str, tracker: Option<Arc<FakeTracker>>, browser: Browser) -> Harness {
    let store = Arc::new(MemoryStore::default());
    let opened = Arc::new(AtomicUsize::new(0));
    let opened_count = Arc::clone(&opened);
    let opener: Opener = Arc::new(move |link: String| {
        opened_count.fetch_add(1, Ordering::SeqCst);
        let tracker = tracker.clone();
        tokio::spawn(async move {
            let redirect = match (browser, &tracker) {
                (Browser::Allow, Some(tracker)) => tracker.authorize(&link),
                (Browser::Deny, _) => {
                    let url = Url::parse(&link).unwrap();
                    let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
                    format!(
                        "{}?error=access_denied&state={}",
                        q["redirect_uri"], q["state"]
                    )
                }
                (Browser::ForgedState, Some(tracker)) => {
                    let redirect = tracker.authorize(&link);
                    let (before, _) = redirect.split_once("&state=").unwrap();
                    format!("{before}&state=forged")
                }
                _ => return,
            };
            let page = client().get(&redirect).send().await.unwrap();
            assert!(page.status().is_success());
        });
    });
    let auth = TrackerAuth::new(
        base,
        store.clone(),
        "TEST-PC".to_string(),
        opener,
        Arc::new(|| {}),
    );
    Harness {
        auth,
        store,
        opened,
    }
}

fn stored(h: &Harness, origin: &str) -> Option<String> {
    h.store.tokens.lock().unwrap().get(origin).cloned()
}

fn status(h: &Harness) -> AuthStatus {
    h.auth.status().borrow().clone()
}

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sign_in_upload_refresh_and_sign_out_end_to_end() {
    let tracker = Arc::new(FakeTracker::start().await);
    let h = harness(&tracker.base, Some(Arc::clone(&tracker)), Browser::Allow);
    let client = client();

    h.auth.load(&client).await;
    assert_eq!(status(&h), AuthStatus::SignedOut { notice: None });

    h.auth.sign_in(&client).await;
    assert_eq!(h.opened.load(Ordering::SeqCst), 1);
    let AuthStatus::SignedIn { whoami, error } = status(&h) else {
        panic!("not signed in: {:?}", status(&h));
    };
    assert_eq!(error, None);
    assert_eq!(whoami.unwrap().user, "traveler");
    // The refresh token is in the store, keyed by origin.
    assert_eq!(stored(&h, &tracker.origin()).as_deref(), Some("refresh-2"));

    // An upload goes with the access token to the signed-in route.
    h.auth
        .upload(
            &client,
            &tracker.base,
            r#"{"format":"GOOD"}"#.into(),
            Some(1_700_000_000_000),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    {
        let state = tracker.state();
        let import = state.imports.last().unwrap();
        assert!(import.contains("irminsul_capture.json"), "{import}");
        assert!(import.contains("1700000000000"), "{import}");
        assert!(import.contains(r#"{"format":"GOOD"}"#), "{import}");
        let (_, _, auth) = state
            .requests
            .iter()
            .rfind(|(_, path, _)| path == "/api/irminsul/import")
            .unwrap();
        assert_eq!(auth.as_deref(), Some("Bearer access-2"));
    }

    // The access token expires: whoami gets 401 token_expired, refreshes
    // (rotating the refresh token in the store), and retries once.
    tracker.state().expire_access = true;
    h.auth.refresh_whoami(&client).await;
    assert!(status(&h).is_signed_in(), "{:?}", status(&h));
    assert_eq!(stored(&h, &tracker.origin()).as_deref(), Some("refresh-3"));

    // Sign out revokes the current refresh token and deletes it.
    h.auth.sign_out(&client).await;
    assert_eq!(status(&h), AuthStatus::SignedOut { notice: None });
    assert_eq!(stored(&h, &tracker.origin()), None);
    assert_eq!(
        tracker.state().revoked_tokens,
        vec!["refresh-3".to_string()]
    );

    // And nothing uploads any more.
    let err = h
        .auth
        .upload(
            &client,
            &tracker.base,
            "{}".into(),
            None,
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert_eq!(err, SIGNED_OUT_NOTICE);
}

#[tokio::test]
async fn a_saved_sign_in_loads_and_reads_whoami() {
    let tracker = Arc::new(FakeTracker::start().await);
    tracker.state().refresh = Some("refresh-saved".to_string());
    tracker.state().whoami_scope = "account".to_string();
    let h = harness(&tracker.base, None, Browser::Nothing);
    h.store.save(&tracker.origin(), "refresh-saved").unwrap();
    let client = client();

    h.auth.load(&client).await;
    let AuthStatus::SignedIn { whoami, error } = status(&h) else {
        panic!("not signed in: {:?}", status(&h));
    };
    assert_eq!(error, None);
    let whoami = whoami.unwrap();
    assert_eq!(whoami.scope, UploadScope::Account);
    assert_eq!(whoami.target_label(), "Main (UID 811111111)");
    // Loading refreshed (no access token survives a restart) and rotated.
    assert_eq!(stored(&h, &tracker.origin()).as_deref(), Some("refresh-1"));
}

#[tokio::test]
async fn a_refresh_the_tracker_refuses_signs_out() {
    let tracker = Arc::new(FakeTracker::start().await);
    // The stored token was rotated away or its session ended.
    tracker.state().refresh = Some("refresh-newer".to_string());
    let h = harness(&tracker.base, None, Browser::Nothing);
    h.store.save(&tracker.origin(), "refresh-old").unwrap();
    let client = client();

    h.auth.load(&client).await;
    assert_eq!(
        status(&h),
        AuthStatus::SignedOut {
            notice: Some(SIGNED_OUT_NOTICE.to_string())
        }
    );
    assert_eq!(stored(&h, &tracker.origin()), None);
}

#[tokio::test]
async fn a_revoked_session_signs_out_on_its_next_request() {
    let tracker = Arc::new(FakeTracker::start().await);
    let h = harness(&tracker.base, Some(Arc::clone(&tracker)), Browser::Allow);
    let client = client();
    h.auth.load(&client).await;
    h.auth.sign_in(&client).await;
    assert!(status(&h).is_signed_in());

    // Ended on the tracker's Devices page.
    tracker.state().revoked = true;
    let err = h
        .auth
        .upload(
            &client,
            &tracker.base,
            "{}".into(),
            None,
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert_eq!(err, SIGNED_OUT_NOTICE);
    assert_eq!(
        status(&h),
        AuthStatus::SignedOut {
            notice: Some(SIGNED_OUT_NOTICE.to_string())
        }
    );
    assert_eq!(stored(&h, &tracker.origin()), None);
}

#[tokio::test]
async fn a_forged_state_never_reaches_the_token_endpoint() {
    let tracker = Arc::new(FakeTracker::start().await);
    let h = harness(
        &tracker.base,
        Some(Arc::clone(&tracker)),
        Browser::ForgedState,
    );
    let client = client();
    h.auth.load(&client).await;
    h.auth.sign_in(&client).await;

    assert!(
        matches!(status(&h), AuthStatus::SignedOut { notice: Some(_) }),
        "{:?}",
        status(&h)
    );
    assert!(
        !tracker
            .state()
            .requests
            .iter()
            .any(|(_, path, _)| path == "/api/oauth/token")
    );
    assert_eq!(stored(&h, &tracker.origin()), None);
}

#[tokio::test]
async fn a_cancel_on_the_consent_screen_leaves_the_user_signed_out() {
    let tracker = Arc::new(FakeTracker::start().await);
    let h = harness(&tracker.base, Some(Arc::clone(&tracker)), Browser::Deny);
    let client = client();
    h.auth.load(&client).await;
    h.auth.sign_in(&client).await;
    assert!(matches!(
        status(&h),
        AuthStatus::SignedOut { notice: Some(_) }
    ));
    assert_eq!(stored(&h, &tracker.origin()), None);
}

#[tokio::test]
async fn cancelling_a_sign_in_stops_waiting_without_a_notice() {
    let tracker = Arc::new(FakeTracker::start().await);
    let h = harness(&tracker.base, None, Browser::Nothing);
    let client = client();
    h.auth.load(&client).await;

    let auth = h.auth.clone();
    let task = tokio::spawn({
        let client = client.clone();
        async move { auth.sign_in(&client).await }
    });
    // Wait until the browser was opened, then cancel.
    let mut rx = h.auth.status();
    rx.wait_for(|s| matches!(s, AuthStatus::Waiting { link: Some(_) }))
        .await
        .unwrap();
    let AuthStatus::Waiting { link: Some(link) } = status(&h) else {
        unreachable!()
    };
    let port: u16 = Url::parse(
        &Url::parse(&link)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "redirect_uri")
            .unwrap()
            .1,
    )
    .unwrap()
    .port()
    .unwrap();
    h.auth.cancel_sign_in();
    task.await.unwrap();
    assert_eq!(status(&h), AuthStatus::SignedOut { notice: None });
    // The listener is gone with the sign-in.
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
}

#[tokio::test]
async fn a_discovery_pointing_tokens_elsewhere_stops_before_the_browser() {
    let tracker = Arc::new(FakeTracker::start().await);
    tracker.state().foreign_token_url = true;
    let h = harness(&tracker.base, Some(Arc::clone(&tracker)), Browser::Allow);
    let client = client();
    h.auth.load(&client).await;
    h.auth.sign_in(&client).await;
    assert_eq!(h.opened.load(Ordering::SeqCst), 0);
    assert!(matches!(
        status(&h),
        AuthStatus::SignedOut { notice: Some(_) }
    ));
}

#[tokio::test]
async fn changing_the_address_signs_out_of_the_old_one_and_never_sends_its_token_on() {
    let old = Arc::new(FakeTracker::start().await);
    let new = Arc::new(FakeTracker::start().await);
    let h = harness(&old.base, Some(Arc::clone(&old)), Browser::Allow);
    let client = client();
    h.auth.load(&client).await;
    h.auth.sign_in(&client).await;
    assert!(status(&h).is_signed_in());
    let old_refresh = stored(&h, &old.origin()).unwrap();

    h.auth.set_address(&client, &new.base).await;

    // Signed out of the old tracker: revoked there, deleted here.
    assert_eq!(old.state().revoked_tokens, vec![old_refresh]);
    assert_eq!(stored(&h, &old.origin()), None);
    // Not signed in to the new one, and nothing goes there with a token.
    assert_eq!(status(&h), AuthStatus::SignedOut { notice: None });
    let err = h
        .auth
        .upload(
            &client,
            &new.base,
            "{}".into(),
            None,
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert_eq!(err, SIGNED_OUT_NOTICE);
    h.auth.refresh_whoami(&client).await;
    assert!(!new.saw_bearer_anywhere());
    assert!(
        !new.state()
            .requests
            .iter()
            .any(|(_, path, _)| path.starts_with("/api/oauth/token")
                || path.starts_with("/api/oauth/revoke"))
    );

    // The same address again (modulo a trailing slash) is not a change.
    let before = new.state().requests.len();
    h.auth.set_address(&client, &format!("{}/", new.base)).await;
    assert_eq!(new.state().requests.len(), before);
}

#[tokio::test]
async fn a_sign_in_saved_for_the_new_address_is_picked_up() {
    let old = Arc::new(FakeTracker::start().await);
    let new = Arc::new(FakeTracker::start().await);
    new.state().refresh = Some("refresh-new".to_string());
    let h = harness(&old.base, None, Browser::Nothing);
    h.store.save(&new.origin(), "refresh-new").unwrap();
    let client = client();
    h.auth.load(&client).await;
    assert!(!status(&h).is_signed_in());

    h.auth.set_address(&client, &new.base).await;
    assert!(status(&h).is_signed_in(), "{:?}", status(&h));
    assert!(!old.saw_bearer_anywhere());
}

#[tokio::test]
async fn an_upload_meant_for_another_address_is_not_sent_with_this_token() {
    let tracker = Arc::new(FakeTracker::start().await);
    let h = harness(&tracker.base, Some(Arc::clone(&tracker)), Browser::Allow);
    let client = client();
    h.auth.load(&client).await;
    h.auth.sign_in(&client).await;
    assert!(status(&h).is_signed_in());

    // The UI already points at another tracker; the session has not moved.
    let err = h
        .auth
        .upload(
            &client,
            "https://gdt.example/api",
            "{}".into(),
            None,
            Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    assert!(err.contains("address changed"), "{err}");
    assert!(tracker.state().imports.is_empty());
    // A trailing slash is the same address.
    h.auth
        .upload(
            &client,
            &format!("{}/", tracker.base),
            "{}".into(),
            None,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    assert_eq!(tracker.state().imports.len(), 1);
}

#[test]
fn a_deleted_upload_target_reads_as_not_chosen() {
    let mut json = whoami_json("account");
    for field in ["accountId", "accountName", "uid", "server"] {
        json[field] = serde_json::Value::Null;
    }
    let whoami = parse_whoami(&json).unwrap();
    assert_eq!(whoami.scope, UploadScope::Account);
    assert_eq!(whoami.target_label(), "Not chosen");
    // Configure is still offered.
    assert!(whoami.config_url.is_some());
}

#[test]
fn an_account_without_a_name_is_called_by_its_uid() {
    // What the tracker answers for an account it made for a new UID
    // (seen against a real tracker: `src/signin/e2e.rs`).
    let mut json = whoami_json("account");
    json["accountName"] = serde_json::Value::Null;
    json["uid"] = serde_json::json!("812345678");
    let whoami = parse_whoami(&json).unwrap();
    assert_eq!(whoami.target_label(), "UID 812345678");
    json["accountName"] = serde_json::json!("Main");
    assert_eq!(
        parse_whoami(&json).unwrap().target_label(),
        "Main (UID 812345678)"
    );
}

#[test]
fn a_failed_request_says_the_trackers_own_sentence() {
    let body = r#"{"error":{"code":"upload_target_missing","message":"The account this PC uploads to was deleted."}}"#;
    assert_eq!(
        http_failure(StatusCode::CONFLICT, body),
        "HTTP 409 Conflict - The account this PC uploads to was deleted."
    );
    assert_eq!(
        http_failure(StatusCode::BAD_GATEWAY, "<html>"),
        "HTTP 502 Bad Gateway - <html>"
    );
}

#[test]
fn a_rate_limited_refresh_is_not_a_sign_out() {
    assert_eq!(
        parse_token_response(429, r#"{"error":"rate_limited"}"#).err(),
        Some(TokenError::Rejected {
            status: 429,
            error: "rate_limited".to_string()
        })
    );
}

#[tokio::test]
async fn concurrent_requests_share_one_refresh() {
    let tracker = Arc::new(FakeTracker::start().await);
    let h = harness(&tracker.base, Some(Arc::clone(&tracker)), Browser::Allow);
    let client = client();
    h.auth.load(&client).await;
    h.auth.sign_in(&client).await;
    assert!(status(&h).is_signed_in());

    // The access token lapsed: every request below needs a refresh, and
    // refresh tokens rotate (reusing one ends the session on the tracker).
    h.auth.inner.session.lock().await.access = None;
    let uploads = (0..4).map(|_| {
        let auth = h.auth.clone();
        let client = client.clone();
        let base = tracker.base.clone();
        tokio::spawn(async move {
            auth.upload(&client, &base, "{}".into(), None, Duration::from_secs(10))
                .await
        })
    });
    for upload in uploads.collect::<Vec<_>>() {
        upload.await.unwrap().unwrap();
    }
    let state = tracker.state();
    assert_eq!(state.refresh_grants, 1);
    assert!(!state.revoked);
    assert_eq!(state.imports.len(), 4);
    // The rotated token was saved before it was used.
    assert_eq!(stored(&h, &tracker.origin()), state.refresh.clone());
}

#[tokio::test]
async fn blocked_uploads_are_shown_but_keep_the_sign_in() {
    let tracker = Arc::new(FakeTracker::start().await);
    let h = harness(&tracker.base, Some(Arc::clone(&tracker)), Browser::Allow);
    let client = client();
    h.auth.load(&client).await;
    h.auth.sign_in(&client).await;

    tracker.state().block_uploads = true;
    h.auth.refresh_whoami(&client).await;
    let AuthStatus::SignedIn { whoami, error } = status(&h) else {
        panic!("signed out: {:?}", status(&h));
    };
    assert!(whoami.is_some(), "the last answer is kept");
    assert_eq!(
        error.as_deref(),
        Some("HTTP 403 Forbidden - Uploads are blocked for this account")
    );
    assert!(stored(&h, &tracker.origin()).is_some());
}
