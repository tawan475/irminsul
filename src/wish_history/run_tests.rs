//! The sync run against a fake wish history API and a fake tracker, both
//! served in process by [`TestServer`]. Every record and key here is
//! synthetic (UID 811111111).

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::Banner;
use super::gacha_log::{LogClient, Pacing, Sleeper, WishKey};
use super::run::{Partial, Run, RunError, RunReport};
use super::test_server::{Reply, Request, TestServer};
use super::tracker::{Tracker, TrackerCredential};
use crate::signin::{MemoryStore, TrackerAuth};

const AUTHKEY: &str = "SyNtHeTiCwIsHkEy+0123456789/abcdefghij==";
const IMPORT_KEY: &str = "gdt_uk_synthetic";
const UID: &str = "811111111";
const LOG_PATH: &str = "/gacha_info/api/getGachaLog";

fn id_of(banner: Banner, index: u64) -> u64 {
    // Newest first: index 0 is the newest record of the banner.
    1_790_000_000_000_000_000 + u64::from(banner) * 100_000 - index
}

/// A record's time: newest first, ten records (a ten-pull) per second, a
/// minute between ten-pulls. Index 0..9 is `2026-10-12 21:04:11`.
fn time_of(index: u64) -> String {
    let newest =
        chrono::NaiveDateTime::parse_from_str("2026-10-12 21:04:11", "%Y-%m-%d %H:%M:%S").unwrap();
    let minutes = i64::try_from(index / 10).unwrap();
    (newest - chrono::Duration::minutes(minutes))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

fn record(banner: Banner, index: u64, uid: &str) -> Value {
    let gacha_type = if banner == 301 && index % 2 == 1 {
        "400".to_owned()
    } else {
        banner.to_string()
    };
    json!({
        "uid": uid, "gacha_type": gacha_type, "item_id": "", "count": "1",
        "time": time_of(index), "name": format!("Item {index}"), "lang": "en-us",
        "item_type": "Weapon", "rank_type": "3", "id": id_of(banner, index).to_string(),
    })
}

/// What the fake API and tracker hold and do.
struct World {
    history: BTreeMap<Banner, Vec<Value>>,
    /// The tracker's newest id per banner.
    newest: BTreeMap<Banner, u64>,
    /// The tracker's newest wish time per banner (`newestTime`); none sent
    /// while empty, like an older tracker.
    newest_time: BTreeMap<Banner, String>,
    /// Answers to override, by the number of the log request (1-based).
    faults: BTreeMap<usize, Reply>,
    /// The tracker's answer to the cursor, if not the cursor.
    cursor_reply: Option<Reply>,
    import_status: u16,
    log_requests: usize,
    /// The server's own address, for the sign-in discovery.
    base: String,
    /// Whether the wish routes want the sign-in's bearer token.
    bearer: bool,
    /// Access tokens issued (`at-<n>`); only the newest is accepted.
    issued: u32,
    /// One-off answers for tracker routes, by path.
    tracker_faults: Vec<(&'static str, Reply)>,
}

impl World {
    fn new(counts: &[(Banner, u64)]) -> Self {
        let history = counts
            .iter()
            .map(|&(banner, count)| {
                (
                    banner,
                    (0..count).map(|index| record(banner, index, UID)).collect(),
                )
            })
            .collect();
        Self {
            history,
            newest: BTreeMap::new(),
            newest_time: BTreeMap::new(),
            faults: BTreeMap::new(),
            cursor_reply: None,
            import_status: 200,
            log_requests: 0,
            base: String::new(),
            bearer: false,
            issued: 0,
            tracker_faults: Vec::new(),
        }
    }

    fn answer(&mut self, request: &Request) -> Reply {
        if request.path == LOG_PATH {
            self.log_requests += 1;
            if let Some(reply) = self.faults.remove(&self.log_requests) {
                return reply;
            }
            let banner: Banner = request.param("gacha_type").unwrap().parse().unwrap();
            let size: usize = request.param("size").unwrap().parse().unwrap();
            let end_id: u64 = request.param("end_id").unwrap().parse().unwrap();
            let list: Vec<Value> = self
                .history
                .get(&banner)
                .into_iter()
                .flatten()
                .filter(|record| {
                    end_id == 0 || record["id"].as_str().unwrap().parse::<u64>().unwrap() < end_id
                })
                .take(size)
                .cloned()
                .collect();
            return Reply::json(
                200,
                json!({"retcode": 0, "message": "OK", "data": {
                    "page": request.param("page").unwrap(), "size": size.to_string(),
                    "region": "os_asia", "list": list,
                }})
                .to_string(),
            );
        }
        if request.path.starts_with("/api/wishes/") {
            if let Some(at) = self
                .tracker_faults
                .iter()
                .position(|(path, _)| *path == request.path)
            {
                return self.tracker_faults.remove(at).1;
            }
            if self.bearer {
                let expected = format!("Bearer at-{}", self.issued);
                if request.header("authorization") != Some(expected.as_str()) {
                    return Reply::json(401, r#"{"error":{"code":"token_expired"}}"#);
                }
            }
        }
        if request.path == "/api/oauth/irminsul" {
            let base = &self.base;
            return Reply::json(
                200,
                json!({
                    "authorize_url": format!("{base}/link"),
                    "token_url": format!("{base}/api/oauth/token"),
                    "revoke_url": format!("{base}/api/oauth/revoke"),
                    "client_id": "irminsul", "version": 1,
                })
                .to_string(),
            );
        }
        if request.path == "/api/oauth/token" {
            self.issued += 1;
            let n = self.issued;
            return Reply::json(
                200,
                json!({
                    "token_type": "Bearer", "access_token": format!("at-{n}"), "expires_in": 900,
                    "refresh_token": format!("rt-{n}"), "refresh_expires_in": 2_592_000,
                })
                .to_string(),
            );
        }
        if request.path == "/api/irminsul/whoami" {
            return Reply::json(
                200,
                json!({"scope": "uid", "user": "player01", "accountId": null,
                       "dashboardUrl": format!("{}/app", self.base)})
                .to_string(),
            );
        }
        if request.path == "/api/wishes/cursor" {
            if let Some(reply) = self.cursor_reply.take() {
                return reply;
            }
            let mut newest = serde_json::Map::new();
            for banner in super::BANNERS {
                let value = match self.newest.get(&banner) {
                    Some(id) => Value::String(id.to_string()),
                    None => Value::Null,
                };
                newest.insert(banner.to_string(), value);
            }
            let mut answer =
                json!({"uid": request.param("uid"), "accountId": 12, "newest": newest});
            if !self.newest_time.is_empty() {
                answer["newestTime"] = json!(self.newest_time);
            }
            return Reply::json(200, answer.to_string());
        }
        if request.path == "/api/wishes/import" {
            if self.import_status != 200 {
                return Reply::json(
                    self.import_status,
                    r#"{"error":{"code":"daily_upload_limit","message":"Try again tomorrow"}}"#,
                );
            }
            let body: Value = serde_json::from_str(&request.body).unwrap();
            let records = body["records"].as_array().unwrap();
            for record in records {
                let id: u64 = record["id"].as_str().unwrap().parse().unwrap();
                let banner = match record["gacha_type"].as_str().unwrap() {
                    "400" => 301,
                    other => other.parse().unwrap(),
                };
                let newest = self.newest.entry(banner).or_insert(0);
                *newest = (*newest).max(id);
            }
            return Reply::json(
                200,
                json!({"accountId": 12, "added": records.len(), "known": 0, "newest": {}})
                    .to_string(),
            );
        }
        Reply::json(404, r#"{"error":{"code":"not_found"}}"#)
    }
}

/// Waits nothing, remembers what it was asked to wait.
#[derive(Clone, Default)]
struct RecordingSleeper(Arc<Mutex<Vec<Duration>>>);

impl Sleeper for RecordingSleeper {
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send {
        self.0.lock().unwrap().push(duration);
        std::future::ready(())
    }
}

impl RecordingSleeper {
    fn waits(&self) -> Vec<Duration> {
        self.0.lock().unwrap().clone()
    }
}

struct Fixture {
    world: Arc<Mutex<World>>,
    server: TestServer,
    sleeper: RecordingSleeper,
    partials: BTreeMap<Banner, Partial>,
    page_cap: u32,
    /// `None`: the import key.
    credential: Option<TrackerCredential>,
}

impl Fixture {
    fn new(world: World) -> Self {
        let world = Arc::new(Mutex::new(world));
        let served = Arc::clone(&world);
        let server = TestServer::start(move |request| served.lock().unwrap().answer(request));
        Self {
            world,
            server,
            sleeper: RecordingSleeper::default(),
            partials: BTreeMap::new(),
            page_cap: super::run::PAGES_PER_RUN,
            credential: None,
        }
    }

    /// A fixture whose wish routes want the sign-in, and a sign-in that has
    /// read its saved refresh token (and so holds access token `at-1`).
    async fn signed_in(mut world: World) -> (Self, TrackerAuth) {
        world.bearer = true;
        let mut fixture = Self::new(world);
        let base = fixture.server.base.clone();
        fixture.world().base = base.clone();
        let api = format!("{base}/api");
        let store = Arc::new(MemoryStore::default());
        store
            .tokens
            .lock()
            .unwrap()
            .insert(base.clone(), "rt-0".to_owned());
        let auth = TrackerAuth::new(
            &api,
            store,
            "TEST-PC".to_owned(),
            Arc::new(|_| {}),
            Arc::new(|| {}),
        );
        auth.load(&crate::http_client_builder().build().unwrap())
            .await;
        assert!(auth.status().borrow().is_signed_in());
        assert_eq!(fixture.world().issued, 1);
        fixture.credential = Some(TrackerCredential::SignedIn {
            auth: auth.clone(),
            base: api,
        });
        (fixture, auth)
    }

    fn world(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    async fn run(&mut self, banners: &[Banner]) -> RunReport {
        capture_logs();
        let http = crate::http_client_builder().build().unwrap();
        let mut log = LogClient::new(
            http.clone(),
            format!("{}{LOG_PATH}", self.server.base),
            WishKey::new(AUTHKEY, "hk4e_global", Instant::now()),
            self.sleeper.clone(),
            Pacing {
                request: Duration::from_secs(1),
                banner: Duration::from_secs(2),
                backoff: vec![Duration::from_secs(5), Duration::from_secs(15)],
            },
        );
        let tracker = Tracker {
            http,
            base_url: format!("{}/api/", self.server.base),
            credential: self
                .credential
                .clone()
                .unwrap_or_else(|| TrackerCredential::ImportKey(IMPORT_KEY.to_owned())),
        };
        let progress = |_: Banner, _: u32| {};
        let report = Run::new(&mut log, &tracker, &progress, self.page_cap)
            .sync(banners, &mut self.partials)
            .await;
        // No key anywhere: not in the outcome, not in a log line, not in
        // anything sent to the tracker.
        let rendered = format!("{report:?} {:?}", self.partials);
        assert!(!rendered.contains("SyNtHeTiC"), "{rendered}");
        assert!(
            !logs().contains("SyNtHeTiC"),
            "the key reached the log: {}",
            logs()
        );
        for request in self.requests("/api/") {
            assert!(!request.raw().contains("SyNtHeTiC"), "{}", request.raw());
        }
        report
    }

    fn requests(&self, prefix: &str) -> Vec<Request> {
        self.server
            .requests()
            .into_iter()
            .filter(|request| request.path.starts_with(prefix))
            .collect()
    }

    fn log_requests(&self) -> Vec<(Banner, u32, u64)> {
        self.requests(LOG_PATH)
            .iter()
            .map(|request| {
                (
                    request.param("gacha_type").unwrap().parse().unwrap(),
                    request.param("page").unwrap().parse().unwrap(),
                    request.param("end_id").unwrap().parse().unwrap(),
                )
            })
            .collect()
    }

    fn imports(&self) -> Vec<Value> {
        self.requests("/api/wishes/import")
            .iter()
            .map(|request| serde_json::from_str(&request.body).unwrap())
            .collect()
    }

    fn imported_ids(&self) -> Vec<u64> {
        self.imports()
            .iter()
            .flat_map(|body| body["records"].as_array().unwrap().clone())
            .map(|record| record["id"].as_str().unwrap().parse().unwrap())
            .collect()
    }
}

/// Every log line of the test binary, whichever test logged it.
fn logs() -> String {
    String::from_utf8_lossy(&LOGS.lock().unwrap()).into_owned()
}

static LOGS: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct LogWriter;

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOGS.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Route every event at every level to [`LOGS`].
fn capture_logs() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(|| LogWriter)
            .with_ansi(false)
            .try_init();
    });
}

const ALL: [Banner; 5] = super::BANNERS;

#[tokio::test]
async fn one_page_per_banner_when_nothing_is_new() {
    let mut world = World::new(&[(301, 30), (200, 5)]);
    world.newest.insert(301, id_of(301, 0));
    world.newest.insert(200, id_of(200, 0));
    let mut fixture = Fixture::new(world);

    let report = fixture.run(&ALL).await;

    assert_eq!(report.error, None);
    assert_eq!(report.sent, 0);
    assert_eq!(
        fixture.log_requests(),
        vec![
            (301, 1, 0),
            (302, 1, 0),
            (500, 1, 0),
            (200, 1, 0),
            (100, 1, 0)
        ]
    );
    assert_eq!(fixture.requests("/api/wishes/cursor").len(), 1);
    assert!(fixture.imports().is_empty());
    // A second between pages would be owed; between banners it is two.
    assert_eq!(fixture.sleeper.waits(), vec![Duration::from_secs(2); 4]);
}

#[tokio::test]
async fn pages_until_a_record_the_tracker_has_and_sends_only_the_new_ones() {
    let mut world = World::new(&[(301, 45)]);
    world.newest.insert(301, id_of(301, 42));
    let mut fixture = Fixture::new(world);

    let report = fixture.run(&[301]).await;

    assert_eq!(report.error, None);
    assert_eq!(report.sent, 42);
    assert_eq!(report.imported.added, 42);
    assert_eq!(report.uid.as_deref(), Some(UID));
    assert_eq!(
        fixture.log_requests(),
        vec![
            (301, 1, 0),
            (301, 2, id_of(301, 19)),
            (301, 3, id_of(301, 39)),
        ]
    );
    assert_eq!(
        fixture.sleeper.waits(),
        vec![Duration::from_secs(1), Duration::from_secs(1)]
    );

    // Oldest first, exactly the 42 new ones.
    let ids = fixture.imported_ids();
    let expected: Vec<u64> = (0..42).rev().map(|index| id_of(301, index)).collect();
    assert_eq!(ids, expected);

    let cursor = &fixture.requests("/api/wishes/cursor")[0];
    assert_eq!(cursor.param("uid"), Some(UID));
    assert_eq!(cursor.header("x-import-key"), Some(IMPORT_KEY));
    let import = &fixture.requests("/api/wishes/import")[0];
    assert_eq!(import.header("x-import-key"), Some(IMPORT_KEY));
    assert_eq!(import.method, "POST");
}

#[tokio::test]
async fn the_import_body_follows_the_contract() {
    let mut fixture = Fixture::new(World::new(&[(301, 2)]));
    fixture.run(&[301]).await;

    let body = &fixture.imports()[0];
    assert_eq!(body["uid"], UID);
    assert_eq!(body["region"], "os_asia");
    assert_eq!(body["lang"], "en-us");
    assert_eq!(body["timezone"], 8);
    // The older record is the 400 one, and it keeps its own banner type.
    assert_eq!(
        body["records"][0],
        json!({
            "id": id_of(301, 1).to_string(), "gacha_type": "400",
            "time": "2026-10-12 21:04:11", "name": "Item 1", "item_type": "Weapon",
            "rank_type": "3", "item_id": "",
        })
    );
    assert_eq!(body["records"][1]["gacha_type"], "301");
    let keys: Vec<&String> = body.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 5, "{keys:?}");
}

#[tokio::test]
async fn an_empty_page_ends_a_banner_the_tracker_has_nothing_of() {
    let mut fixture = Fixture::new(World::new(&[(302, 30)]));

    let report = fixture.run(&[302]).await;

    assert_eq!(report.error, None);
    assert_eq!(report.sent, 30);
    assert_eq!(
        fixture.log_requests(),
        vec![
            (302, 1, 0),
            (302, 2, id_of(302, 19)),
            (302, 3, id_of(302, 29)),
        ]
    );
}

#[tokio::test]
async fn an_expired_key_stops_the_run_and_the_next_key_finishes_without_a_gap() {
    let mut world = World::new(&[(301, 45), (302, 3)]);
    world.faults.insert(
        2,
        Reply::json(
            200,
            r#"{"retcode":-101,"message":"authkey timeout","data":null}"#,
        ),
    );
    let mut fixture = Fixture::new(world);

    let report = fixture.run(&[301, 302]).await;

    assert_eq!(report.error, Some(RunError::KeyExpired));
    // Half a banner is not sent: the tracker would then hide the other half.
    assert!(fixture.imports().is_empty());
    assert_eq!(report.unfinished, vec![301]);
    assert_eq!(fixture.log_requests().len(), 2, "nothing after the timeout");

    let report = fixture.run(&[301, 302]).await;

    assert_eq!(report.error, None);
    assert_eq!(report.sent, 48);
    assert!(report.unfinished.is_empty());
    let mut ids = fixture.imported_ids();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 48);
    // The second run read page 1 to see what is new above the part it had,
    // then carried on from where the first run stopped.
    assert_eq!(
        fixture.log_requests()[2..5],
        [
            (301, 1, 0),
            (301, 2, id_of(301, 19)),
            (301, 3, id_of(301, 39)),
        ]
    );
}

#[tokio::test]
async fn the_page_cap_hands_the_rest_to_the_next_run() {
    let mut fixture = Fixture::new(World::new(&[(301, 50)]));
    fixture.page_cap = 2;

    let report = fixture.run(&[301]).await;

    assert_eq!(report.error, None);
    assert_eq!(report.sent, 0);
    assert_eq!(report.unfinished, vec![301]);
    assert_eq!(fixture.log_requests().len(), 2);

    let report = fixture.run(&[301]).await;

    assert_eq!(report.sent, 50);
    assert!(report.unfinished.is_empty());
    assert_eq!(
        fixture.log_requests()[2..],
        [
            (301, 1, 0),
            (301, 3, id_of(301, 39)),
            (301, 4, id_of(301, 49)),
        ]
    );
}

#[tokio::test]
async fn new_wishes_above_an_unfinished_part_are_read_first() {
    let mut fixture = Fixture::new(World::new(&[(301, 50)]));
    fixture.page_cap = 2;
    fixture.run(&[301]).await;

    // Three wishes are made before the next run.
    {
        let mut world = fixture.world();
        let records = world.history.get_mut(&301).unwrap();
        for extra in 1..=3u64 {
            let mut newer = record(301, 0, UID);
            newer["id"] = Value::String((id_of(301, 0) + extra).to_string());
            records.insert(0, newer);
        }
    }

    let report = fixture.run(&[301]).await;

    assert_eq!(report.sent, 53);
    let mut ids = fixture.imported_ids();
    ids.dedup();
    assert_eq!(ids.len(), 53);
}

#[tokio::test]
async fn throttling_backs_off_and_retries() {
    let mut world = World::new(&[(301, 3)]);
    world.faults.insert(
        1,
        Reply::json(
            200,
            r#"{"retcode":-110,"message":"visit too frequently","data":null}"#,
        ),
    );
    world.faults.insert(2, Reply::json(429, "{}"));
    let mut fixture = Fixture::new(world);

    let report = fixture.run(&[301]).await;

    assert_eq!(report.error, None);
    assert_eq!(report.sent, 3);
    assert_eq!(
        fixture.sleeper.waits(),
        vec![
            Duration::from_secs(5),
            Duration::from_secs(15),
            Duration::from_secs(1),
        ]
    );
    // The log capture works, so "no key in the log" above means something.
    assert!(logs().contains("retrying in 15s"), "{}", logs());
}

#[tokio::test]
async fn an_api_that_keeps_failing_ends_the_run_without_the_key_in_the_error() {
    let mut world = World::new(&[(301, 3)]);
    for n in 1..=3 {
        world.faults.insert(n, Reply::json(502, "bad gateway"));
    }
    let mut fixture = Fixture::new(world);

    let report = fixture.run(&[301, 302]).await;

    let Some(RunError::Api(why)) = &report.error else {
        panic!("expected an API error, got {:?}", report.error);
    };
    assert!(why.contains("502"), "{why}");
    assert_eq!(fixture.log_requests().len(), 3, "two retries, then give up");
    assert!(fixture.requests("/api/").is_empty());
}

#[tokio::test]
async fn records_of_two_uids_are_not_sent() {
    let mut world = World::new(&[(301, 3)]);
    world
        .history
        .get_mut(&301)
        .unwrap()
        .push(record(301, 3, "822222222"));
    let mut fixture = Fixture::new(world);

    let report = fixture.run(&[301]).await;

    assert!(
        matches!(report.error, Some(RunError::Data(_))),
        "{report:?}"
    );
    assert!(fixture.requests("/api/").is_empty());
}

#[tokio::test]
async fn a_tracker_refusal_stops_the_run_with_its_code() {
    let mut world = World::new(&[(301, 3), (302, 3)]);
    world.cursor_reply = Some(Reply::json(
        409,
        r#"{"error":{"code":"uid_mismatch","message":"This key is for another UID"}}"#,
    ));
    let mut fixture = Fixture::new(world);

    let report = fixture.run(&[301, 302]).await;

    assert_eq!(
        report.error,
        Some(RunError::Tracker(
            "tracker: the tracker account uploads go to has another UID".to_owned()
        ))
    );
    assert_eq!(fixture.log_requests(), vec![(301, 1, 0)]);
    assert!(fixture.imports().is_empty());
}

#[tokio::test]
async fn a_failed_import_keeps_nothing_it_did_not_send() {
    let mut world = World::new(&[(301, 50), (302, 3)]);
    world.import_status = 429;
    let mut fixture = Fixture::new(world);
    fixture.page_cap = 2;

    let report = fixture.run(&[301, 302]).await;

    assert!(
        matches!(&report.error, Some(RunError::Tracker(why)) if why.contains("upload limit")),
        "{report:?}"
    );
    // 301 stopped at the cap; with the import of 302 refused, the run keeps no
    // part of it, and the next run starts over from the tracker's cursor.
    assert!(fixture.partials.is_empty());
}

#[tokio::test]
async fn more_than_one_import_request_of_records_is_chunked_oldest_first() {
    let mut fixture = Fixture::new(World::new(&[(301, 2_050)]));
    fixture.page_cap = 200;

    let report = fixture.run(&[301]).await;

    assert_eq!(report.sent, 2_050);
    let imports = fixture.imports();
    assert_eq!(imports.len(), 2);
    assert_eq!(imports[0]["records"].as_array().unwrap().len(), 2_000);
    assert_eq!(imports[1]["records"].as_array().unwrap().len(), 50);
    let ids = fixture.imported_ids();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
}

// -- signed in -----------------------------------------------------------------

#[tokio::test]
async fn signed_in_the_wish_routes_get_the_sessions_bearer_token() {
    let (mut fixture, _auth) = Fixture::signed_in(World::new(&[(301, 3)])).await;

    let report = fixture.run(&[301]).await;

    assert_eq!(report.error, None);
    assert_eq!(report.sent, 3);
    for path in ["/api/wishes/cursor", "/api/wishes/import"] {
        let request = &fixture.requests(path)[0];
        assert_eq!(
            request.header("authorization"),
            Some("Bearer at-1"),
            "{path}"
        );
        assert_eq!(request.header("x-import-key"), None, "{path}");
    }
}

#[tokio::test]
async fn an_expired_access_token_is_refreshed_once_and_the_request_retried() {
    let (mut fixture, _auth) = Fixture::signed_in(World::new(&[(301, 3)])).await;
    // The tracker moved on: `at-1` is no longer accepted.
    fixture.world().issued += 1;

    let report = fixture.run(&[301]).await;

    assert_eq!(report.error, None);
    assert_eq!(report.sent, 3);
    // One refresh (through the sign-in, under its lock), then the retry.
    assert_eq!(fixture.requests("/api/oauth/token").len(), 2);
    let cursors = fixture.requests("/api/wishes/cursor");
    assert_eq!(cursors.len(), 2);
    assert_eq!(cursors[1].header("authorization"), Some("Bearer at-3"));
}

#[tokio::test]
async fn a_revoked_session_signs_out_and_ends_the_run() {
    let (mut fixture, auth) = Fixture::signed_in(World::new(&[(301, 3)])).await;
    fixture.world().tracker_faults.push((
        "/api/wishes/cursor",
        Reply::json(401, r#"{"error":{"code":"session_revoked"}}"#),
    ));

    let report = fixture.run(&[301]).await;

    assert_eq!(
        report.error,
        Some(RunError::Tracker(
            "tracker: signed out of the tracker; sign in again".to_owned()
        ))
    );
    assert!(!auth.status().borrow().is_signed_in());
    assert!(fixture.imports().is_empty());
}

#[tokio::test]
async fn the_trackers_refusals_end_the_run_in_words() {
    for (path, status, code, said) in [
        (
            "/api/wishes/import",
            409,
            "upload_target_missing",
            "tracker: the upload target no longer exists; choose one with Configure on the tracker",
        ),
        (
            "/api/wishes/cursor",
            409,
            "uid_mismatch",
            "tracker: the tracker account uploads go to has another UID",
        ),
        (
            "/api/wishes/cursor",
            403,
            "uploads_blocked",
            "tracker: uploads are blocked for this tracker account",
        ),
        (
            "/api/wishes/import",
            429,
            "rate_limited",
            "tracker: the tracker is busy; the next key or wish tries again",
        ),
    ] {
        let (mut fixture, auth) = Fixture::signed_in(World::new(&[(301, 3)])).await;
        fixture.world().tracker_faults.push((
            path,
            Reply::json(status, json!({"error": {"code": code}}).to_string()),
        ));

        let report = fixture.run(&[301]).await;

        assert_eq!(
            report.error,
            Some(RunError::Tracker(said.to_owned())),
            "{code}"
        );
        assert!(auth.status().borrow().is_signed_in(), "{code}");
    }
}

/// The ids sent, newest first, as indexes of `banner`'s history.
fn sent_indexes(fixture: &Fixture, banner: Banner) -> Vec<u64> {
    let mut indexes: Vec<u64> = fixture
        .imported_ids()
        .into_iter()
        .map(|id| u64::from(banner) * 100_000 + 1_790_000_000_000_000_000 - id)
        .collect();
    indexes.sort_unstable();
    indexes
}

#[tokio::test]
async fn a_history_the_tracker_got_from_a_backup_stops_at_its_newest_time() {
    // The tracker's history came from a paimon.moe backup: no real ids, only
    // the newest wish's time.
    let mut world = World::new(&[(301, 100), (200, 15), (500, 8)]);
    world.newest_time.insert(301, time_of(25));
    world.newest_time.insert(200, time_of(0));
    world
        .newest_time
        .insert(500, "2026-10-12 23:00:00".to_owned());
    let mut fixture = Fixture::new(world);

    let report = fixture.run(&[301, 200, 500]).await;

    assert_eq!(report.error, None);
    // 301: page 2 holds the first record older than the tracker's newest;
    // 200 and 500: page 1 already does, or is all older.
    assert_eq!(
        fixture.log_requests(),
        vec![
            (301, 1, 0),
            (301, 2, id_of(301, 19)),
            (200, 1, 0),
            (500, 1, 0)
        ]
    );
    // 301: everything newer, plus the ten-pull of the tracker's newest
    // second (20..29); 200: that second's ten-pull only; 500: nothing.
    let ids = fixture.imported_ids();
    let expected: Vec<u64> = (0..30)
        .map(|index| id_of(301, index))
        .chain((0..10).map(|index| id_of(200, index)))
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    let mut expected_sorted = expected;
    expected_sorted.sort_unstable();
    assert_eq!(sorted, expected_sorted);
    assert_eq!(report.sent, 40);
}

#[tokio::test]
async fn ids_and_times_together_stop_at_whichever_comes_first() {
    // The time comes first (index 30 is older than its second; id 50 later).
    let mut world = World::new(&[(301, 100)]);
    world.newest.insert(301, id_of(301, 50));
    world.newest_time.insert(301, time_of(25));
    let mut fixture = Fixture::new(world);
    fixture.run(&[301]).await;
    assert_eq!(fixture.log_requests().len(), 2);
    assert_eq!(sent_indexes(&fixture, 301), (0..30).collect::<Vec<_>>());

    // The id comes first.
    let mut world = World::new(&[(301, 100)]);
    world.newest.insert(301, id_of(301, 5));
    world.newest_time.insert(301, time_of(60));
    let mut fixture = Fixture::new(world);
    fixture.run(&[301]).await;
    assert_eq!(fixture.log_requests(), vec![(301, 1, 0)]);
    assert_eq!(sent_indexes(&fixture, 301), (0..5).collect::<Vec<_>>());
}

#[tokio::test]
async fn a_cursor_without_usable_times_stops_by_id_as_before() {
    for newest_time in [
        json!("2026-10-12 21:00:00"),
        json!({"301": "yesterday", "200": 17}),
        json!(null),
    ] {
        let mut world = World::new(&[(301, 45)]);
        world.cursor_reply = Some(Reply::json(
            200,
            json!({"uid": UID, "accountId": 12,
                   "newest": {"301": id_of(301, 42).to_string()},
                   "newestTime": newest_time})
            .to_string(),
        ));
        let mut fixture = Fixture::new(world);
        let report = fixture.run(&[301]).await;
        assert_eq!(report.error, None, "{newest_time}");
        assert_eq!(report.sent, 42, "{newest_time}");
        assert_eq!(fixture.log_requests().len(), 3, "{newest_time}");
    }
}
