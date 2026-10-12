//! The web cache reader and source, on synthetic logs and cache files in
//! temporary folders, with a fake wish history API. Every path, key and
//! link here is made up.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use auto_artifactarium::GachaAuthKey;
use tokio::sync::mpsc;

use super::super::gacha_log::{KeySource, WishKey};
use super::super::test_server::{Reply, TestServer};
use super::super::tests::hub;
use super::super::{Trigger, WishEvent};
use super::*;

const LOG_PATH: &str = "/gacha_info/api/getGachaLog";

/// The game's link as the cache holds it, with the key `key` (escaped as
/// the game does).
fn link(key: &str) -> String {
    format!(
        "https://public-operation-hk4e-sg.hoyoverse.com/gacha_info/api/getGachaLog\
         ?win_mode=fullscreen&no_joypad_close=1&authkey_ver=1&sign_type=2\
         &auth_appid=webview_gacha&init_type=301\
         &gacha_id=0123456789abcdef0123456789abcdef01234567&timestamp=1790000000\
         &lang=en&device_type=pc&game_version=OSRELWin7.1.0_R11111111_S22222222_D33333333\
         &region=os_asia&authkey={key}%2bSyNtHeTiC%2f%3d%3d&game_biz=hk4e_global"
    )
}

/// The history page's own link, same parameters.
fn page_link(key: &str) -> String {
    link(key).replace(
        "public-operation-hk4e-sg.hoyoverse.com/gacha_info/api/getGachaLog",
        "gs.hoyoverse.com/genshin/event/e20190909gacha-0000/index.html",
    )
}

/// The binary a cache file has between entries.
const JUNK: &[u8] = b"\x00\x01\xff\xfeHTTP/1.1 200\x00\x00\xc3\x28key\x00";

/// A cache file's contents: `links` among junk, oldest first.
fn cache_bytes(links: &[String]) -> Vec<u8> {
    let mut bytes = JUNK.to_vec();
    for link in links {
        bytes.extend_from_slice(link.as_bytes());
        bytes.extend_from_slice(JUNK);
    }
    bytes
}

/// Write `<data>/webCaches/<version>/Cache/Cache_Data/data_2`.
fn write_cache(data: &Path, version: &str, bytes: &[u8]) -> PathBuf {
    let dir = data
        .join("webCaches")
        .join(version)
        .join("Cache")
        .join("Cache_Data");
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("data_2");
    fs::write(&file, bytes).unwrap();
    file
}

fn set_mtime(path: &Path, at: SystemTime) {
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(at)
        .unwrap();
}

// ---- the game's log ----

#[test]
fn the_current_log_format_names_the_game_folder() {
    // The shape of a 7.1 client's output_log.txt (made-up path).
    let log = "[2026-10-12 21:00:00.100] Genshin Start Log: GameManager Awake - NowTimeStamp:1790000000\r\n\
               [2026-10-12 21:00:00.100] Genshin Start Log: GameManager InitGame - NowTimeStamp:1790000000\r\n\
               [2026-10-12 21:00:00.170] DeserializeBinary (E:/Games/Genshin Impact game/GenshinImpact_Data/Persistent\\AssetBundles/blocks\\00/31049740.blk) onlyStreamingFalse appendFalse\r\n\
               [2026-10-12 21:00:00.600] LoadDataIndex succeed! file E:/Games/Genshin Impact game/GenshinImpact_Data/StreamingAssets\\AssetBundles/blocks\\00/31049741.blk\r\n\
               [2026-10-12 21:00:09.000] Genshin Start Log: NetworkManager ConnectGlobalDispatchServer https://dispatch.example.invalid/query_region_list - NowTimeStamp:1790000009\r\n";
    assert_eq!(
        data_dir_in_log(log.as_bytes()),
        Some(PathBuf::from(
            "E:/Games/Genshin Impact game/GenshinImpact_Data"
        ))
    );
}

#[test]
fn older_formats_the_chinese_client_and_player_log_name_it_too() {
    let cases = [
        (
            "[Subsystems] Discovering subsystems at path C:/Program Files/Genshin Impact/Genshin Impact Game/GenshinImpact_Data/UnitySubsystems",
            "C:/Program Files/Genshin Impact/Genshin Impact Game/GenshinImpact_Data",
        ),
        (
            "[Subsystems] Discovering subsystems at path D:\\原神\\Genshin Impact Game\\YuanShen_Data\\UnitySubsystems",
            "D:\\原神\\Genshin Impact Game\\YuanShen_Data",
        ),
        (
            // Unity's Player.log.
            "Mono path[0] = 'F:/Games/Genshin Impact/Genshin Impact Game/GenshinImpact_Data/Managed'",
            "F:/Games/Genshin Impact/Genshin Impact Game/GenshinImpact_Data",
        ),
        (
            "Loading file:///E:/Games/Genshin Impact game/GenshinImpact_Data/StreamingAssets/x.json",
            "E:/Games/Genshin Impact game/GenshinImpact_Data",
        ),
    ];
    for (line, expected) in cases {
        let text = format!("noise\n{line}\nmore noise D:/Other/GenshinImpact_Data\n");
        assert_eq!(
            data_dir_in_log(text.as_bytes()),
            Some(PathBuf::from(expected)),
            "{line}"
        );
    }
}

#[test]
fn a_log_without_the_game_folder_names_none() {
    for text in [
        "",
        "[2026-10-12 21:00:00.100] Genshin Start Log: GameManager Awake",
        "C:/Windows/System32 and https://example.invalid/GenshinImpact_Data",
        "GenshinImpact_Data without a drive",
    ] {
        assert_eq!(data_dir_in_log(text.as_bytes()), None, "{text}");
    }
}

/// A profile root with the game's log folders.
struct Profile {
    root: tempfile::TempDir,
}

impl Profile {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn log(&self, client: &str, name: &str) -> PathBuf {
        self.root
            .path()
            .join("AppData")
            .join("LocalLow")
            .join("miHoYo")
            .join(client)
            .join(name)
    }

    fn write(&self, client: &str, name: &str, text: &str, at: SystemTime) -> PathBuf {
        let path = self.log(client, name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
        set_mtime(&path, at);
        path
    }

    fn reader(&self) -> CacheReader {
        CacheReader::new(&[self.root.path().to_path_buf()])
    }
}

fn line(dir: &str) -> String {
    format!("[2026-10-12 21:00:00.170] DeserializeBinary ({dir}/Persistent\\AssetBundles/x.blk)\n")
}

#[test]
fn the_newest_log_that_names_a_folder_wins() {
    let profile = Profile::new();
    let hour_ago = SystemTime::now() - Duration::from_secs(3600);
    let now = SystemTime::now();
    profile.write(
        "Genshin Impact",
        "output_log.txt",
        &line("E:/Old/GenshinImpact_Data"),
        hour_ago,
    );
    profile.write("原神", "output_log.txt", &line("E:/Cn/YuanShen_Data"), now);
    assert_eq!(
        profile.reader().locate(),
        Ok(PathBuf::from("E:/Cn/YuanShen_Data"))
    );

    // A newer log that names no folder is passed over.
    profile.write(
        "Genshin Impact",
        "Player.log",
        "nothing here\n",
        now + Duration::from_secs(5),
    );
    assert_eq!(
        profile.reader().locate(),
        Ok(PathBuf::from("E:/Cn/YuanShen_Data"))
    );
}

#[test]
fn the_folder_is_kept_while_the_game_rewrites_its_log() {
    let profile = Profile::new();
    let start = SystemTime::now() - Duration::from_secs(60);
    let text = format!("{}{}", line("E:/Games/GenshinImpact_Data"), "x".repeat(500));
    profile.write("Genshin Impact", "output_log.txt", &text, start);
    let mut reader = profile.reader();
    assert_eq!(
        reader.locate(),
        Ok(PathBuf::from("E:/Games/GenshinImpact_Data"))
    );

    // The game starts again: its log is rewritten, the folder not named yet.
    profile.write(
        "Genshin Impact",
        "output_log.txt",
        "[2026-10-12 22:00:00.000] Genshin Start Log: GameManager Awake\n",
        start + Duration::from_secs(30),
    );
    assert_eq!(
        reader.locate(),
        Ok(PathBuf::from("E:/Games/GenshinImpact_Data"))
    );

    // Seconds later it names its (new) folder.
    profile.write(
        "Genshin Impact",
        "output_log.txt",
        &format!("header\n{}", line("F:/Moved/GenshinImpact_Data")),
        start + Duration::from_secs(35),
    );
    assert_eq!(
        reader.locate(),
        Ok(PathBuf::from("F:/Moved/GenshinImpact_Data"))
    );
}

#[test]
fn without_logs_or_a_named_folder_the_reader_says_so() {
    let profile = Profile::new();
    assert_eq!(profile.reader().locate(), Err(Miss::NoLog));
    profile.write(
        "Genshin Impact",
        "output_log.txt",
        "nothing\n",
        SystemTime::now(),
    );
    assert_eq!(profile.reader().locate(), Err(Miss::NoGameFolder));
}

#[test]
fn logs_are_labelled_without_the_profile_path() {
    let profile = Profile::new();
    let log = profile.log("原神", "Player.log");
    assert_eq!(log_label(&log), "原神/Player.log");
}

// ---- the cache file ----

#[test]
fn the_newest_web_cache_folder_with_a_cache_file_is_read() {
    let data = tempfile::tempdir().unwrap();
    assert_eq!(newest_cache_file(data.path()), None, "no webCaches");

    write_cache(data.path(), "2.55.0.0", b"a");
    std::thread::sleep(Duration::from_millis(50));
    // Written later: newer, whatever its name says.
    let newer = write_cache(data.path(), "2.49.0.0", b"b");
    assert_eq!(newest_cache_file(data.path()), Some(newer.clone()));

    // A newer folder without a cache file is passed over.
    std::thread::sleep(Duration::from_millis(50));
    fs::create_dir_all(data.path().join("webCaches").join("2.56.0.0")).unwrap();
    assert_eq!(newest_cache_file(data.path()), Some(newer));
}

#[test]
fn the_newest_wish_history_link_with_a_key_is_taken() {
    let without_key = link("AAAA").replace("&authkey=AAAA%2bSyNtHeTiC%2f%3d%3d", "");
    let beyond = link("EEEE").replace("getGachaLog", "getBeyondGachaLog");
    let cache = cache_bytes(&[
        link("AAAA"),
        page_link("BBBB"),
        link("CCCC"),
        without_key,
        page_link("DDDD"),
        beyond,
    ]);
    assert_eq!(wish_link_in_cache(&cache), Some(link("CCCC")));

    // Only the history page's own link: that one.
    assert_eq!(
        wish_link_in_cache(&cache_bytes(&[page_link("FFFF")])),
        Some(page_link("FFFF"))
    );
    assert_eq!(wish_link_in_cache(JUNK), None);
    assert_eq!(
        wish_link_in_cache(b"https://example.invalid/?game_biz=hk4e_global&authkey=x"),
        None
    );
}

#[test]
fn a_link_ends_at_the_game_biz_value_and_at_binary() {
    let mut cache = link("GGGG").into_bytes();
    cache.extend_from_slice(b"\x00&page=2");
    assert_eq!(wish_link_in_cache(&cache), Some(link("GGGG")));
}

// ---- the source ----

/// A fake wish history API answering every check with `retcode` (HTTP
/// `status`).
fn api(status: u16, retcode: i64) -> TestServer {
    TestServer::start(move |_| {
        let message = match retcode {
            0 => "OK",
            -101 => "authkey timeout",
            -109 => "app id error",
            _ => "error",
        };
        let data = if retcode == 0 {
            r#"{"page":"1","size":"1","region":"os_asia","list":[]}"#
        } else {
            "null"
        };
        Reply::json(
            status,
            format!(r#"{{"retcode":{retcode},"message":"{message}","data":{data}}}"#),
        )
    })
}

struct Fixture {
    data: tempfile::TempDir,
    hub: WishHub,
    key_rx: tokio::sync::watch::Receiver<Option<WishKey>>,
    triggers: mpsc::UnboundedReceiver<Trigger>,
    source: CacheSource,
    server: TestServer,
}

impl Fixture {
    fn new(server: TestServer, links: &[String]) -> Self {
        let data = tempfile::tempdir().unwrap();
        write_cache(data.path(), "2.55.0.0", &cache_bytes(links));
        let (hub, key_rx, triggers) = hub();
        let (_requests_tx, requests) = mpsc::unbounded_channel();
        let source = CacheSource::with_reader(
            hub.clone(),
            requests,
            CacheReader::for_data_dir(data.path().to_path_buf()),
        )
        .with_endpoint(format!("{}{LOG_PATH}", server.base));
        Self {
            data,
            hub,
            key_rx,
            triggers,
            source,
            server,
        }
    }

    fn rewrite(&self, links: &[String]) {
        write_cache(self.data.path(), "2.55.0.0", &cache_bytes(links));
    }

    fn held(&self) -> Option<WishKey> {
        self.key_rx.borrow().clone()
    }

    fn seen(&self) -> CacheState {
        self.hub.seen_tx.borrow().cached_link
    }

    fn requests(&self) -> usize {
        self.server.requests().len()
    }

    fn live(&self, key: &str) {
        self.hub.forward(
            vec![WishEvent::Key(GachaAuthKey::new(
                key,
                "webview_gacha",
                "hk4e_global",
            ))],
            None,
        );
    }
}

/// The key `link(key)` carries, unescaped.
fn authkey(key: &str) -> String {
    format!("{key}+SyNtHeTiC/==")
}

#[tokio::test]
async fn a_cached_link_that_works_becomes_the_key_and_syncs_once() {
    let mut fx = Fixture::new(api(200, 0), &[link("HHHH")]);
    assert_eq!(fx.source.look().await, Ok(link("HHHH")));

    let held = fx.held().expect("the cached key is held");
    assert_eq!(held.source(), KeySource::Cache);
    assert_eq!(held.wish_url(), link("HHHH"), "the game's link, verbatim");
    assert_eq!(fx.triggers.try_recv(), Ok(Trigger::NewKey));
    assert_eq!(fx.seen(), CacheState::Valid);

    // ONE request: the game's link as it is, then one record of 301.
    let requests = fx.server.requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.path, LOG_PATH);
    assert_eq!(request.param("authkey"), Some(authkey("HHHH").as_str()));
    let names: Vec<&str> = request
        .query
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "win_mode",
            "no_joypad_close",
            "authkey_ver",
            "sign_type",
            "auth_appid",
            "init_type",
            "gacha_id",
            "timestamp",
            "lang",
            "device_type",
            "game_version",
            "region",
            "authkey",
            "game_biz",
            "gacha_type",
            "size",
            "page",
            "end_id",
        ]
    );
    assert_eq!(request.param("game_biz"), Some("hk4e_global"));
    assert_eq!(request.param("gacha_type"), Some("301"));
    assert_eq!(request.param("size"), Some("1"));

    // The same link again (a look, or the file unchanged): no request, no sync.
    assert_eq!(fx.source.look().await, Ok(link("HHHH")));
    fx.source.on_change().await;
    assert_eq!(fx.requests(), 1);
    assert!(fx.triggers.try_recv().is_err());
}

#[tokio::test]
async fn an_expired_or_refused_link_is_ignored_and_checked_once() {
    for (retcode, state, why) in [
        (-101, CacheState::Expired, "expired"),
        (-109, CacheState::Refused, "refused"),
    ] {
        let mut fx = Fixture::new(api(200, retcode), &[link("IIII")]);
        let answer = fx.source.look().await.unwrap_err();
        assert!(answer.contains(why), "{retcode}: {answer}");
        assert!(!answer.contains("IIII"), "{answer}");
        assert!(fx.held().is_none(), "{retcode}");
        assert!(fx.triggers.try_recv().is_err(), "{retcode}");
        assert_eq!(fx.seen(), state, "{retcode}");

        assert!(fx.source.look().await.is_err());
        assert_eq!(fx.requests(), 1, "{retcode}: checked once");
    }
}

#[tokio::test]
async fn a_check_without_an_answer_is_tried_again_next_time() {
    let mut fx = Fixture::new(api(500, 0), &[link("JJJJ")]);
    let answer = fx.source.look().await.unwrap_err();
    assert!(answer.contains("could not check"), "{answer}");
    assert!(!answer.contains("JJJJ"), "{answer}");
    assert_eq!(fx.seen(), CacheState::Found);
    assert!(fx.held().is_none());

    assert!(fx.source.look().await.is_err());
    assert_eq!(fx.requests(), 2);
}

#[tokio::test]
async fn a_key_from_the_traffic_wins_over_the_cache() {
    let mut fx = Fixture::new(api(200, 0), &[link("KKKK")]);
    fx.live("LIVE");
    assert_eq!(fx.triggers.try_recv(), Ok(Trigger::NewKey));
    let live_url = fx.held().unwrap().wish_url();

    // Another key in the cache: not even checked.
    assert_eq!(fx.source.look().await, Ok(live_url));
    assert_eq!(fx.requests(), 0);
    assert_eq!(fx.seen(), CacheState::Found);
    assert_eq!(fx.held().unwrap().source(), KeySource::Game);
    assert!(fx.triggers.try_recv().is_err());

    // The cache holding the key in use: valid, no request.
    fx.rewrite(&[link("KKKK"), link("MMMM")]);
    fx.live(&authkey("MMMM"));
    assert_eq!(fx.triggers.try_recv(), Ok(Trigger::NewKey));
    assert!(fx.source.look().await.is_ok());
    assert_eq!(fx.requests(), 0);
    assert_eq!(fx.seen(), CacheState::Valid);
}

#[tokio::test]
async fn a_live_key_replaces_a_cached_one_but_the_same_key_does_not_sync_again() {
    let mut fx = Fixture::new(api(200, 0), &[link("NNNN")]);
    fx.source.look().await.unwrap();
    assert_eq!(fx.triggers.try_recv(), Ok(Trigger::NewKey));

    // The same key from the traffic: no new sync; it is the game's now.
    fx.live(&authkey("NNNN"));
    assert!(fx.triggers.try_recv().is_err());
    let held = fx.held().unwrap();
    assert_eq!(held.source(), KeySource::Game);
    assert_eq!(
        held.wish_url(),
        link("NNNN"),
        "the link stays the game's own"
    );

    // A newer cached link cannot replace it now.
    fx.rewrite(&[link("NNNN"), link("OOOO")]);
    assert!(fx.source.look().await.is_ok());
    assert_eq!(fx.requests(), 1);
    assert!(fx.triggers.try_recv().is_err());

    // A different live key replaces it.
    fx.live("PPPP");
    assert_eq!(fx.triggers.try_recv(), Ok(Trigger::NewKey));
    assert!(fx.held().unwrap().wish_url().contains("authkey=PPPP"));
}

#[tokio::test]
async fn a_newer_cached_link_replaces_an_older_cached_key() {
    let mut fx = Fixture::new(api(200, 0), &[link("QQQQ")]);
    fx.source.look().await.unwrap();
    assert_eq!(fx.triggers.try_recv(), Ok(Trigger::NewKey));

    std::thread::sleep(Duration::from_millis(20));
    fx.rewrite(&[link("QQQQ"), link("RRRR")]);
    fx.source.on_change().await;
    assert_eq!(fx.requests(), 2);
    assert_eq!(fx.triggers.try_recv(), Ok(Trigger::NewKey));
    assert_eq!(fx.held().unwrap().wish_url(), link("RRRR"));
}

#[tokio::test]
async fn a_cached_key_the_sync_dropped_is_not_taken_again() {
    let mut fx = Fixture::new(api(200, 0), &[link("SSSS")]);
    fx.source.look().await.unwrap();
    assert_eq!(fx.triggers.try_recv(), Ok(Trigger::NewKey));

    // The sync found it expired and dropped it.
    fx.hub.key_tx.send_replace(None);
    let answer = fx.source.look().await.unwrap_err();
    assert!(answer.contains("expired"), "{answer}");
    assert!(fx.held().is_none());
    assert!(fx.triggers.try_recv().is_err());
    assert_eq!(fx.requests(), 1);
    assert_eq!(fx.seen(), CacheState::Expired);
}

#[tokio::test]
async fn misses_are_said_and_seen_as_none() {
    let mut fx = Fixture::new(api(200, 0), &[]);
    assert_eq!(fx.source.look().await, Err(Miss::NoLink.to_string()));
    assert_eq!(fx.seen(), CacheState::None);

    fs::remove_dir_all(fx.data.path().join("webCaches")).unwrap();
    assert_eq!(fx.source.look().await, Err(Miss::NoCache.to_string()));
    assert_eq!(fx.requests(), 0);
}

#[test]
fn cache_states_have_their_labels() {
    assert_eq!(CacheState::default(), CacheState::None);
    assert_eq!(CacheState::Found.label(), "found");
    assert_eq!(CacheState::Valid.label(), "valid");
    assert_eq!(CacheState::Expired.label(), "expired");
    assert_eq!(CacheState::Refused.label(), "refused");
    assert_eq!(CacheState::None.label(), "none");
}

/// This PC's real game cache, checked with ONE request to the game's server.
/// Prints only what came of it -- never a path, a link or a key.
///
/// `IRMINSUL_REAL_WISH_CACHE=1 cargo test real_game_cache -- --ignored --nocapture`
#[tokio::test]
#[ignore = "reads this PC's game cache and asks the game's server; set IRMINSUL_REAL_WISH_CACHE=1"]
async fn real_game_cache() {
    if std::env::var_os("IRMINSUL_REAL_WISH_CACHE").is_none() {
        println!("IRMINSUL_REAL_WISH_CACHE is not set; skipped");
        return;
    }
    let roots = user_profile_roots().unwrap_or_default();
    let mut reader = CacheReader::new(&roots);
    let file = match reader.cache_file() {
        Ok(file) => file,
        Err(miss) => {
            println!("cached link: none ({miss})");
            return;
        }
    };
    let found = match CacheReader::read_link(&file) {
        Ok(found) => found,
        Err(miss) => {
            println!("cached link: none ({miss})");
            return;
        }
    };
    println!(
        "cached link: found (cache file ~{} h old)",
        found.age.as_secs() / 3600
    );
    let Some(key) = WishKey::from_game_link(&found.url, found.age, Instant::now()) else {
        println!("cached link: no key in it");
        return;
    };
    let http = crate::http_client_builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let outcome = match probe(&http, key.endpoint(), &key).await {
        Probe::Valid => "valid".to_owned(),
        Probe::Expired => "expired".to_owned(),
        Probe::Refused(retcode) => format!("refused ({retcode})"),
        Probe::Failed(why) => format!("not checked ({why})"),
    };
    println!("cached link: {outcome}");
}
