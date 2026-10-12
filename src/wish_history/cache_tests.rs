//! The web cache reader and source, on synthetic logs and cache files in
//! temporary folders. Every path, key and link here is made up.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use auto_artifactarium::GachaAuthKey;
use tokio::sync::mpsc;

use super::super::tests::hub;
use super::super::{Trigger, WishEvent};
use super::*;

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

fn source(data: &Path) -> (CacheSource, mpsc::UnboundedReceiver<Trigger>, WishHub) {
    let (hub, key_rx, triggers) = hub();
    drop(key_rx);
    let (_requests_tx, requests) = mpsc::unbounded_channel();
    let source = CacheSource::with_reader(
        hub.clone(),
        requests,
        CacheReader::for_data_dir(data.to_path_buf()),
    );
    (source, triggers, hub)
}

#[test]
fn a_cached_link_feeds_copy_but_never_becomes_a_key_or_a_sync() {
    let data = tempfile::tempdir().unwrap();
    write_cache(data.path(), "2.55.0.0", &cache_bytes(&[link("HHHH")]));
    let (mut source, mut triggers, hub) = source(data.path());

    assert_eq!(source.look(), Ok(link("HHHH")), "the game's link, verbatim");
    assert!(hub.key_tx.borrow().is_none(), "never a key");
    assert!(triggers.try_recv().is_err(), "never a sync");
    assert_eq!(hub.seen_tx.borrow().cached_link, CacheState::Found);

    // A held key of this login is not replaced by it either.
    hub.forward(
        vec![WishEvent::Key(GachaAuthKey::new(
            "LIVE",
            "webview_gacha",
            "hk4e_global",
        ))],
        Some(811_111_111),
    );
    assert_eq!(triggers.try_recv(), Ok(Trigger::NewKey));
    assert_eq!(source.look(), Ok(link("HHHH")));
    assert!(
        hub.key_tx
            .borrow()
            .as_ref()
            .unwrap()
            .wish_url()
            .contains("authkey=LIVE")
    );
    assert!(triggers.try_recv().is_err());
}

#[test]
fn misses_are_said_and_seen_as_none() {
    let data = tempfile::tempdir().unwrap();
    write_cache(data.path(), "2.55.0.0", &cache_bytes(&[]));
    let (mut source, _triggers, hub) = source(data.path());
    hub.see_cache(CacheState::Found);
    assert_eq!(source.look(), Err(Miss::NoLink.to_string()));
    assert_eq!(hub.seen_tx.borrow().cached_link, CacheState::None);

    fs::remove_dir_all(data.path().join("webCaches")).unwrap();
    assert_eq!(source.look(), Err(Miss::NoCache.to_string()));
}

#[tokio::test]
async fn the_source_answers_the_uis_requests() {
    let data = tempfile::tempdir().unwrap();
    write_cache(data.path(), "2.55.0.0", &cache_bytes(&[link("IIII")]));
    let (hub, _key_rx, _triggers) = hub();
    let (requests_tx, requests) = mpsc::unbounded_channel();
    let source = CacheSource::with_reader(
        hub,
        requests,
        CacheReader::for_data_dir(data.path().to_path_buf()),
    );
    let task = tokio::spawn(source.run());
    let (reply, answer) = tokio::sync::oneshot::channel();
    requests_tx.send(reply).unwrap();
    assert_eq!(answer.await.unwrap(), Ok(link("IIII")));
    drop(requests_tx);
    task.await.unwrap();
}

#[test]
fn cache_states_have_their_labels() {
    assert_eq!(CacheState::default(), CacheState::None);
    assert_eq!(CacheState::None.label(), "none");
    assert_eq!(CacheState::Found.label(), "found (may be another account)");
}

/// This PC's real game cache. Prints only whether a link was found -- never
/// a path, a link or a key -- and sends nothing anywhere.
///
/// `IRMINSUL_REAL_WISH_CACHE=1 cargo test real_game_cache -- --ignored --nocapture`
#[test]
#[ignore = "reads this PC's game cache; set IRMINSUL_REAL_WISH_CACHE=1"]
fn real_game_cache() {
    if std::env::var_os("IRMINSUL_REAL_WISH_CACHE").is_none() {
        println!("IRMINSUL_REAL_WISH_CACHE is not set; skipped");
        return;
    }
    let roots = user_profile_roots().unwrap_or_default();
    match CacheReader::new(&roots).find() {
        Ok(_) => println!("cached link: found"),
        Err(miss) => println!("cached link: none ({miss})"),
    }
}
