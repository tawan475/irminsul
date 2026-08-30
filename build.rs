use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::{env, fs, io};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use winresource::WindowsResource;

#[tokio::main]
async fn main() -> io::Result<()> {
    // Without these, cargo re-runs this build script on *every* source edit,
    // which means every edit performs a network probe against gitlab.com.  With
    // them the game data is refreshed when the build script or icon changes,
    // when OUT_DIR is wiped (`cargo clean`), or when IRMINSUL_REFRESH_GAME_DATA
    // is changed, which is the documented way to force a refresh.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-env-changed=IRMINSUL_REFRESH_GAME_DATA");

    // Download new game data and save it in a location to be included by the source.
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let cache_path = Path::new(&out_dir).join("game_data.json");
    let gz_path = Path::new(&out_dir).join("game_data.gz");

    let mut db = anime_game_data::AnimeGameData::new_with_cache(&cache_path);

    // Network failures must not fail the build when a usable cache already
    // exists: a build with a warm OUT_DIR is expected to work offline.
    let needs_update = match db.needs_update().await {
        Ok(needs_update) => needs_update,
        Err(e) => {
            println!(
                "cargo:warning=unable to check for new game data ({e}); falling back to the \
                 cached copy"
            );
            false
        }
    };

    let mut updated = false;
    if needs_update {
        match db.update().await {
            Ok(()) => updated = true,
            Err(e) => println!("cargo:warning=unable to download game data ({e})"),
        }
    }

    // `save_to_writer()` errors out when no database is loaded, so bail with an
    // actionable message rather than writing an empty/short game_data.gz that
    // `include_bytes!` would happily embed.
    assert!(
        db.has_data(),
        "no cached game data at {} and the download failed: irminsul's first build needs network \
         access to gitlab.com",
        cache_path.display()
    );

    // The gz is what `monitor.rs` embeds with `include_bytes!`, so it must exist
    // whether or not this run refreshed the json cache.  Writing it only inside
    // the update branch used to leave a warm json cache next to a missing gz,
    // which failed every later build with an error pointing at monitor.rs.
    if updated || gz_needs_write(&gz_path, &cache_path) {
        write_game_data_gz(&db, &gz_path)?;
    }

    // Add icon to windows binary.
    if env::var_os("CARGO_CFG_WINDOWS").is_some() {
        WindowsResource::new()
            .set_icon("assets/icon.ico")
            .set_manifest(
                r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
        <requestedPrivileges>
            <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
        </requestedPrivileges>
    </security>
</trustInfo>
</assembly>
"#,
            )
            .compile()?;
    }

    // `cfg(unix)` in a build script describes the *host*, not the target, so it
    // silently drops the link directive when cross compiling a unix target from
    // a non-unix host (and vice versa).  CARGO_CFG_UNIX / CARGO_FEATURE_* are
    // set by cargo for the target being built, mirroring CARGO_CFG_WINDOWS above.
    if env::var_os("CARGO_CFG_UNIX").is_some()
        && env::var_os("CARGO_FEATURE_STATIC_LIBPCAP").is_some()
    {
        println!("cargo:rustc-link-lib=static=pcap");
    }
    Ok(())
}

/// True when `game_data.gz` is missing, unreadable, older than the
/// `game_data.json` cache it is generated from, or not a complete gzip stream
/// (e.g. truncated by an interrupted build from an earlier version of this
/// script, which wrote the file in place).
fn gz_needs_write(gz_path: &Path, cache_path: &Path) -> bool {
    let Ok(gz_modified) = fs::metadata(gz_path).and_then(|m| m.modified()) else {
        return true;
    };

    // No json cache to compare against means the gz is all we have to go on.
    if let Ok(json_modified) = fs::metadata(cache_path).and_then(|m| m.modified())
        && gz_modified < json_modified
    {
        return true;
    }

    !gz_is_complete(gz_path)
}

/// Decompresses `gz_path` and discards the result, just to confirm the stream
/// (including its trailer) is intact.
fn gz_is_complete(gz_path: &Path) -> bool {
    let Ok(file) = File::open(gz_path) else {
        return false;
    };
    let mut decoder = GzDecoder::new(file);
    let mut buf = [0u8; 64 * 1024];
    loop {
        match decoder.read(&mut buf) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
}

/// Writes the compressed game data to a temporary file and renames it into
/// place, so an interrupted build cannot leave a truncated `game_data.gz`
/// behind.
fn write_game_data_gz(db: &anime_game_data::AnimeGameData, gz_path: &Path) -> io::Result<()> {
    let tmp_path = gz_path.with_extension("gz.tmp");
    let file = File::create(&tmp_path)?;
    let mut writer = GzEncoder::new(file, Compression::best());
    db.save_to_writer(&mut writer)
        .map_err(|e| io::Error::other(format!("unable to serialize game data: {e}")))?;
    let file = writer.finish()?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp_path, gz_path)
}
