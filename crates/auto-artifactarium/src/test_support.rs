//! Helpers shared by the crate's unit tests.

use std::fmt;
use std::fmt::Write;

use tracing::Level;

/// Runs `f` and returns every WARN event it logged on this thread, each as
/// its message followed by its other fields.
pub(crate) fn warnings(f: impl FnOnce()) -> Vec<String> {
    logged(Level::WARN, f)
}

/// Runs `f` and returns every event at exactly `level` it logged on this
/// thread, each as its message followed by its other fields.
pub(crate) fn logged(level: Level, f: impl FnOnce()) -> Vec<String> {
    use std::sync::{Arc, Mutex};

    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    struct Capture {
        level: Level,
        seen: Arc<Mutex<Vec<String>>>,
    }

    struct Fields(String);

    impl Visit for Fields {
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            if field.name() == "message" {
                self.0.insert_str(0, &format!("{value:?}"));
            } else {
                let _ = write!(self.0, " {}={value:?}", field.name());
            }
        }
    }

    impl Subscriber for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            if *event.metadata().level() == self.level {
                let mut fields = Fields(String::new());
                event.record(&mut fields);
                self.seen.lock().unwrap().push(fields.0);
            }
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    let seen = Arc::new(Mutex::new(Vec::new()));
    let capture = Capture {
        level,
        seen: Arc::clone(&seen),
    };
    tracing::subscriber::with_default(capture, || {
        // `tracing` caches, per call site and for every thread at once,
        // whether anyone listens. Tests capture in parallel on many threads,
        // and a call site first reached while no capture was registered can
        // stay cached as unheard, so a warning this test logs goes missing
        // (seen on CI as a flaky count of 0). Rebuilding the cache with this
        // capture registered makes every call site ask it again.
        tracing::callsite::rebuild_interest_cache();
        f();
    });
    seen.lock().unwrap().clone()
}

/// The messages of one Oodle test vector stream in
/// `tests/data/oodle/<name>.ontv.gz`, each as (decompressed, as sent). The
/// format is described in `tests/oodle_vectors.rs`.
pub(crate) fn oodle_vectors(name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    use std::io::Read;

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/oodle")
        .join(format!("{name}.ontv.gz"));
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();

    let word = |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap()) as usize;
    assert_eq!(&data[..4], b"ONTV");
    let count = word(16);
    let mut at = 20;
    (0..count)
        .map(|_| {
            let (raw_len, sent_len) = (word(at), word(at + 4));
            let raw = data[at + 8..at + 8 + raw_len].to_vec();
            let sent = data[at + 8 + raw_len..at + 8 + raw_len + sent_len].to_vec();
            at += 8 + raw_len + sent_len;
            (raw, sent)
        })
        .collect()
}
