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
///
/// One global subscriber, installed on first use, routes each event to the
/// capture running on the thread that logged it. A scoped subscriber per test
/// (`with_default`) was not enough: `tracing` caches, per call site and for all
/// threads at once, whether anyone listens, and on CI a warning call site that
/// earlier tests reached without a capture stayed cached as unheard, so a test
/// that did capture saw 0 events. A global subscriber that always listens
/// leaves nothing to cache wrongly.
pub(crate) fn logged(level: Level, f: impl FnOnce()) -> Vec<String> {
    use std::cell::RefCell;
    use std::sync::Once;

    use tracing::field::{Field, Visit};
    use tracing::metadata::LevelFilter;
    use tracing::span::{Attributes, Id, Record};
    use tracing::subscriber::Interest;
    use tracing::{Event, Metadata, Subscriber};

    thread_local! {
        /// The level being captured on this thread and what it caught.
        static CAPTURE: RefCell<Option<(Level, Vec<String>)>> = const { RefCell::new(None) };
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

    struct Router;

    impl Subscriber for Router {
        fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
            Interest::always()
        }
        fn max_level_hint(&self) -> Option<LevelFilter> {
            Some(LevelFilter::TRACE)
        }
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            CAPTURE.with(|capture| {
                if let Some((level, seen)) = capture.borrow_mut().as_mut()
                    && event.metadata().level() == level
                {
                    let mut fields = Fields(String::new());
                    event.record(&mut fields);
                    seen.push(fields.0);
                }
            });
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    /// Ends this thread's capture even if `f` panics.
    struct Stop;

    impl Drop for Stop {
        fn drop(&mut self) {
            CAPTURE.with(|capture| capture.borrow_mut().take());
        }
    }

    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        tracing::subscriber::set_global_default(Router)
            .expect("no other global subscriber in the unit tests");
    });

    CAPTURE.with(|capture| *capture.borrow_mut() = Some((level, Vec::new())));
    let stop = Stop;
    f();
    let seen = CAPTURE.with(|capture| capture.borrow_mut().take().map(|(_, seen)| seen));
    drop(stop);
    seen.unwrap_or_default()
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
