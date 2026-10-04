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
    tracing::subscriber::with_default(capture, f);
    seen.lock().unwrap().clone()
}
