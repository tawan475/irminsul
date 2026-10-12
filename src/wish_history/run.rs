//! One sync run: page the wish history down to what the tracker already
//! holds, then import what is new.
//!
//! The rule (the user's): ask the tracker for its newest record id per banner
//! (the cursor), then for each banner read page 1; if its newest record is one
//! the tracker has, that banner is done after one request. Otherwise keep the
//! records newer than the cursor and read the next page (`end_id` = the last
//! record's id) until a record the tracker has, an empty page, an expired
//! key, or the per-run page cap.
//!
//! ## No gaps
//!
//! The tracker only remembers its newest id per banner, so importing the
//! newest part of a banner's new records without the rest would hide the rest
//! forever: the next run would stop at page 1. A banner's records are
//! therefore imported only once its pass is complete. A pass cut short (page
//! cap, expired key, an API failure) is kept in memory as a [`Partial`] and
//! finished by a later run, which first reads what arrived above it and then
//! carries on below it. Records go to the tracker oldest first, so even an
//! import cut short between chunks leaves no gap.

use std::collections::BTreeMap;

use super::Banner;
use super::gacha_log::{ApiRecord, FetchError, LogClient, Sleeper};
use super::tracker::{Cursor, Imported, Tracker};

/// Pages read per banner per run, beyond which the run stops that banner and
/// a later one carries on.
pub(crate) const PAGES_PER_RUN: u32 = 50;

/// A banner's pass that did not reach the end, kept until a later run
/// finishes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Partial {
    /// Whose history this is.
    uid: String,
    /// The tracker's newest id when the pass began; records at or below it
    /// are known.
    floor: Option<u64>,
    /// The newest record read.
    top: u64,
    /// The last (oldest) record read: where the pass carries on.
    end_id: u64,
    /// The page number to ask for next.
    next_page: u32,
    records: BTreeMap<u64, ApiRecord>,
}

/// Why a run ended early.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RunError {
    /// The API said "authkey timeout".
    KeyExpired,
    /// The wish history API could not be read.
    Api(String),
    /// The tracker refused or could not be reached.
    Tracker(String),
    /// The answers were not consistent (records of two UIDs, a bad id).
    Data(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyExpired => write!(f, "the wish key expired"),
            Self::Api(why) | Self::Tracker(why) | Self::Data(why) => write!(f, "{why}"),
        }
    }
}

impl From<FetchError> for RunError {
    fn from(error: FetchError) -> Self {
        match error {
            FetchError::KeyExpired => Self::KeyExpired,
            other => Self::Api(other.to_string()),
        }
    }
}

/// What a run did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RunReport {
    /// The account's UID, once any record was read.
    pub(crate) uid: Option<String>,
    /// Records sent to the tracker.
    pub(crate) sent: usize,
    /// What the tracker made of them.
    pub(crate) imported: Imported,
    /// Banners left unfinished, for a later run.
    pub(crate) unfinished: Vec<Banner>,
    pub(crate) error: Option<RunError>,
}

/// Where a pass stops reading.
#[derive(Clone, Copy)]
enum Floor {
    /// The tracker's newest id for the banner (the cursor, read when first
    /// needed).
    Cursor,
    /// A fixed id: a [`Partial`]'s.
    Fixed(Option<u64>),
}

/// How a pass ended.
enum PassEnd {
    /// It reached a known record or an empty page.
    Complete,
    /// It stopped early, at `end_id` / `next_page`.
    Cut {
        end_id: u64,
        next_page: u32,
        error: Option<RunError>,
    },
}

/// A banner's complete records and what is left for later; or why the run
/// ends, and what is left for later.
type BannerResult = Result<(Vec<ApiRecord>, Option<Partial>), (RunError, Option<Partial>)>;

struct Pass {
    records: BTreeMap<u64, ApiRecord>,
    /// The floor it used, once known.
    floor: Option<u64>,
    end: PassEnd,
}

/// The state of one run.
pub(crate) struct Run<'a, S> {
    log: &'a mut LogClient<S>,
    tracker: &'a Tracker,
    progress: &'a (dyn Fn(Banner, u32) + Sync),
    page_cap: u32,
    uid: Option<String>,
    region: String,
    cursor: Option<Cursor>,
}

impl<'a, S: Sleeper> Run<'a, S> {
    pub(crate) fn new(
        log: &'a mut LogClient<S>,
        tracker: &'a Tracker,
        progress: &'a (dyn Fn(Banner, u32) + Sync),
        page_cap: u32,
    ) -> Self {
        Self {
            log,
            tracker,
            progress,
            page_cap,
            uid: None,
            region: String::new(),
            cursor: None,
        }
    }

    /// Sync `banners`, carrying on from and updating `partials`.
    pub(crate) async fn sync(
        mut self,
        banners: &[Banner],
        partials: &mut BTreeMap<Banner, Partial>,
    ) -> RunReport {
        let mut report = RunReport::default();
        let mut complete: Vec<ApiRecord> = Vec::new();
        // Partials change only once the import of the complete banners went
        // through: on a failed import nothing is known to have landed, and
        // the next run starts over from the tracker's cursor anyway.
        let mut staged = partials.clone();

        for (n, &banner) in banners.iter().enumerate() {
            if n > 0 {
                self.log.next_banner();
            }
            match self.banner(banner, staged.remove(&banner)).await {
                Ok((records, partial)) => {
                    complete.extend(records);
                    if let Some(partial) = partial {
                        staged.insert(banner, partial);
                    }
                }
                Err((error, partial)) => {
                    if let Some(partial) = partial {
                        staged.insert(banner, partial);
                    }
                    report.error = Some(error);
                    break;
                }
            }
        }
        report.uid = self.uid.clone();

        if !complete.is_empty() {
            let uid = self
                .uid
                .clone()
                .expect("records were read, so their UID is known");
            // Oldest first: an import cut short between chunks then leaves the
            // tracker's newest id below everything not yet sent.
            complete.sort_by_key(|record| record_id(record).unwrap_or(0));
            match self.tracker.import(&uid, &self.region, &complete).await {
                Ok(imported) => {
                    report.sent = complete.len();
                    report.imported = imported;
                }
                Err(error) => {
                    report.error = Some(RunError::Tracker(error));
                    report.unfinished = partials.keys().copied().collect();
                    return report;
                }
            }
        }
        *partials = staged;
        report.unfinished = partials.keys().copied().collect();
        report
    }

    /// One banner: the records it completed, and what is left for later.
    async fn banner(&mut self, banner: Banner, partial: Option<Partial>) -> BannerResult {
        let head_floor = match &partial {
            Some(partial) => Floor::Fixed(Some(partial.top)),
            None => Floor::Cursor,
        };
        let head = self
            .pass(banner, 0, 1, head_floor)
            .await
            .map_err(|error| (error, partial.clone()))?;

        let Some(mut partial) = partial else {
            return self.fresh(head);
        };

        // A partial of another account (the player switched) is dropped and
        // the banner read again against the cursor; one the history no longer
        // reaches (nothing read at all) is just dropped.
        match self.uid.as_deref() {
            Some(uid) if uid == partial.uid => {}
            Some(_) => {
                tracing::info!(
                    banner,
                    "dropping an unfinished wish sync of another account"
                );
                let head = self
                    .pass(banner, 0, 1, Floor::Cursor)
                    .await
                    .map_err(|error| (error, None))?;
                return self.fresh(head);
            }
            None => return Ok((Vec::new(), None)),
        }

        partial.records.extend(head.records);
        if let PassEnd::Cut { error, .. } = head.end {
            // The pass above the unfinished part did not get down to it (more
            // than a page cap of new wishes, or a failure). Its records are
            // kept -- they are real, and the set dedupes -- but `top` stays,
            // so the next run reads down to it again before going on below.
            tracing::info!(
                banner,
                "new wishes did not yet join up with the unfinished sync"
            );
            return match error {
                Some(error) => Err((error, Some(partial))),
                None => Ok((Vec::new(), Some(partial))),
            };
        }
        partial.top = partial
            .records
            .keys()
            .next_back()
            .copied()
            .unwrap_or(partial.top);

        let tail = match self
            .pass(
                banner,
                partial.end_id,
                partial.next_page,
                Floor::Fixed(partial.floor),
            )
            .await
        {
            Ok(tail) => tail,
            Err(error) => return Err((error, Some(partial))),
        };
        partial.records.extend(tail.records);
        match tail.end {
            PassEnd::Complete => Ok((partial.records.into_values().collect(), None)),
            PassEnd::Cut {
                end_id,
                next_page,
                error,
            } => {
                partial.end_id = end_id;
                partial.next_page = next_page;
                match error {
                    Some(error) => Err((error, Some(partial))),
                    None => Ok((Vec::new(), Some(partial))),
                }
            }
        }
    }

    /// The end of a banner that had nothing unfinished.
    fn fresh(&self, head: Pass) -> BannerResult {
        match head.end {
            PassEnd::Complete => Ok((head.records.into_values().collect(), None)),
            PassEnd::Cut {
                end_id,
                next_page,
                error,
            } => {
                let partial = self.partial_from(head.floor, head.records, end_id, next_page);
                match error {
                    Some(error) => Err((error, partial)),
                    None => Ok((Vec::new(), partial)),
                }
            }
        }
    }

    fn partial_from(
        &self,
        floor: Option<u64>,
        records: BTreeMap<u64, ApiRecord>,
        end_id: u64,
        next_page: u32,
    ) -> Option<Partial> {
        let top = *records.keys().next_back()?;
        Some(Partial {
            uid: self.uid.clone()?,
            floor,
            top,
            end_id,
            next_page,
            records,
        })
    }

    /// Read pages from `end_id` (0 = the newest) down to `floor`.
    ///
    /// `Err` only for what ends the run before a single page of this pass was
    /// usable; anything later comes back as [`PassEnd::Cut`] with the records
    /// read so far.
    async fn pass(
        &mut self,
        banner: Banner,
        mut end_id: u64,
        mut page: u32,
        floor: Floor,
    ) -> Result<Pass, RunError> {
        let mut records = BTreeMap::new();
        let mut known_floor = match floor {
            Floor::Fixed(floor) => Some(floor),
            Floor::Cursor => self.cursor.as_ref().map(|cursor| cursor.newest(banner)),
        };
        for read in 0.. {
            if read == self.page_cap {
                return Ok(Pass {
                    records,
                    floor: known_floor.flatten(),
                    end: PassEnd::Cut {
                        end_id,
                        next_page: page,
                        error: None,
                    },
                });
            }
            (self.progress)(banner, page);
            let answer = match self.log.page(banner, page, end_id).await {
                Ok(answer) => answer,
                Err(error) if records.is_empty() && read == 0 => return Err(error.into()),
                Err(error) => {
                    return Ok(Pass {
                        records,
                        floor: known_floor.flatten(),
                        end: PassEnd::Cut {
                            end_id,
                            next_page: page,
                            error: Some(error.into()),
                        },
                    });
                }
            };
            if answer.records.is_empty() {
                break;
            }
            if self.region.is_empty() {
                self.region = answer.region.clone();
            }
            self.check_uid(&answer.records)?;
            let floor = match known_floor {
                Some(floor) => floor,
                None => {
                    let uid = self.uid.clone().expect("check_uid set it");
                    let cursor = self.tracker.cursor(&uid).await.map_err(RunError::Tracker)?;
                    let floor = cursor.newest(banner);
                    self.cursor = Some(cursor);
                    known_floor = Some(floor);
                    floor
                }
            };

            let mut reached_known = false;
            let mut last = None;
            for record in answer.records {
                let id = record_id(&record)?;
                last = Some(id);
                if floor.is_some_and(|floor| id <= floor) {
                    reached_known = true;
                } else {
                    records.insert(id, record);
                }
            }
            if reached_known {
                break;
            }
            end_id = last.expect("the page was not empty");
            page += 1;
        }
        Ok(Pass {
            records,
            floor: known_floor.flatten(),
            end: PassEnd::Complete,
        })
    }

    /// Every record must be the same account's: the first one read decides.
    fn check_uid(&mut self, records: &[ApiRecord]) -> Result<(), RunError> {
        for record in records {
            match &self.uid {
                None => self.uid = Some(record.uid.clone()),
                Some(uid) if *uid == record.uid => {}
                Some(_) => {
                    return Err(RunError::Data(
                        "the wish history holds records of more than one UID".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn record_id(record: &ApiRecord) -> Result<u64, RunError> {
    record
        .id
        .parse()
        .map_err(|_| RunError::Data("the wish history sent a record with a bad id".to_owned()))
}
