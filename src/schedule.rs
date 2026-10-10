use crate::cache::Family;
use crate::config::ALLOWLIST_MAX;

/// Lower bound of the normal and negative refresh intervals, in seconds.
pub const REFRESH_MIN: u64 = 30;

/// Upper bound of the normal and negative refresh intervals, in seconds.
pub const REFRESH_MAX: u64 = 300;

/// The bounded retry backoff ladder, in seconds. The final stage repeats until
/// a validated positive answer with cacheable bindings resets the type.
pub const BACKOFF_STAGES: [u64; 6] = [1, 2, 4, 8, 16, 30];

const LAST_BACKOFF_STAGE: u8 = (BACKOFF_STAGES.len() - 1) as u8;

/// The SOA TTL and MINIMUM of a validated negative answer, used to schedule
/// the next negative refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Soa {
    ttl: u64,
    minimum: u64,
}

impl Soa {
    pub fn new(ttl: u64, minimum: u64) -> Soa {
        Soa { ttl, minimum }
    }

    fn min_ttl(self) -> u64 {
        self.ttl.min(self.minimum)
    }
}

/// Returns the normal refresh interval for an entry TTL, honoring the fixed
/// 30/300-second bounds. The floor subsumes the zero-TTL-as-one-second rule.
pub fn normal_refresh_interval(ttl: u64) -> u64 {
    ttl.clamp(REFRESH_MIN, REFRESH_MAX)
}

/// Returns the negative refresh interval for a validated negative answer's
/// SOA, honoring the same fixed bounds after taking the earlier of its TTL and
/// MINIMUM.
pub fn negative_refresh_interval(soa: Soa) -> u64 {
    soa.min_ttl().clamp(REFRESH_MIN, REFRESH_MAX)
}

fn advance_backoff(stage: u8) -> u8 {
    stage.saturating_add(1).min(LAST_BACKOFF_STAGE)
}

/// Reasons a scheduling operation can refuse; every failure leaves the table
/// unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleError {
    NameOutOfRange,
    DeadlineOverflow,
}

/// One fixed schedule slot: one due time per name and family, one in-flight
/// flag, one start-rate guard, and one independent retry backoff stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    due: Option<u64>,
    pending: bool,
    not_before: u64,
    backoff: u8,
}

const UNDUE: Slot = Slot {
    due: None,
    pending: false,
    not_before: 0,
    backoff: 0,
};

/// A by-value record of one exchange selected from the due table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DueToken {
    name: usize,
    family: Family,
}

impl DueToken {
    /// The admitted name index of the selected exchange, matching
    /// `Cache::name_index` numbering for later cache integration.
    pub fn name(&self) -> usize {
        self.name
    }

    /// The record family of the selected exchange.
    pub fn family(&self) -> Family {
        self.family
    }
}

fn family_slot(family: Family) -> usize {
    match family {
        Family::A => 0,
        Family::Aaaa => 1,
    }
}

/// The fixed per-name, per-family DNS due table with independent retry state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedules {
    name_count: u8,
    next_scan: u8,
    slots: [[Slot; 2]; ALLOWLIST_MAX],
}

impl Schedules {
    /// Constructs a fixed due table admitting `name_count` allowlist names.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name_count` is zero or exceeds
    /// `ALLOWLIST_MAX`.
    pub fn new(name_count: usize) -> Result<Schedules, ScheduleError> {
        if name_count == 0 || name_count > ALLOWLIST_MAX {
            return Err(ScheduleError::NameOutOfRange);
        }
        let name_count = u8::try_from(name_count).map_err(|_| ScheduleError::NameOutOfRange)?;
        Ok(Schedules {
            name_count,
            next_scan: 0,
            slots: [[UNDUE; 2]; ALLOWLIST_MAX],
        })
    }

    /// The number of admitted names.
    pub fn name_count(&self) -> usize {
        usize::from(self.name_count)
    }

    fn slot(&self, name: usize, family: Family) -> &Slot {
        &self.slots[name][family_slot(family)]
    }

    fn slot_mut(&mut self, name: usize, family: Family) -> &mut Slot {
        &mut self.slots[name][family_slot(family)]
    }

    fn admit(&self, name: usize) -> Result<(), ScheduleError> {
        if name < self.name_count() {
            Ok(())
        } else {
            Err(ScheduleError::NameOutOfRange)
        }
    }

    /// The currently scheduled due time for `name` and `family`, when any.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted.
    pub fn due_time(&self, name: usize, family: Family) -> Result<Option<u64>, ScheduleError> {
        self.admit(name)?;
        Ok(self.slot(name, family).due)
    }

    /// Overwrites the due time for `name` and `family` with `due`, superseding
    /// any prior schedule for the same slot and its in-flight marker.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted.
    pub fn overwrite_due_at(
        &mut self,
        name: usize,
        family: Family,
        due: u64,
    ) -> Result<(), ScheduleError> {
        self.admit(name)?;
        let slot = self.slot_mut(name, family);
        slot.due = Some(due);
        slot.pending = false;
        Ok(())
    }

    /// Completes a selection that performed no exchange: clears the in-flight
    /// marker while preserving the due time and the one-second start guard. A
    /// resolved name's skipped sibling family therefore stays selectable for a
    /// later serving refresh without its pending flag leaking.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted.
    pub fn release_selection(&mut self, name: usize, family: Family) -> Result<(), ScheduleError> {
        self.admit(name)?;
        self.slot_mut(name, family).pending = false;
        Ok(())
    }

    /// Records a validated positive outcome for one family.
    ///
    /// A cacheable positive resets that family's backoff and schedules the next
    /// normal refresh from `receipt`; a positive without cacheable bindings
    /// advances the backoff and schedules a retry from `now`.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` or `DeadlineOverflow`; on either the slot is
    /// unchanged.
    pub fn note_positive(
        &mut self,
        name: usize,
        family: Family,
        receipt: u64,
        ttl: u64,
        cacheable: bool,
        now: u64,
    ) -> Result<(), ScheduleError> {
        self.admit(name)?;
        let slot = self.slot_mut(name, family);
        let stage = slot.backoff;
        let (new_due, new_stage) = if cacheable {
            (
                receipt
                    .checked_add(normal_refresh_interval(ttl))
                    .ok_or(ScheduleError::DeadlineOverflow)?,
                0,
            )
        } else {
            (
                now.checked_add(BACKOFF_STAGES[usize::from(stage)])
                    .ok_or(ScheduleError::DeadlineOverflow)?,
                advance_backoff(stage),
            )
        };
        slot.due = Some(new_due);
        slot.backoff = new_stage;
        slot.pending = false;
        Ok(())
    }

    /// Records an exchange failure for one family, scheduling a retry from
    /// `now` at that family's current backoff stage and advancing the ladder.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` or `DeadlineOverflow`; on either the slot is
    /// unchanged.
    pub fn note_exchange_failure(
        &mut self,
        name: usize,
        family: Family,
        now: u64,
    ) -> Result<(), ScheduleError> {
        self.admit(name)?;
        let slot = self.slot_mut(name, family);
        let stage = slot.backoff;
        let new_due = now
            .checked_add(BACKOFF_STAGES[usize::from(stage)])
            .ok_or(ScheduleError::DeadlineOverflow)?;
        slot.due = Some(new_due);
        slot.backoff = advance_backoff(stage);
        slot.pending = false;
        Ok(())
    }

    /// Records a validated NXDOMAIN for the whole name.
    ///
    /// With an SOA, both families are scheduled for the negative refresh from
    /// `receipt` and their backoff stages are left untouched; without an SOA,
    /// both families advance their backoff and schedule from `now`.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` or `DeadlineOverflow`; on either error no slot
    /// changes.
    pub fn note_nxdomain(
        &mut self,
        name: usize,
        soa: Option<Soa>,
        receipt: u64,
        now: u64,
    ) -> Result<(), ScheduleError> {
        self.admit(name)?;
        let mut new_due = [0u64; 2];
        let mut new_stage = [0u8; 2];
        for (i, family) in [Family::A, Family::Aaaa].into_iter().enumerate() {
            let slot = self.slot(name, family);
            match soa {
                Some(soa) => {
                    new_due[i] = receipt
                        .checked_add(negative_refresh_interval(soa))
                        .ok_or(ScheduleError::DeadlineOverflow)?;
                    new_stage[i] = slot.backoff;
                }
                None => {
                    new_due[i] = now
                        .checked_add(BACKOFF_STAGES[usize::from(slot.backoff)])
                        .ok_or(ScheduleError::DeadlineOverflow)?;
                    new_stage[i] = advance_backoff(slot.backoff);
                }
            }
        }
        for (i, family) in [Family::A, Family::Aaaa].into_iter().enumerate() {
            let slot = self.slot_mut(name, family);
            slot.due = Some(new_due[i]);
            slot.backoff = new_stage[i];
            slot.pending = false;
        }
        Ok(())
    }

    /// Records a validated NODATA for the queried family only.
    ///
    /// With an SOA, the family is scheduled for the negative refresh from
    /// `receipt` and its backoff stage is left untouched; without an SOA, its
    /// backoff advances and schedules from `now`. The other family is
    /// unaffected.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` or `DeadlineOverflow`; on either the slot is
    /// unchanged.
    pub fn note_nodata(
        &mut self,
        name: usize,
        family: Family,
        soa: Option<Soa>,
        receipt: u64,
        now: u64,
    ) -> Result<(), ScheduleError> {
        self.admit(name)?;
        let slot = self.slot_mut(name, family);
        let stage = slot.backoff;
        let (new_due, new_stage) = match soa {
            Some(soa) => (
                receipt
                    .checked_add(negative_refresh_interval(soa))
                    .ok_or(ScheduleError::DeadlineOverflow)?,
                stage,
            ),
            None => (
                now.checked_add(BACKOFF_STAGES[usize::from(stage)])
                    .ok_or(ScheduleError::DeadlineOverflow)?,
                advance_backoff(stage),
            ),
        };
        slot.due = Some(new_due);
        slot.backoff = new_stage;
        slot.pending = false;
        Ok(())
    }

    /// Selects at most one due exchange, scanning in fixed rotating
    /// round-robin order from the last served slot so repeated failures cannot
    /// monopolize selection.
    ///
    /// A selected slot is marked pending and rate-limited to at most one start
    /// per second until an outcome routes back; the returned token is by value,
    /// and tracking a single globally outstanding exchange belongs to the later
    /// transport owner. Delayed processing coalesces: an overdue slot is simply
    /// selected once when scanned, with no catch-up queue.
    ///
    /// # Errors
    ///
    /// Returns `DeadlineOverflow` only when the start-rate timestamp cannot be
    /// represented (at `now == u64::MAX`); no slot is changed.
    pub fn select_due(&mut self, now: u64) -> Result<Option<DueToken>, ScheduleError> {
        let total = self.name_count() * 2;
        for step in 0..total {
            let linear = (usize::from(self.next_scan) + step) % total;
            let name = linear / 2;
            let family = match linear % 2 {
                0 => Family::A,
                _ => Family::Aaaa,
            };
            let slot = self.slot(name, family);
            if slot.pending || slot.not_before > now {
                continue;
            }
            let Some(due) = slot.due else {
                continue;
            };
            if due > now {
                continue;
            }
            let not_before = now.checked_add(1).ok_or(ScheduleError::DeadlineOverflow)?;
            let slot = self.slot_mut(name, family);
            slot.pending = true;
            slot.not_before = not_before;
            self.next_scan = ((linear + 1) % total) as u8;
            return Ok(Some(DueToken { name, family }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc-witness")]
    use crate::alloc::{Phase, run_phase};

    #[test]
    fn new_admits_only_actual_configured_count() {
        assert_eq!(Schedules::new(0), Err(ScheduleError::NameOutOfRange));
        assert_eq!(
            Schedules::new(ALLOWLIST_MAX + 1),
            Err(ScheduleError::NameOutOfRange)
        );
        for count in [1usize, 2, 31, ALLOWLIST_MAX] {
            assert_eq!(Schedules::new(count).unwrap().name_count(), count);
        }
    }

    #[test]
    fn out_of_range_operations_err_without_mutation() {
        let mut schedules = Schedules::new(2).unwrap();
        let before = schedules;
        assert_eq!(
            schedules.due_time(7, Family::A),
            Err(ScheduleError::NameOutOfRange)
        );
        assert_eq!(
            schedules.overwrite_due_at(7, Family::A, 0),
            Err(ScheduleError::NameOutOfRange)
        );
        assert_eq!(
            schedules.note_positive(7, Family::A, 0, 60, true, 0),
            Err(ScheduleError::NameOutOfRange)
        );
        assert_eq!(
            schedules.note_exchange_failure(7, Family::A, 0),
            Err(ScheduleError::NameOutOfRange)
        );
        assert_eq!(
            schedules.note_nxdomain(7, None, 0, 0),
            Err(ScheduleError::NameOutOfRange)
        );
        assert_eq!(
            schedules.note_nodata(7, Family::A, None, 0, 0),
            Err(ScheduleError::NameOutOfRange)
        );
        assert_eq!(schedules, before, "out-of-range calls must not mutate");
    }

    #[test]
    fn overwrite_supersedes_without_queue() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules
            .note_positive(0, Family::A, 1000, 60, true, 0)
            .unwrap();
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(1060));
        schedules.note_exchange_failure(0, Family::A, 2000).unwrap();
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(2001));
    }

    #[test]
    fn rotating_scan_selects_every_slot_once_per_pass() {
        let mut schedules = Schedules::new(ALLOWLIST_MAX).unwrap();
        for name in 0..ALLOWLIST_MAX {
            schedules.overwrite_due_at(name, Family::A, 0).unwrap();
            schedules.overwrite_due_at(name, Family::Aaaa, 0).unwrap();
        }
        let mut selected = [[false; 2]; ALLOWLIST_MAX];
        for _ in 0..(ALLOWLIST_MAX * 2) {
            let token = schedules.select_due(0).unwrap().expect("due");
            assert!(
                !selected[token.name()][family_slot(token.family())],
                "slot re-selected before a full pass"
            );
            selected[token.name()][family_slot(token.family())] = true;
        }
        assert_eq!(schedules.select_due(0).unwrap(), None, "pass exhausted");
    }

    #[test]
    fn repeated_failures_do_not_starve_other_names() {
        let mut schedules = Schedules::new(2).unwrap();
        for name in 0..2 {
            schedules.overwrite_due_at(name, Family::A, 0).unwrap();
            schedules.overwrite_due_at(name, Family::Aaaa, 0).unwrap();
        }
        for now in [0u64, 1] {
            let mut served = [[false; 2]; 2];
            for _ in 0..4 {
                let token = schedules.select_due(now).unwrap().expect("due");
                assert!(!served[token.name()][family_slot(token.family())]);
                served[token.name()][family_slot(token.family())] = true;
                schedules
                    .note_exchange_failure(token.name(), token.family(), now)
                    .unwrap();
            }
            for row in &served {
                for slot in row {
                    assert!(slot, "slot served");
                }
            }
        }
    }

    #[test]
    fn selected_slot_stays_pending_until_outcome_completes() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.overwrite_due_at(0, Family::A, 0).unwrap();
        let token = schedules.select_due(0).unwrap().unwrap();
        assert_eq!((token.name(), token.family()), (0, Family::A));
        assert_eq!(
            schedules.select_due(0).unwrap(),
            None,
            "pending slot is not re-selected"
        );
        schedules.overwrite_due_at(0, Family::A, 0).unwrap();
        assert_eq!(
            schedules.select_due(0).unwrap(),
            None,
            "start-rate guard blocks reselection in the same second"
        );
        assert!(
            schedules.select_due(1).unwrap().is_some(),
            "completed slot re-selectable after the one-second start guard"
        );
    }

    #[test]
    fn release_selection_clears_pending_keeps_due_and_guard() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.overwrite_due_at(0, Family::Aaaa, 1000).unwrap();
        let token = schedules.select_due(1000).unwrap().expect("due");
        assert_eq!((token.name(), token.family()), (0, Family::Aaaa));
        assert_eq!(
            schedules.select_due(1000).unwrap(),
            None,
            "selected slot is pending until released"
        );
        schedules.release_selection(0, Family::Aaaa).unwrap();
        assert_eq!(schedules.due_time(0, Family::Aaaa).unwrap(), Some(1000));
        assert_eq!(
            schedules.select_due(1000).unwrap(),
            None,
            "start guard still rate-limits re-selection in the same second"
        );
        assert!(schedules.select_due(1001).unwrap().is_some());
        assert_eq!(
            schedules.due_time(0, Family::Aaaa).unwrap(),
            Some(1000),
            "release must not retarget the due time"
        );
        assert_eq!(
            schedules.release_selection(1, Family::A),
            Err(ScheduleError::NameOutOfRange)
        );
    }

    #[test]
    fn normal_refresh_interval_honors_bounds() {
        let vectors = [
            (0u64, 30u64),
            (1, 30),
            (29, 30),
            (30, 30),
            (31, 31),
            (299, 299),
            (300, 300),
            (301, 300),
        ];
        for (ttl, expect) in vectors {
            assert_eq!(normal_refresh_interval(ttl), expect, "ttl={ttl}");
        }
    }

    #[test]
    fn negative_refresh_interval_honors_soa_and_bounds() {
        let cases = [
            (Soa::new(1, 1), 30u64),
            (Soa::new(29, 1000), 30),
            (Soa::new(30, 30), 30),
            (Soa::new(50, 10), 30),
            (Soa::new(31, 1000), 31),
            (Soa::new(299, 1000), 299),
            (Soa::new(1000, 300), 300),
            (Soa::new(301, 301), 300),
        ];
        for (soa, expect) in cases {
            assert_eq!(negative_refresh_interval(soa), expect, "soa={soa:?}");
        }
    }

    #[test]
    fn backoff_ladder_is_exact_and_capped() {
        let mut schedules = Schedules::new(1).unwrap();
        let mut dues = [0u64; 8];
        for due in dues.iter_mut() {
            schedules.note_exchange_failure(0, Family::A, 0).unwrap();
            *due = schedules.due_time(0, Family::A).unwrap().unwrap();
        }
        assert_eq!(&dues[..], &[1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[test]
    fn nxdomain_schedules_both_families_nodata_only_own() {
        let mut schedules = Schedules::new(1).unwrap();
        let soa = Soa::new(60, 60);
        schedules.note_nxdomain(0, Some(soa), 1000, 0).unwrap();
        let expected = 1000 + negative_refresh_interval(soa);
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(expected));
        assert_eq!(schedules.due_time(0, Family::Aaaa).unwrap(), Some(expected));

        schedules.overwrite_due_at(0, Family::A, 5000).unwrap();
        schedules.overwrite_due_at(0, Family::Aaaa, 6000).unwrap();
        schedules
            .note_nodata(0, Family::A, Some(soa), 2000, 0)
            .unwrap();
        let nodata_expected = 2000 + negative_refresh_interval(soa);
        assert_eq!(
            schedules.due_time(0, Family::A).unwrap(),
            Some(nodata_expected)
        );
        assert_eq!(
            schedules.due_time(0, Family::Aaaa).unwrap(),
            Some(6000),
            "NODATA must not touch the other family"
        );
    }

    #[test]
    fn soa_negatives_leave_backoff_stage_unchanged() {
        let mut schedules = Schedules::new(1).unwrap();
        for _ in 0..2 {
            schedules.note_exchange_failure(0, Family::A, 0).unwrap();
            schedules.note_exchange_failure(0, Family::Aaaa, 0).unwrap();
        }
        let soa = Soa::new(60, 60);
        schedules.note_nxdomain(0, Some(soa), 1000, 0).unwrap();
        schedules
            .note_nodata(0, Family::A, Some(soa), 2000, 0)
            .unwrap();
        schedules.note_exchange_failure(0, Family::A, 3000).unwrap();
        schedules
            .note_exchange_failure(0, Family::Aaaa, 4000)
            .unwrap();
        assert_eq!(
            schedules.due_time(0, Family::A).unwrap(),
            Some(3004),
            "stage 2 ladder used after SOA negatives on own family"
        );
        assert_eq!(
            schedules.due_time(0, Family::Aaaa).unwrap(),
            Some(4004),
            "stage 2 ladder used after SOA negatives on other family"
        );
    }

    #[test]
    fn nxdomain_without_soa_one_family_overflow_commits_nothing() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.note_exchange_failure(0, Family::Aaaa, 0).unwrap();
        let before = schedules;
        let near_max = u64::MAX - 1;
        assert_eq!(
            schedules.note_nxdomain(0, None, 0, near_max),
            Err(ScheduleError::DeadlineOverflow),
            "A fits while Aaaa overflows; two-phase commit must refuse both"
        );
        assert_eq!(schedules, before, "no partial application");
    }

    #[test]
    fn long_overdue_slot_selects_once_without_catchup() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.overwrite_due_at(0, Family::A, 0).unwrap();
        let token = schedules.select_due(1000).unwrap().unwrap();
        assert_eq!((token.name(), token.family()), (0, Family::A));
        schedules.note_exchange_failure(0, Family::A, 1000).unwrap();
        assert_eq!(
            schedules.select_due(1000).unwrap(),
            None,
            "overdue delay yields one selection, not a catch-up queue"
        );
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(1001));
    }

    #[test]
    fn nxdomain_without_soa_advances_both_backoffs() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.note_nxdomain(0, None, 0, 1000).unwrap();
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(1001));
        assert_eq!(schedules.due_time(0, Family::Aaaa).unwrap(), Some(1001));
        schedules.note_nxdomain(0, None, 0, 2000).unwrap();
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(2002));
        assert_eq!(schedules.due_time(0, Family::Aaaa).unwrap(), Some(2002));
    }

    #[test]
    fn cacheable_positive_resets_only_its_own_family_backoff() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.note_exchange_failure(0, Family::A, 0).unwrap();
        schedules.note_exchange_failure(0, Family::Aaaa, 0).unwrap();
        schedules
            .note_positive(0, Family::A, 1000, 60, true, 0)
            .unwrap();
        schedules.note_exchange_failure(0, Family::A, 2000).unwrap();
        assert_eq!(
            schedules.due_time(0, Family::A).unwrap(),
            Some(2001),
            "cacheable positive resets its own backoff"
        );
        schedules
            .note_exchange_failure(0, Family::Aaaa, 3000)
            .unwrap();
        assert_eq!(
            schedules.due_time(0, Family::Aaaa).unwrap(),
            Some(3002),
            "other family's backoff is untouched"
        );
    }

    #[test]
    fn empty_eligible_positive_advances_backoff() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules
            .note_positive(0, Family::A, 1000, 60, false, 0)
            .unwrap();
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(1));
        schedules
            .note_positive(0, Family::A, 2000, 60, false, 0)
            .unwrap();
        assert_eq!(schedules.due_time(0, Family::A).unwrap(), Some(2));
    }

    #[test]
    fn deadline_overflow_errs_without_mutation() {
        let mut schedules = Schedules::new(1).unwrap();
        schedules.overwrite_due_at(0, Family::A, 100).unwrap();
        schedules.overwrite_due_at(0, Family::Aaaa, 200).unwrap();
        let before = schedules;
        let near_max = u64::MAX - 10;
        assert_eq!(
            schedules.note_positive(0, Family::A, near_max, 60, true, 0),
            Err(ScheduleError::DeadlineOverflow)
        );
        assert_eq!(
            schedules.note_nxdomain(0, Some(Soa::new(60, 60)), near_max, 0),
            Err(ScheduleError::DeadlineOverflow)
        );
        assert_eq!(
            schedules, before,
            "deadline overflow must not mutate either slot"
        );
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn scheduler_paths_do_not_allocate_or_deallocate() {
        let (_, control) = run_phase(Phase::BackgroundRefresh, || 0usize);
        assert!(control.all_zero(), "baseline should be quiet: {control:?}");
        let (_, failure_path) = run_phase(Phase::BackgroundRefresh, || {
            let mut schedules = Schedules::new(2).unwrap();
            for name in 0..2 {
                schedules.overwrite_due_at(name, Family::A, 0).unwrap();
                schedules.overwrite_due_at(name, Family::Aaaa, 0).unwrap();
            }
            for now in [0u64, 1] {
                while let Some(token) = schedules.select_due(now).unwrap() {
                    schedules
                        .note_exchange_failure(token.name(), token.family(), now)
                        .unwrap();
                }
            }
        });
        assert!(
            failure_path.all_zero(),
            "failure path allocated: {failure_path:?}"
        );
        let (_, success_path) = run_phase(Phase::BackgroundRefresh, || {
            let mut schedules = Schedules::new(1).unwrap();
            schedules
                .note_positive(0, Family::A, 1000, 60, true, 0)
                .unwrap();
            schedules
                .note_nxdomain(0, Some(Soa::new(60, 60)), 2000, 0)
                .unwrap();
            schedules
                .note_nodata(0, Family::Aaaa, None, 0, 3000)
                .unwrap();
            while let Some(token) = schedules.select_due(3000).unwrap() {
                schedules
                    .note_exchange_failure(token.name(), token.family(), 3000)
                    .unwrap();
            }
        });
        assert!(
            success_path.all_zero(),
            "success path allocated: {success_path:?}"
        );
    }
}
