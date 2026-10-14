use super::action::{AnyIllegalScope, DomainOrdinal};
use super::policy::{AnyIllegalCause, Effect, UnknownReason};
use super::state::SaturatingCounter;
use crate::config::ALLOWLIST_MAX;

pub(crate) const CAPTURE_DETAIL_LEN: usize = 64;

#[derive(Clone, Copy, Debug, Default)]
pub struct FactCounters {
    pub(crate) any_illegal: [SaturatingCounter; AnyIllegalCause::KIND_COUNT],
    pub(crate) early_data: [SaturatingCounter; ALLOWLIST_MAX],
    pub(crate) unknown: [SaturatingCounter; UnknownReason::COUNT],
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ActionCounters {
    pub(crate) first_slot_block: [SaturatingCounter; AnyIllegalScope::COUNT],
    pub(crate) domain_block: [SaturatingCounter; ALLOWLIST_MAX],
    pub(crate) flare: [SaturatingCounter; ALLOWLIST_MAX],
    pub(crate) block_all: SaturatingCounter,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RefusalCounters {
    pub(crate) blocked_domain: [SaturatingCounter; ALLOWLIST_MAX],
}

#[derive(Clone, Copy, Debug)]
pub struct Monitor {
    pub(crate) facts: FactCounters,
    pub(crate) actions: ActionCounters,
    pub(crate) refusals: RefusalCounters,
    pub(crate) report_drops: SaturatingCounter,
    captures: [Option<ConsumedCapture>; CAPTURE_DETAIL_LEN],
    capture_head: usize,
    capture_len: usize,
    capture_drops: SaturatingCounter,
    dirty: bool,
    last_report_secs: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapturedFact {
    AnyIllegal(AnyIllegalCause),
    EarlyData(DomainOrdinal),
    Unknown(UnknownReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapturedDetail {
    pub(crate) fact: CapturedFact,
    pub(crate) effect: Effect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumedCapture {
    pub(crate) slot: usize,
    pub(crate) generation: u64,
    pub(crate) detail: CapturedDetail,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotCapture {
    pub(crate) slot: usize,
    pub(crate) generation: u64,
    pub(crate) detail: Option<CapturedDetail>,
}

impl SlotCapture {
    pub(crate) fn fresh(slot: usize, generation: u64) -> SlotCapture {
        SlotCapture {
            slot,
            generation,
            detail: None,
        }
    }
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Monitor {
    pub(crate) fn new() -> Monitor {
        Monitor {
            facts: FactCounters::default(),
            actions: ActionCounters::default(),
            refusals: RefusalCounters::default(),
            report_drops: SaturatingCounter::new(),
            captures: std::array::from_fn(|_| None),
            capture_head: 0,
            capture_len: 0,
            capture_drops: SaturatingCounter::new(),
            dirty: false,
            last_report_secs: None,
        }
    }

    pub(crate) fn note_fact_any_illegal(&mut self, cause: AnyIllegalCause) {
        self.facts.any_illegal[cause.kind_index()].bump();
        self.dirty = true;
    }

    pub(crate) fn note_fact_early_data(&mut self, ordinal: DomainOrdinal) {
        self.facts.early_data[ordinal.get()].bump();
        self.dirty = true;
    }

    pub(crate) fn note_fact_unknown(&mut self, reason: UnknownReason) {
        self.facts.unknown[reason.index()].bump();
        self.dirty = true;
    }

    pub(crate) fn note_action_first_slot_block(&mut self, scope: AnyIllegalScope) {
        self.actions.first_slot_block[scope as usize].bump();
        self.dirty = true;
    }

    pub(crate) fn note_action_domain_block(&mut self, ordinal: DomainOrdinal) {
        self.actions.domain_block[ordinal.get()].bump();
        self.dirty = true;
    }

    pub(crate) fn note_action_flare(&mut self, ordinal: DomainOrdinal) {
        self.actions.flare[ordinal.get()].bump();
        self.dirty = true;
    }

    pub(crate) fn note_block_all(&mut self) {
        self.actions.block_all.bump();
        self.dirty = true;
    }

    pub(crate) fn note_refusal_blocked_domain(&mut self, ordinal: DomainOrdinal) {
        self.refusals.blocked_domain[ordinal.get()].bump();
        self.dirty = true;
    }

    pub(crate) fn note_report_drop(&mut self) {
        self.report_drops.bump();
        self.dirty = true;
    }

    pub(crate) fn note_consumed_capture(&mut self, capture: SlotCapture) {
        let Some(detail) = capture.detail else {
            return;
        };
        let consumed = ConsumedCapture {
            slot: capture.slot,
            generation: capture.generation,
            detail,
        };
        if self.capture_len == CAPTURE_DETAIL_LEN {
            self.capture_drops.bump();
            self.captures[self.capture_head] = Some(consumed);
            self.capture_head = (self.capture_head + 1) % CAPTURE_DETAIL_LEN;
        } else {
            let index = (self.capture_head + self.capture_len) % CAPTURE_DETAIL_LEN;
            self.captures[index] = Some(consumed);
            self.capture_len += 1;
        }
        self.dirty = true;
    }

    pub(crate) fn note_suppressed_detail(&mut self) {
        self.capture_drops.bump();
        self.dirty = true;
    }

    pub(crate) fn report_due(&self, secs: u64) -> bool {
        self.dirty && self.last_report_secs != Some(secs)
    }

    pub(crate) fn mark_reported(&mut self, secs: u64, committed: bool) {
        self.last_report_secs = Some(secs);
        if committed {
            self.dirty = false;
            self.clear_captures();
        } else {
            self.note_report_drop();
        }
    }

    pub(crate) fn mark_forced_reported(&mut self, committed: bool) {
        if committed {
            self.dirty = false;
            self.clear_captures();
        } else {
            self.note_report_drop();
        }
    }

    fn clear_captures(&mut self) {
        self.captures = std::array::from_fn(|_| None);
        self.capture_head = 0;
        self.capture_len = 0;
    }

    #[cfg(test)]
    pub(crate) fn last_report_secs(&self) -> Option<u64> {
        self.last_report_secs
    }

    #[cfg(test)]
    pub(crate) fn facts_any_illegal(&self, cause: AnyIllegalCause) -> u32 {
        self.facts.any_illegal[cause.kind_index()].value()
    }

    pub(crate) fn facts_any_illegal_total(&self) -> u64 {
        self.facts
            .any_illegal
            .iter()
            .map(|c| u64::from(c.value()))
            .sum()
    }

    pub(crate) fn facts_early_data(&self, ordinal: DomainOrdinal) -> u32 {
        self.facts.early_data[ordinal.get()].value()
    }

    #[cfg(test)]
    pub(crate) fn facts_unknown(&self, reason: UnknownReason) -> u32 {
        self.facts.unknown[reason.index()].value()
    }

    pub(crate) fn facts_any_illegal_by_index(&self, index: usize) -> u32 {
        self.facts.any_illegal[index].value()
    }

    pub(crate) fn facts_unknown_by_index(&self, index: usize) -> u32 {
        self.facts.unknown[index].value()
    }

    pub(crate) fn unknown_total(&self) -> u64 {
        self.facts
            .unknown
            .iter()
            .map(|c| u64::from(c.value()))
            .sum()
    }

    pub(crate) fn facts_total(&self) -> u64 {
        self.facts_any_illegal_total()
            + self
                .facts
                .early_data
                .iter()
                .map(|c| u64::from(c.value()))
                .sum::<u64>()
            + self.unknown_total()
    }

    pub(crate) fn actions_block_all(&self) -> u32 {
        self.actions.block_all.value()
    }

    pub(crate) fn actions_domain_block(&self, ordinal: DomainOrdinal) -> u32 {
        self.actions.domain_block[ordinal.get()].value()
    }

    pub(crate) fn refusals_blocked_domain(&self, ordinal: DomainOrdinal) -> u32 {
        self.refusals.blocked_domain[ordinal.get()].value()
    }

    pub(crate) fn actions_first_slot_block(&self, scope: AnyIllegalScope) -> u32 {
        self.actions.first_slot_block[scope as usize].value()
    }

    pub(crate) fn actions_total(&self) -> u64 {
        self.actions
            .domain_block
            .iter()
            .map(|c| u64::from(c.value()))
            .sum::<u64>()
            + self
                .actions
                .flare
                .iter()
                .map(|c| u64::from(c.value()))
                .sum::<u64>()
            + self
                .actions
                .first_slot_block
                .iter()
                .map(|c| u64::from(c.value()))
                .sum::<u64>()
    }

    pub(crate) fn actions_flare(&self, ordinal: DomainOrdinal) -> u32 {
        self.actions.flare[ordinal.get()].value()
    }

    pub(crate) fn refusals_total(&self) -> u64 {
        self.refusals
            .blocked_domain
            .iter()
            .map(|c| u64::from(c.value()))
            .sum()
    }

    pub(crate) fn capture_detail_len(&self) -> usize {
        self.capture_len
    }

    pub(crate) fn capture_detail(&self, i: usize) -> Option<ConsumedCapture> {
        if i >= self.capture_len {
            return None;
        }
        self.captures[(self.capture_head + i) % CAPTURE_DETAIL_LEN]
    }

    pub(crate) fn capture_drops(&self) -> u32 {
        self.capture_drops.value()
    }

    pub(crate) fn capture_drops_overflow(&self) -> bool {
        self.capture_drops.overflow()
    }

    pub(crate) fn report_drops(&self) -> u32 {
        self.report_drops.value()
    }

    pub(crate) fn facts_any_illegal_overflow(&self) -> bool {
        self.facts
            .any_illegal
            .iter()
            .any(SaturatingCounter::overflow)
    }

    pub(crate) fn facts_early_data_overflow(&self) -> bool {
        self.facts
            .early_data
            .iter()
            .any(SaturatingCounter::overflow)
    }

    pub(crate) fn facts_unknown_overflow(&self) -> bool {
        self.facts.unknown.iter().any(SaturatingCounter::overflow)
    }

    pub(crate) fn actions_overflow(&self) -> bool {
        self.actions
            .first_slot_block
            .iter()
            .any(SaturatingCounter::overflow)
            || self
                .actions
                .domain_block
                .iter()
                .any(SaturatingCounter::overflow)
            || self.actions.flare.iter().any(SaturatingCounter::overflow)
            || self.actions.block_all.overflow()
    }

    pub(crate) fn refusals_overflow(&self) -> bool {
        self.refusals
            .blocked_domain
            .iter()
            .any(SaturatingCounter::overflow)
    }

    pub(crate) fn report_drops_overflow(&self) -> bool {
        self.report_drops.overflow()
    }

    #[cfg(test)]
    pub(crate) fn saturate_facts_any_illegal_for_test(&mut self, cause: AnyIllegalCause) {
        self.facts.any_illegal[cause.kind_index()].saturate_for_test();
        self.dirty = true;
    }

    #[cfg(test)]
    pub(crate) fn saturate_all_for_test(&mut self) {
        for c in &mut self.facts.any_illegal {
            c.saturate_for_test();
        }
        for c in &mut self.facts.early_data {
            c.saturate_for_test();
        }
        for c in &mut self.facts.unknown {
            c.saturate_for_test();
        }
        for c in &mut self.actions.first_slot_block {
            c.saturate_for_test();
        }
        for c in &mut self.actions.domain_block {
            c.saturate_for_test();
        }
        for c in &mut self.actions.flare {
            c.saturate_for_test();
        }
        self.actions.block_all.saturate_for_test();
        for c in &mut self.refusals.blocked_domain {
            c.saturate_for_test();
        }
        self.report_drops.saturate_for_test();
        for _ in 0..CAPTURE_DETAIL_LEN {
            let index = (self.capture_head + self.capture_len) % CAPTURE_DETAIL_LEN;
            self.captures[index] = Some(ConsumedCapture {
                slot: crate::inventory::TUNNEL_SLOTS - 1,
                generation: u64::MAX,
                detail: CapturedDetail {
                    fact: CapturedFact::AnyIllegal(AnyIllegalCause::TlsProfile(
                        crate::client_hello::HelloRejectReason::Profile,
                    )),
                    effect: Effect::Block {
                        scope: crate::enforcement::action::Scope::Domain,
                    },
                },
            });
            self.capture_len += 1;
        }
        self.capture_drops.saturate_for_test();
        self.dirty = true;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::enforcement::action::{ActionKind, DomainAction, FirstSlot, Scope};
    use crate::enforcement::policy::{Effect, Violation};
    use crate::enforcement::state::Enforcement;

    fn table(
        any_illegal: AnyIllegalScope,
        actions: &[(ActionKind, Scope)],
    ) -> crate::enforcement::action::ControlTable {
        use crate::enforcement::action::ControlTable;
        let entries: Vec<DomainAction> = actions
            .iter()
            .map(|&(kind, scope)| DomainAction::new(kind, scope))
            .collect();
        ControlTable::new(any_illegal, &entries).expect("in-bound test table")
    }

    #[test]
    fn committed_emission_clears_dirty_and_a_dropped_summary_re_dirtes() {
        let mut m = Monitor::new();
        assert!(!m.report_due(5), "clean aggregate is never due");
        m.note_fact_unknown(UnknownReason::Unattributed);
        assert!(m.report_due(5), "dirty aggregate is due at the boundary");
        m.mark_reported(5, true);
        assert!(!m.report_due(5), "same second suppresses the re-emission");
        assert!(
            !m.report_due(6),
            "H1: no event between seconds, a committed aggregate is not due again"
        );
        assert_eq!(m.report_drops(), 0);
        m.note_fact_unknown(UnknownReason::Unattributed);
        assert!(m.report_due(6), "a new event re-dirties the aggregate");
        m.mark_reported(6, false);
        assert_eq!(
            m.report_drops(),
            1,
            "an uncommitted summary is honest detail loss"
        );
        assert!(
            m.report_due(7),
            "L3: a dropped summary re-dirties so the current aggregate re-emits next second"
        );
        m.mark_reported(7, true);
        assert_eq!(
            m.report_drops(),
            1,
            "the re-emission commits, loss not re-counted"
        );
        assert!(
            !m.report_due(8),
            "after a successful re-emission the aggregate is clean again"
        );
    }

    #[test]
    fn dropped_report_is_counted_as_detail_loss_and_stays_dirty() {
        let mut m = Monitor::new();
        m.note_fact_unknown(UnknownReason::Unattributed);
        m.mark_reported(5, false);
        assert_eq!(
            m.report_drops(),
            1,
            "an uncommitted summary is honest detail loss"
        );
        assert!(
            m.last_report_secs().is_some(),
            "the cadence still advances so the next second re-emits the aggregate"
        );
    }

    #[test]
    fn split_facts_actions_and_refusals_through_enforcement() {
        let mut latch = FirstSlot::new();
        let mut en = Enforcement::new(table(
            AnyIllegalScope::Connection,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        ));
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let v = en.decide(&mut latch, Violation::AnyIllegal { cause });
        assert_eq!(
            v,
            Effect::Block {
                scope: Scope::Connection
            }
        );
        en.decide(&mut latch, Violation::AnyIllegal { cause });
        assert_eq!(
            en.counters().facts_any_illegal_total(),
            2,
            "every detection folds a fact independent of the spent first-slot latch (ogot B3b)"
        );
        assert_eq!(
            en.counters()
                .actions_first_slot_block(AnyIllegalScope::Connection),
            1,
            "the Block action applies exactly once per connection"
        );
        assert_eq!(en.counters().refusals_total(), 0, "no refusal here");
    }

    #[test]
    fn domain_block_action_and_later_refusal_are_distinct_channels() {
        let actions = [(ActionKind::Block, Scope::Domain)];
        let mut en = Enforcement::new(table(AnyIllegalScope::Connection, &actions));
        let ordinal = DomainOrdinal::from_index(0).expect("bound-level ordinal");
        let v = en.decide(
            &mut FirstSlot::new(),
            Violation::EarlyUpstreamData { ordinal },
        );
        assert_eq!(
            v,
            Effect::Block {
                scope: Scope::Domain
            }
        );
        assert_eq!(en.counters().actions_domain_block(ordinal), 1);
        assert_eq!(en.counters().refusals_blocked_domain(ordinal), 0);
        en.note_domain_block(ordinal);
        assert_eq!(en.counters().actions_domain_block(ordinal), 1);
        assert_eq!(en.counters().refusals_blocked_domain(ordinal), 1);
        assert_eq!(
            en.counters().refusals_total(),
            1,
            "the action and the later refusal fold their own truthful totals"
        );
    }

    #[test]
    fn two_saturated_counters_total_exactly_2x_u32_max_without_panic_or_wrap() {
        use crate::connect::ConnectHeadReason;
        let mut m = Monitor::new();
        m.saturate_facts_any_illegal_for_test(AnyIllegalCause::HostNotAllowlisted);
        m.saturate_facts_any_illegal_for_test(AnyIllegalCause::ConnectParse(
            ConnectHeadReason::TooLong,
        ));
        m.note_fact_any_illegal(AnyIllegalCause::HostNotAllowlisted);
        m.note_fact_any_illegal(AnyIllegalCause::ConnectParse(ConnectHeadReason::TooLong));
        assert_eq!(
            m.facts_any_illegal_total(),
            2 * u32::MAX as u64,
            "M1: per-element u64 widening sums two saturated u32 counters exactly"
        );
    }

    #[test]
    fn consumed_capture_is_correlated_with_slot_generation_fact_and_effect() {
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        let cap = |slot, generation| SlotCapture {
            slot,
            generation,
            detail: Some(CapturedDetail {
                fact: CapturedFact::AnyIllegal(cause),
                effect,
            }),
        };
        let mut m = Monitor::new();
        m.note_consumed_capture(cap(0, 42));
        m.note_consumed_capture(cap(1, 7));
        assert_eq!(
            m.capture_detail_len(),
            2,
            "H3: consumed captures fold into detail"
        );
        let first = m.capture_detail(0).expect("first capture");
        assert_eq!((first.slot, first.generation), (0, 42));
        assert_eq!(
            first.detail.fact,
            CapturedFact::AnyIllegal(cause),
            "the fact travels with the capture"
        );
        let second = m.capture_detail(1).expect("second capture");
        assert_eq!((second.slot, second.generation), (1, 7));
        assert_eq!(
            m.capture_drops(),
            0,
            "no detail loss until the ring overflows"
        );
        assert!(m.report_due(1), "a consumed capture dirties the aggregate");
    }

    #[test]
    fn two_slots_at_equal_generation_are_distinct_identities_and_reuse_bumps_generation() {
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        let cap = |slot, generation| SlotCapture {
            slot,
            generation,
            detail: Some(CapturedDetail {
                fact: CapturedFact::AnyIllegal(cause),
                effect,
            }),
        };
        let mut m = Monitor::new();
        m.note_consumed_capture(cap(0, 1));
        m.note_consumed_capture(cap(1, 1));
        let first = m.capture_detail(0).expect("slot 0 capture");
        let second = m.capture_detail(1).expect("slot 1 capture");
        assert_eq!((first.slot, first.generation), (0, 1));
        assert_eq!((second.slot, second.generation), (1, 1));
        assert_ne!(
            first, second,
            "H1': equal per-slot generations on different slots are distinct connection identities"
        );
        m.note_consumed_capture(cap(0, 2));
        let reused = m.capture_detail(2).expect("reused slot capture");
        assert_eq!((reused.slot, reused.generation), (0, 2));
        assert_ne!(
            reused, first,
            "H1': a reused slot at a new generation is a fresh identity"
        );
    }

    #[test]
    fn accepted_summary_enqueue_consumes_its_detail_window_and_a_refused_summary_retains() {
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        let cap = |slot| SlotCapture {
            slot,
            generation: 1,
            detail: Some(CapturedDetail {
                fact: CapturedFact::AnyIllegal(cause),
                effect,
            }),
        };
        let mut m = Monitor::new();
        m.note_consumed_capture(cap(0));
        assert_eq!(
            m.capture_detail_len(),
            1,
            "a consumed capture fills the window"
        );
        m.mark_reported(5, true);
        assert_eq!(
            m.capture_detail_len(),
            0,
            "M2': an accepted enqueue consumes its detail window"
        );
        assert!(
            !m.report_due(5),
            "the accepted emission leaves a clean aggregate"
        );
        m.note_consumed_capture(cap(0));
        m.mark_reported(6, false);
        assert_eq!(
            m.capture_detail_len(),
            1,
            "M2': a refused summary retains its bounded detail window"
        );
        assert_eq!(
            m.report_drops(),
            1,
            "M2': the refused summary is truthful counted loss"
        );
        assert!(m.report_due(7), "M2': refused detail re-emits next cadence");
        m.mark_reported(7, true);
        assert_eq!(
            m.capture_detail_len(),
            0,
            "M2': the re-emitted accepted summary consumes the window"
        );
        assert_eq!(
            m.report_drops(),
            1,
            "M2': the earlier refusal is not re-counted"
        );
    }

    #[test]
    fn capture_ring_overflow_keeps_latest_and_counts_the_drops() {
        let cause = AnyIllegalCause::HostNotAllowlisted;
        let effect = Effect::Block {
            scope: Scope::Connection,
        };
        let cap = |slot, generation| SlotCapture {
            slot,
            generation,
            detail: Some(CapturedDetail {
                fact: CapturedFact::AnyIllegal(cause),
                effect,
            }),
        };
        let mut m = Monitor::new();
        let overflow = 5u64;
        for generation in 0..(CAPTURE_DETAIL_LEN as u64 + overflow) {
            m.note_consumed_capture(cap(0, generation));
        }
        assert_eq!(
            m.capture_detail_len(),
            CAPTURE_DETAIL_LEN,
            "the ring holds at most the fixed detail window"
        );
        assert_eq!(
            m.capture_drops(),
            overflow as u32,
            "every capture past the window is honest counted detail loss"
        );
        assert_eq!(
            m.capture_detail(0).expect("oldest held").generation,
            overflow,
            "the oldest held capture is the first one that fits the window"
        );
        assert_eq!(
            m.capture_detail(CAPTURE_DETAIL_LEN - 1)
                .expect("newest held")
                .generation,
            CAPTURE_DETAIL_LEN as u64 + overflow - 1,
            "the newest capture is always kept"
        );
    }

    #[test]
    fn a_capture_without_a_relation_is_never_folded_into_the_ring() {
        let mut m = Monitor::new();
        let bare = SlotCapture::fresh(3, 9);
        m.note_consumed_capture(bare);
        assert_eq!(
            m.capture_detail_len(),
            0,
            "L1: a slot that detected nothing contributes no ring entry"
        );
        assert_eq!(m.capture_drops(), 0, "never a fake loss for an absent fact");
        assert!(
            !m.report_due(1),
            "an empty capture leaves the aggregate clean"
        );
    }

    #[test]
    fn suppressed_later_relation_is_counted_correlated_detail_loss() {
        let mut m = Monitor::new();
        m.note_suppressed_detail();
        assert_eq!(
            m.capture_drops(),
            1,
            "L2: a later relation suppressed behind the first is counted correlated-detail loss"
        );
        assert!(
            m.report_due(1),
            "the suppression dirties the aggregate for the next summary"
        );
        m.mark_reported(1, true);
        assert_eq!(
            m.capture_drops(),
            1,
            "the committed summary does not re-count the earlier suppression"
        );
        assert!(
            !m.report_due(2),
            "the accepted summary leaves a clean aggregate"
        );
    }

    #[test]
    fn monitor_overflow_flags_latch_and_totals_do_not_wrap() {
        let mut m = Monitor::new();
        m.saturate_facts_any_illegal_for_test(AnyIllegalCause::HostNotAllowlisted);
        m.note_fact_any_illegal(AnyIllegalCause::HostNotAllowlisted);
        assert!(
            m.facts_any_illegal_overflow(),
            "the overflow flag latches once a counter saturates"
        );
        assert_eq!(
            m.facts_any_illegal(AnyIllegalCause::HostNotAllowlisted),
            u32::MAX,
            "a saturated counter never wraps"
        );
        assert!(
            m.facts_total() >= u32::MAX as u64,
            "the total stays truthful under saturation, never wraps: {}",
            m.facts_total()
        );
        assert!(
            m.report_due(1),
            "a saturated-and-dirty aggregate is still due for reporting"
        );
    }
}
