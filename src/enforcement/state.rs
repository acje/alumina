use super::action::{AnyIllegalScope, ControlTable, DomainOrdinal, FirstSlot, Scope};
use super::monitor::{Monitor, SlotCapture};
use super::policy::{Effect, UnknownReason, Violation, decide as pure_decide};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaturatingCounter {
    value: u32,
    overflow: bool,
}

impl SaturatingCounter {
    pub const fn new() -> SaturatingCounter {
        SaturatingCounter {
            value: 0,
            overflow: false,
        }
    }

    pub fn bump(&mut self) {
        if self.value == u32::MAX {
            self.overflow = true;
        } else {
            self.value += 1;
        }
    }

    pub const fn value(&self) -> u32 {
        self.value
    }

    pub const fn overflow(&self) -> bool {
        self.overflow
    }

    #[cfg(test)]
    pub fn saturate_for_test(&mut self) {
        self.value = u32::MAX;
        self.overflow = true;
    }
}

impl Default for SaturatingCounter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Enforcement {
    control: ControlTable,
    block_all: bool,
    blocked: u32,
    monitor: Monitor,
}

impl Enforcement {
    pub fn new(control: ControlTable) -> Enforcement {
        Enforcement {
            control,
            block_all: false,
            blocked: 0,
            monitor: Monitor::new(),
        }
    }

    pub fn control(&self) -> ControlTable {
        self.control
    }

    pub fn block_all(&self) -> bool {
        self.block_all
    }

    pub fn is_blocked(&self, ordinal: DomainOrdinal) -> bool {
        (self.blocked >> ordinal.get()) & 1 == 1
    }

    pub fn decide(&mut self, latch: &mut FirstSlot, violation: Violation) -> Effect {
        let effect = pure_decide(&self.control, latch, violation);
        match violation {
            Violation::AnyIllegal { cause } => {
                self.monitor.note_fact_any_illegal(cause);
                match effect {
                    Effect::Block {
                        scope: Scope::Connection,
                    } => {
                        self.monitor
                            .note_action_first_slot_block(AnyIllegalScope::Connection);
                    }
                    Effect::Block { scope: Scope::All } => {
                        let was_latched = self.block_all;
                        self.block_all = true;
                        self.monitor
                            .note_action_first_slot_block(AnyIllegalScope::All);
                        if !was_latched {
                            self.monitor.note_block_all();
                        }
                    }
                    _ => {}
                }
            }
            Violation::EarlyUpstreamData { ordinal } => {
                self.monitor.note_fact_early_data(ordinal);
                match effect {
                    Effect::FlareOnly { .. } => {
                        self.monitor.note_action_flare(ordinal);
                    }
                    Effect::Block { scope } => {
                        self.monitor.note_action_domain_block(ordinal);
                        match scope {
                            Scope::Domain => self.blocked |= 1 << ordinal.get(),
                            Scope::All => {
                                let was_latched = self.block_all;
                                self.block_all = true;
                                if !was_latched {
                                    self.monitor.note_block_all();
                                }
                            }
                            Scope::Connection => {}
                        }
                    }
                    Effect::Unknown { .. } => {}
                    Effect::BaselineOnly => {}
                }
            }
            Violation::EvidenceInsufficient => {
                self.monitor
                    .note_fact_unknown(UnknownReason::NotYetValidated);
            }
            Violation::Unattributed => {
                self.monitor.note_fact_unknown(UnknownReason::Unattributed);
            }
            Violation::MissingParseResult => {
                self.monitor
                    .note_fact_unknown(UnknownReason::MissingParseResult);
            }
        }
        effect
    }

    pub fn note_domain_block(&mut self, ordinal: DomainOrdinal) {
        self.monitor.note_refusal_blocked_domain(ordinal);
    }

    pub(crate) fn note_consumed_capture(&mut self, capture: SlotCapture) {
        self.monitor.note_consumed_capture(capture);
    }

    pub(crate) fn note_suppressed_detail(&mut self) {
        self.monitor.note_suppressed_detail();
    }

    pub(crate) fn monitor(&self) -> &Monitor {
        &self.monitor
    }

    pub(crate) fn monitor_due(&self, secs: u64) -> bool {
        self.monitor.report_due(secs)
    }

    pub(crate) fn mark_monitor_reported(&mut self, secs: u64, committed: bool) {
        self.monitor.mark_reported(secs, committed);
    }

    pub(crate) fn mark_forced_monitor_reported(&mut self, committed: bool) {
        self.monitor.mark_forced_reported(committed);
    }

    #[cfg(test)]
    pub fn counters(&self) -> &Monitor {
        &self.monitor
    }

    #[cfg(test)]
    pub(crate) fn test_blocked(&self, ordinal: DomainOrdinal) -> bool {
        self.is_blocked(ordinal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_hello::HelloRejectReason;
    use crate::connect::ConnectHeadReason;
    use crate::enforcement::action::{ActionKind, AnyIllegalScope, DomainAction};
    use crate::enforcement::policy::{AnyIllegalCause, UnknownReason};

    fn table(any_illegal: AnyIllegalScope, actions: &[(ActionKind, Scope)]) -> ControlTable {
        let entries: Vec<DomainAction> = actions
            .iter()
            .map(|&(kind, scope)| DomainAction::new(kind, scope))
            .collect();
        ControlTable::new(any_illegal, &entries).expect("in-bound test table")
    }

    #[test]
    fn saturating_counter_reports_wrapped_value_and_overflow() {
        let mut c = SaturatingCounter::new();
        for _ in 0..u32::MAX as u64 {
            c.bump();
        }
        assert_eq!(c.value(), u32::MAX);
        assert!(!c.overflow());
        c.bump();
        assert_eq!(c.value(), u32::MAX);
        assert!(c.overflow());
    }

    #[test]
    fn any_illegal_folds_every_fact_by_exact_cause_and_latches_all_once() {
        let t = table(
            AnyIllegalScope::All,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(t);
        let mut latch = FirstSlot::new();
        let effect = en.decide(
            &mut latch,
            Violation::AnyIllegal {
                cause: crate::enforcement::policy::AnyIllegalCause::HostNotAllowlisted,
            },
        );
        assert_eq!(effect, Effect::Block { scope: Scope::All });
        assert!(en.block_all());
        assert_eq!(
            en.counters()
                .facts_any_illegal(AnyIllegalCause::HostNotAllowlisted),
            1
        );
        assert_eq!(en.counters().facts_any_illegal_total(), 1);
        let again = en.decide(
            &mut latch,
            Violation::AnyIllegal {
                cause: AnyIllegalCause::TlsProfile(HelloRejectReason::ServerNameMismatch),
            },
        );
        assert_eq!(again, Effect::BaselineOnly);
        assert!(
            en.block_all(),
            "a latched connection may not fire the action twice"
        );
        assert_eq!(
            en.counters().facts_any_illegal(AnyIllegalCause::TlsProfile(
                HelloRejectReason::ServerNameMismatch
            )),
            1,
            "a later AnyIllegal fact still folds by its exact cause"
        );
        assert_eq!(en.counters().facts_any_illegal_total(), 2);
    }

    #[test]
    fn wrong_port_and_transfer_encoding_fold_into_distinct_cause_counters() {
        let t = table(
            AnyIllegalScope::All,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(t);
        let mut latch = FirstSlot::new();
        en.decide(
            &mut latch,
            Violation::AnyIllegal {
                cause: AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort),
            },
        );
        en.decide(
            &mut latch,
            Violation::AnyIllegal {
                cause: AnyIllegalCause::ConnectParse(ConnectHeadReason::TransferEncoding),
            },
        );
        assert_eq!(
            en.counters()
                .facts_any_illegal(AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort)),
            1,
            "WrongPort folds into its own counter"
        );
        assert_eq!(
            en.counters()
                .facts_any_illegal(AnyIllegalCause::ConnectParse(
                    ConnectHeadReason::TransferEncoding
                )),
            1,
            "TransferEncoding folds into its own distinct counter"
        );
        assert_eq!(en.counters().facts_any_illegal_total(), 2);
    }

    #[test]
    fn early_data_block_domain_sets_bitset_and_counts() {
        let t = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::Block, Scope::Domain)],
        );
        let mut en = Enforcement::new(t);
        let mut latch = FirstSlot::new();
        let ordinal = t.ordinal(0).expect("ordinal");
        let effect = en.decide(&mut latch, Violation::EarlyUpstreamData { ordinal });
        assert_eq!(
            effect,
            Effect::Block {
                scope: Scope::Domain
            }
        );
        assert!(en.test_blocked(ordinal));
        assert_eq!(en.counters().actions_domain_block(ordinal), 1);
        assert!(!en.block_all());
    }

    #[test]
    fn early_data_flare_counts_per_ordinal() {
        let t = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(t);
        let mut latch = FirstSlot::new();
        let ordinal = t.ordinal(0).expect("ordinal");
        assert_eq!(
            en.decide(&mut latch, Violation::EarlyUpstreamData { ordinal }),
            Effect::FlareOnly {
                scope: Scope::Connection
            }
        );
        assert_eq!(en.counters().actions_flare(ordinal), 1);
        assert_eq!(en.counters().actions_domain_block(ordinal), 0);
    }

    #[test]
    fn all_transition_is_a_derived_latch_count_not_a_duplicate_action_total() {
        let t = table(
            AnyIllegalScope::All,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(t);
        let mut latch = FirstSlot::new();
        let effect = en.decide(
            &mut latch,
            Violation::AnyIllegal {
                cause: AnyIllegalCause::HostNotAllowlisted,
            },
        );
        assert_eq!(effect, Effect::Block { scope: Scope::All });
        assert!(en.block_all());
        assert_eq!(
            en.counters().actions_block_all(),
            1,
            "the All latch records one transition"
        );
        assert_eq!(
            en.counters().actions_total(),
            1,
            "M2: the one applied first-slot Block is the only action counted; ba is a derived view"
        );
    }

    #[test]
    fn block_all_latch_counts_the_transition_once_not_every_all_application() {
        let t = table(AnyIllegalScope::All, &[(ActionKind::Block, Scope::All); 2]);
        let mut en = Enforcement::new(t);
        let mut latch = FirstSlot::new();
        en.decide(
            &mut latch,
            Violation::AnyIllegal {
                cause: AnyIllegalCause::HostNotAllowlisted,
            },
        );
        let ordinal = t.ordinal(0).expect("big table ordinal");
        en.decide(&mut latch, Violation::EarlyUpstreamData { ordinal });
        assert!(en.block_all(), "both applications select Block All");
        assert_eq!(
            en.counters().actions_block_all(),
            1,
            "L1: the latch transition counts once even across a later All application"
        );
    }

    #[test]
    fn early_data_unknown_outcome_is_one_detection_fact_not_two() {
        let small = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(small);
        let mut latch = FirstSlot::new();
        let big = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::Block, Scope::All); 2],
        );
        let unbound = big.ordinal(1).expect("big table ordinal");
        let effect = en.decide(
            &mut latch,
            Violation::EarlyUpstreamData { ordinal: unbound },
        );
        assert!(matches!(effect, Effect::Unknown { .. }));
        assert_eq!(
            en.counters().facts_total(),
            1,
            "M2: an early-data Unknown outcome is one detection event, not two"
        );
        assert_eq!(
            en.counters().facts_early_data(unbound),
            1,
            "the detection is typed as early upstream data on its ordinal"
        );
        assert_eq!(
            en.counters().facts_unknown(UnknownReason::UnboundOrdinal),
            0,
            "M2: the Unknown is the outcome, carried by the correlation, not a second fact"
        );
    }

    #[test]
    fn unbound_and_insufficient_evidence_fold_unknown_by_reason_not_baseline() {
        let small = table(
            AnyIllegalScope::All,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut en = Enforcement::new(small);
        let mut latch = FirstSlot::new();
        let big = table(AnyIllegalScope::All, &[(ActionKind::Block, Scope::All); 2]);
        let unbound = big.ordinal(1).expect("big table ordinal");
        let effect = en.decide(
            &mut latch,
            Violation::EarlyUpstreamData { ordinal: unbound },
        );
        assert!(matches!(
            effect,
            Effect::Unknown {
                reason: UnknownReason::UnboundOrdinal
            }
        ));
        assert_eq!(
            en.counters().facts_early_data(unbound),
            1,
            "the early-data detection folds its own fact exactly once"
        );
        assert_eq!(
            en.counters().facts_unknown(UnknownReason::UnboundOrdinal),
            0,
            "M2: an early-data Unknown outcome is one detection fact, not a second unknown"
        );
        assert_eq!(en.counters().unknown_total(), 0);
        assert_eq!(
            en.decide(&mut latch, Violation::EvidenceInsufficient),
            Effect::Unknown {
                reason: UnknownReason::NotYetValidated
            }
        );
        assert_eq!(
            en.counters().facts_unknown(UnknownReason::NotYetValidated),
            1
        );
        assert_eq!(en.counters().unknown_total(), 1);
        assert!(!en.block_all(), "Unknown must never set the All latch");
    }

    #[test]
    fn missing_result_and_unattributed_fold_distinct_unknown_never_block() {
        let t = table(AnyIllegalScope::All, &[(ActionKind::Block, Scope::All)]);
        let mut en = Enforcement::new(t);
        let mut latch = FirstSlot::new();
        let effect = en.decide(&mut latch, Violation::MissingParseResult);
        assert_eq!(
            effect,
            Effect::Unknown {
                reason: UnknownReason::MissingParseResult
            }
        );
        assert!(
            !matches!(effect, Effect::Block { .. }),
            "a missing internal parse result must never latch Block-All"
        );
        let effect = en.decide(&mut latch, Violation::Unattributed);
        assert_eq!(
            effect,
            Effect::Unknown {
                reason: UnknownReason::Unattributed
            }
        );
        assert!(!en.block_all());
        assert_eq!(
            en.counters()
                .facts_unknown(UnknownReason::MissingParseResult),
            1
        );
        assert_eq!(en.counters().facts_unknown(UnknownReason::Unattributed), 1);
        assert!(
            !en.test_blocked(t.ordinal(0).expect("ordinal")),
            "Unknown must never mark a configured domain blocked"
        );
    }
}
