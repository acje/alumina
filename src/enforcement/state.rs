use super::action::{ControlTable, DomainOrdinal, FirstSlot, Scope};
use super::policy::{AnyIllegalCause, Effect, UnknownReason, Violation, decide as pure_decide};
use crate::config::ALLOWLIST_MAX;

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

    fn bump(&mut self) {
        if self.value == u32::MAX {
            self.overflow = true;
        } else {
            self.value += 1;
        }
    }

    #[cfg(test)]
    pub const fn value(&self) -> u32 {
        self.value
    }

    #[cfg(test)]
    pub const fn overflow(&self) -> bool {
        self.overflow
    }
}

impl Default for SaturatingCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureCounters {
    any_illegal: [SaturatingCounter; AnyIllegalCause::KIND_COUNT],
    domain_blocks: [SaturatingCounter; ALLOWLIST_MAX],
    domain_flares: [SaturatingCounter; ALLOWLIST_MAX],
    unknown: [SaturatingCounter; UnknownReason::COUNT],
}

pub struct Enforcement {
    control: ControlTable,
    block_all: bool,
    blocked: u32,
    counters: CaptureCounters,
}

impl Enforcement {
    pub fn new(control: ControlTable) -> Enforcement {
        Enforcement {
            control,
            block_all: false,
            blocked: 0,
            counters: CaptureCounters::default(),
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
                self.counters.any_illegal[cause.kind_index()].bump();
                if let Effect::Block { scope: Scope::All } = effect {
                    self.block_all = true;
                }
            }
            Violation::EarlyUpstreamData { ordinal } => match effect {
                Effect::FlareOnly { .. } => self.counters.domain_flares[ordinal.get()].bump(),
                Effect::Block { scope } => {
                    self.counters.domain_blocks[ordinal.get()].bump();
                    match scope {
                        Scope::Domain => self.blocked |= 1 << ordinal.get(),
                        Scope::All => self.block_all = true,
                        Scope::Connection => {}
                    }
                }
                Effect::Unknown { reason } => self.counters.unknown[reason.index()].bump(),
                Effect::BaselineOnly => {}
            },
            Violation::EvidenceInsufficient => {
                self.counters.unknown[UnknownReason::NotYetValidated.index()].bump();
            }
            Violation::Unattributed => {
                self.counters.unknown[UnknownReason::Unattributed.index()].bump();
            }
            Violation::MissingParseResult => {
                self.counters.unknown[UnknownReason::MissingParseResult.index()].bump();
            }
        }
        effect
    }

    pub fn note_domain_block(&mut self, ordinal: DomainOrdinal) {
        self.counters.domain_blocks[ordinal.get()].bump();
    }

    #[cfg(test)]
    pub fn counters(&self) -> &CaptureCounters {
        &self.counters
    }

    #[cfg(test)]
    pub(crate) fn test_blocked(&self, ordinal: DomainOrdinal) -> bool {
        self.is_blocked(ordinal)
    }
}

impl CaptureCounters {
    #[cfg(test)]
    pub(crate) fn any_illegal(&self, cause: AnyIllegalCause) -> u32 {
        self.any_illegal[cause.kind_index()].value()
    }

    #[cfg(test)]
    pub(crate) fn any_illegal_total(&self) -> u32 {
        self.any_illegal.iter().map(SaturatingCounter::value).sum()
    }

    #[cfg(test)]
    pub(crate) fn unknown(&self, reason: UnknownReason) -> u32 {
        self.unknown[reason.index()].value()
    }

    #[cfg(test)]
    pub(crate) fn unknown_total(&self) -> u32 {
        self.unknown.iter().map(SaturatingCounter::value).sum()
    }

    #[cfg(test)]
    pub(crate) fn domain_blocks(&self, ordinal: DomainOrdinal) -> u32 {
        self.domain_blocks[ordinal.get()].value()
    }

    #[cfg(test)]
    pub(crate) fn domain_flares(&self, ordinal: DomainOrdinal) -> u32 {
        self.domain_flares[ordinal.get()].value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_hello::HelloRejectReason;
    use crate::connect::ConnectHeadReason;
    use crate::enforcement::action::{ActionKind, AnyIllegalScope, DomainAction};
    use crate::enforcement::policy::UnknownReason;

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
                .any_illegal(AnyIllegalCause::HostNotAllowlisted),
            1
        );
        assert_eq!(en.counters().any_illegal_total(), 1);
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
            en.counters().any_illegal(AnyIllegalCause::TlsProfile(
                HelloRejectReason::ServerNameMismatch
            )),
            1,
            "a later AnyIllegal fact still folds by its exact cause"
        );
        assert_eq!(en.counters().any_illegal_total(), 2);
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
                .any_illegal(AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort)),
            1,
            "WrongPort folds into its own counter"
        );
        assert_eq!(
            en.counters().any_illegal(AnyIllegalCause::ConnectParse(
                ConnectHeadReason::TransferEncoding
            )),
            1,
            "TransferEncoding folds into its own distinct counter"
        );
        assert_eq!(en.counters().any_illegal_total(), 2);
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
        assert_eq!(en.counters().domain_blocks(ordinal), 1);
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
        assert_eq!(en.counters().domain_flares(ordinal), 1);
        assert_eq!(en.counters().domain_blocks(ordinal), 0);
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
        assert_eq!(en.counters().unknown(UnknownReason::UnboundOrdinal), 1);
        assert_eq!(en.counters().unknown_total(), 1);
        assert_eq!(
            en.decide(&mut latch, Violation::EvidenceInsufficient),
            Effect::Unknown {
                reason: UnknownReason::NotYetValidated
            }
        );
        assert_eq!(en.counters().unknown(UnknownReason::NotYetValidated), 1);
        assert_eq!(en.counters().unknown_total(), 2);
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
        assert_eq!(en.counters().unknown(UnknownReason::MissingParseResult), 1);
        assert_eq!(en.counters().unknown(UnknownReason::Unattributed), 1);
        assert!(
            !en.test_blocked(t.ordinal(0).expect("ordinal")),
            "Unknown must never mark a configured domain blocked"
        );
    }
}
