use super::action::{ActionKind, AnyIllegalScope, ControlTable, DomainOrdinal, FirstSlot, Scope};
use crate::client_hello::HelloRejectReason;
use crate::connect::ConnectHeadReason;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnyIllegalCause {
    ConnectParse(ConnectHeadReason),
    HostNotAllowlisted,
    TlsProfile(HelloRejectReason),
}

impl AnyIllegalCause {
    pub fn kind_index(self) -> usize {
        match self {
            AnyIllegalCause::ConnectParse(reason) => reason.index(),
            AnyIllegalCause::HostNotAllowlisted => ConnectHeadReason::COUNT,
            AnyIllegalCause::TlsProfile(reason) => ConnectHeadReason::COUNT + 1 + reason.index(),
        }
    }

    pub const KIND_COUNT: usize = ConnectHeadReason::COUNT + 1 + HelloRejectReason::COUNT;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum UnknownReason {
    UnboundOrdinal,
    NotYetValidated,
    MissingParseResult,
    Unattributed,
}

impl UnknownReason {
    pub fn index(self) -> usize {
        self as usize
    }

    pub const COUNT: usize = 4;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    AnyIllegal { cause: AnyIllegalCause },
    EarlyUpstreamData { ordinal: DomainOrdinal },
    EvidenceInsufficient,
    Unattributed,
    MissingParseResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    BaselineOnly,
    FlareOnly { scope: Scope },
    Block { scope: Scope },
    Unknown { reason: UnknownReason },
}

pub fn decide(table: &ControlTable, latch: &mut FirstSlot, violation: Violation) -> Effect {
    match violation {
        Violation::AnyIllegal { cause: _ } => match (latch.take_if_armed(), table.any_illegal()) {
            (false, _) => Effect::BaselineOnly,
            (true, AnyIllegalScope::Connection) => Effect::Block {
                scope: Scope::Connection,
            },
            (true, AnyIllegalScope::All) => Effect::Block { scope: Scope::All },
        },
        Violation::EarlyUpstreamData { ordinal } => match table.at(ordinal) {
            None => Effect::Unknown {
                reason: UnknownReason::UnboundOrdinal,
            },
            Some(action) => match action.kind() {
                ActionKind::FlareOnly => Effect::FlareOnly {
                    scope: action.scope(),
                },
                ActionKind::Block => Effect::Block {
                    scope: action.scope(),
                },
            },
        },
        Violation::EvidenceInsufficient => Effect::Unknown {
            reason: UnknownReason::NotYetValidated,
        },
        Violation::Unattributed => Effect::Unknown {
            reason: UnknownReason::Unattributed,
        },
        Violation::MissingParseResult => Effect::Unknown {
            reason: UnknownReason::MissingParseResult,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ALLOWLIST_MAX;
    use crate::enforcement::action::DomainAction;

    fn table(any_illegal: AnyIllegalScope, actions: &[(ActionKind, Scope)]) -> ControlTable {
        let entries: Vec<DomainAction> = actions
            .iter()
            .map(|&(kind, scope)| DomainAction::new(kind, scope))
            .collect();
        ControlTable::new(any_illegal, &entries).expect("in-bound test table")
    }

    fn any(cause: AnyIllegalCause) -> Violation {
        Violation::AnyIllegal { cause }
    }

    #[test]
    fn first_any_illegal_scoped_all_yields_block_all_once() {
        let t = table(
            AnyIllegalScope::All,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut latch = FirstSlot::new();
        assert_eq!(
            decide(&t, &mut latch, any(AnyIllegalCause::HostNotAllowlisted)),
            Effect::Block { scope: Scope::All }
        );
        assert_eq!(
            decide(
                &t,
                &mut latch,
                any(AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort)),
            ),
            Effect::BaselineOnly
        );
    }

    #[test]
    fn first_any_illegal_scoped_connection_yields_block_connection() {
        let t = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut latch = FirstSlot::new();
        assert_eq!(
            decide(
                &t,
                &mut latch,
                any(AnyIllegalCause::TlsProfile(
                    HelloRejectReason::ServerNameMismatch
                )),
            ),
            Effect::Block {
                scope: Scope::Connection
            }
        );
    }

    #[test]
    fn any_illegal_cause_is_carried_regardless_of_projection() {
        let t = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        for cause in [
            AnyIllegalCause::ConnectParse(ConnectHeadReason::TransferEncoding),
            AnyIllegalCause::HostNotAllowlisted,
            AnyIllegalCause::TlsProfile(HelloRejectReason::EchPresent),
        ] {
            let mut latch = FirstSlot::new();
            assert_eq!(
                decide(&t, &mut latch, any(cause)),
                Effect::Block {
                    scope: Scope::Connection
                },
                "every AnyIllegal cause selects the configured first-slot Block"
            );
        }
    }

    #[test]
    fn latched_connection_cannot_fire_twice() {
        let t = table(
            AnyIllegalScope::All,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut latch = FirstSlot::new();
        assert_eq!(
            decide(
                &t,
                &mut latch,
                any(AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort)),
            ),
            Effect::Block { scope: Scope::All }
        );
        assert_eq!(
            decide(
                &t,
                &mut latch,
                any(AnyIllegalCause::TlsProfile(
                    HelloRejectReason::ServerNameMismatch
                )),
            ),
            Effect::BaselineOnly
        );
        assert_eq!(
            decide(&t, &mut latch, any(AnyIllegalCause::HostNotAllowlisted)),
            Effect::BaselineOnly
        );
    }

    #[test]
    fn early_data_selects_configured_block_domain() {
        let t = table(AnyIllegalScope::All, &[(ActionKind::Block, Scope::Domain)]);
        let mut latch = FirstSlot::new();
        assert_eq!(
            decide(
                &t,
                &mut latch,
                Violation::EarlyUpstreamData {
                    ordinal: t.ordinal(0).expect("ordinal"),
                }
            ),
            Effect::Block {
                scope: Scope::Domain
            }
        );
        assert_eq!(
            latch,
            FirstSlot::Armed,
            "early-data must not consume the first-slot latch"
        );
    }

    #[test]
    fn early_data_selects_configured_flare_scope() {
        let t = table(
            AnyIllegalScope::Connection,
            &[
                (ActionKind::FlareOnly, Scope::Connection),
                (ActionKind::Block, Scope::All),
            ],
        );
        let mut latch = FirstSlot::new();
        assert_eq!(
            decide(
                &t,
                &mut latch,
                Violation::EarlyUpstreamData {
                    ordinal: t.ordinal(0).expect("ordinal"),
                }
            ),
            Effect::FlareOnly {
                scope: Scope::Connection
            }
        );
        assert_eq!(
            decide(
                &t,
                &mut latch,
                Violation::EarlyUpstreamData {
                    ordinal: t.ordinal(1).expect("ordinal"),
                }
            ),
            Effect::Block { scope: Scope::All }
        );
    }

    #[test]
    fn early_data_unbound_ordinal_is_unknown_not_baseline() {
        let mut many = Vec::new();
        for _ in 0..ALLOWLIST_MAX {
            many.push((ActionKind::Block, Scope::All));
        }
        let big = table(AnyIllegalScope::All, &many);
        let unbound = big.ordinal(5).expect("index 5 configured in a full table");
        let small = table(
            AnyIllegalScope::All,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut latch = FirstSlot::new();
        assert_eq!(
            decide(
                &small,
                &mut latch,
                Violation::EarlyUpstreamData { ordinal: unbound }
            ),
            Effect::Unknown {
                reason: UnknownReason::UnboundOrdinal
            },
            "an unbound ordinal is Evidence Unknown, never a legal BaselineOnly"
        );
    }

    #[test]
    fn evidence_insufficient_is_unknown_not_baseline() {
        let t = table(AnyIllegalScope::All, &[(ActionKind::Block, Scope::All)]);
        let mut latch = FirstSlot::new();
        assert_eq!(
            decide(&t, &mut latch, Violation::EvidenceInsufficient),
            Effect::Unknown {
                reason: UnknownReason::NotYetValidated
            }
        );
        assert_eq!(
            latch,
            FirstSlot::Armed,
            "insufficient evidence must not consume the first-slot latch"
        );
    }

    #[test]
    fn unattributed_is_unknown_not_any_illegal() {
        let t = table(AnyIllegalScope::All, &[(ActionKind::Block, Scope::All)]);
        let mut latch = FirstSlot::new();
        assert_eq!(
            decide(&t, &mut latch, Violation::Unattributed),
            Effect::Unknown {
                reason: UnknownReason::Unattributed
            }
        );
        assert_eq!(
            latch,
            FirstSlot::Armed,
            "an unattributed anomaly must not consume the first-slot latch"
        );
        assert_eq!(
            decide(&t, &mut latch, Violation::Unattributed),
            Effect::Unknown {
                reason: UnknownReason::Unattributed
            }
        );
    }

    #[test]
    fn missing_parse_result_is_unknown_never_an_action() {
        let t = table(AnyIllegalScope::All, &[(ActionKind::Block, Scope::All)]);
        let mut latch = FirstSlot::new();
        let effect = decide(&t, &mut latch, Violation::MissingParseResult);
        assert_eq!(
            effect,
            Effect::Unknown {
                reason: UnknownReason::MissingParseResult
            }
        );
        assert!(
            !matches!(effect, Effect::Block { .. }),
            "a missing internal parse result must never select a Block action"
        );
        assert_eq!(
            latch,
            FirstSlot::Armed,
            "a missing internal parse result must not consume the first-slot latch"
        );
    }

    #[test]
    fn finite_cause_discriminants_stay_distinct_through_latch() {
        let t = table(
            AnyIllegalScope::Connection,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut latch = FirstSlot::new();
        let first = decide(
            &t,
            &mut latch,
            any(AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort)),
        );
        assert_eq!(
            first,
            Effect::Block {
                scope: Scope::Connection
            }
        );
        let second = decide(
            &t,
            &mut latch,
            any(AnyIllegalCause::ConnectParse(
                ConnectHeadReason::TransferEncoding,
            )),
        );
        assert_eq!(
            second,
            Effect::BaselineOnly,
            "the first-slot action fires once, but the discriminant is not erased"
        );
        assert_ne!(
            AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort),
            AnyIllegalCause::ConnectParse(ConnectHeadReason::TransferEncoding),
            "WrongPort and TransferEncoding are distinct finite causes"
        );
        let mut seen = [false; AnyIllegalCause::KIND_COUNT];
        let kinds = [
            AnyIllegalCause::ConnectParse(ConnectHeadReason::TooLong),
            AnyIllegalCause::ConnectParse(ConnectHeadReason::NotHttp),
            AnyIllegalCause::ConnectParse(ConnectHeadReason::MalformedRequestLine),
            AnyIllegalCause::ConnectParse(ConnectHeadReason::BareLineFeed),
            AnyIllegalCause::ConnectParse(ConnectHeadReason::ObsFold),
            AnyIllegalCause::ConnectParse(ConnectHeadReason::InvalidHostname),
            AnyIllegalCause::ConnectParse(ConnectHeadReason::WrongPort),
            AnyIllegalCause::ConnectParse(ConnectHeadReason::TransferEncoding),
            AnyIllegalCause::ConnectParse(ConnectHeadReason::NonzeroContentLength),
            AnyIllegalCause::ConnectParse(ConnectHeadReason::DuplicateContentLength),
            AnyIllegalCause::HostNotAllowlisted,
            AnyIllegalCause::TlsProfile(HelloRejectReason::EchPresent),
            AnyIllegalCause::TlsProfile(HelloRejectReason::ServerNameMismatch),
            AnyIllegalCause::TlsProfile(HelloRejectReason::InvalidServerName),
            AnyIllegalCause::TlsProfile(HelloRejectReason::Profile),
        ];
        for kind in kinds {
            let i = kind.kind_index();
            assert!(i < seen.len(), "kind index {i} within the fixed array");
            assert!(!seen[i], "kind index {i} is assigned exactly once");
            seen[i] = true;
        }
        assert!(
            seen.iter().all(|&s| s),
            "every cause-kind slot is covered by exactly one finite discriminant"
        );
    }

    #[test]
    fn unknown_and_cause_reason_kinds_are_finite_and_ordered() {
        assert_eq!(UnknownReason::COUNT, 4);
        assert_eq!(
            UnknownReason::UnboundOrdinal.index(),
            0,
            "the fold array must map reason to index in declaration order"
        );
        assert_eq!(UnknownReason::NotYetValidated.index(), 1);
        assert_eq!(UnknownReason::MissingParseResult.index(), 2);
        assert_eq!(UnknownReason::Unattributed.index(), 3);
        assert_eq!(
            AnyIllegalCause::KIND_COUNT,
            10 + 1 + 4,
            "10 CONNECT-head + HostNotAllowlisted + 4 hello-reject discriminants"
        );
    }

    #[test]
    fn control_table_storage_fits_planned_bound() {
        let t = table(AnyIllegalScope::All, &[(ActionKind::Block, Scope::All)]);
        assert!(
            core::mem::size_of_val(&t) <= 96,
            "data table at {} bytes",
            core::mem::size_of_val(&t)
        );
        assert_eq!(core::mem::size_of::<DomainAction>(), 2);
        assert_eq!(t.len(), 1);
    }
}
