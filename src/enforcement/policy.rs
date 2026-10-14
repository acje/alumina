//! Pure tripwire policy decision: maps a typed violation fact, the
//! per-connection first-AnyIllegal latch, and the configured control table to
//! a supplementary enforcement effect. The baseline mandatory denial is
//! always applied by the detection site independently; this decision only
//! produces the action projection. Operational failures and absent internal
//! evidence are not violations and cannot be expressed as such
//! (docs/alumina-proxy.md tripwire amendment).

use super::action::{ActionKind, AnyIllegalScope, ControlTable, DomainOrdinal, FirstSlot, Scope};

/// A typed violation fact captured at detection before erasure. `AnyIllegal`
/// is never domain-attributed; `EarlyUpstreamData` carries the validated
/// configured-domain ordinal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    AnyIllegal,
    EarlyUpstreamData { ordinal: DomainOrdinal },
}

/// The supplementary effect on top of the always-applied baseline denial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    BaselineOnly,
    FlareOnly { scope: Scope },
    Block { scope: Scope },
}

/// The pure decision. An `AnyIllegal` fact fires the first-slot latch at most
/// once per connection and selects the configured Connection/All Block; later
/// AnyIllegal facts on the same connection yield `BaselineOnly`. An
/// `EarlyUpstreamData` fact selects the configured per-domain action; an
/// ordinal this table did not configure is unbound and yields `BaselineOnly`
/// (never a fabricated configured action).
pub fn decide(table: &ControlTable, latch: &mut FirstSlot, violation: Violation) -> Effect {
    match violation {
        Violation::AnyIllegal => match (latch.take_if_armed(), table.any_illegal()) {
            (false, _) => Effect::BaselineOnly,
            (true, AnyIllegalScope::Connection) => Effect::Block {
                scope: Scope::Connection,
            },
            (true, AnyIllegalScope::All) => Effect::Block { scope: Scope::All },
        },
        Violation::EarlyUpstreamData { ordinal } => match table.at(ordinal) {
            None => Effect::BaselineOnly,
            Some(action) => match action.kind() {
                ActionKind::FlareOnly => Effect::FlareOnly {
                    scope: action.scope(),
                },
                ActionKind::Block => Effect::Block {
                    scope: action.scope(),
                },
            },
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

    #[test]
    fn first_any_illegal_scoped_all_yields_block_all_once() {
        let t = table(
            AnyIllegalScope::All,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut latch = FirstSlot::new();
        assert_eq!(
            decide(&t, &mut latch, Violation::AnyIllegal),
            Effect::Block { scope: Scope::All }
        );
        assert_eq!(
            decide(&t, &mut latch, Violation::AnyIllegal),
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
            decide(&t, &mut latch, Violation::AnyIllegal),
            Effect::Block {
                scope: Scope::Connection
            }
        );
    }

    #[test]
    fn latched_connection_cannot_fire_twice() {
        let t = table(
            AnyIllegalScope::All,
            &[(ActionKind::FlareOnly, Scope::Connection)],
        );
        let mut latch = FirstSlot::new();
        assert_eq!(
            decide(&t, &mut latch, Violation::AnyIllegal),
            Effect::Block { scope: Scope::All }
        );
        assert_eq!(
            decide(&t, &mut latch, Violation::AnyIllegal),
            Effect::BaselineOnly
        );
        assert_eq!(
            decide(&t, &mut latch, Violation::AnyIllegal),
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
    fn early_data_with_cross_table_ordinal_is_baseline_only() {
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
            Effect::BaselineOnly,
            "no fabricated configured action for an ordinal this table did not configure"
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
