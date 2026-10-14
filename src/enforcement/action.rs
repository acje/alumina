//! Legal configuration values for the tripwire/action control surface
//! (docs/alumina-proxy.md tripwire amendment): scopes, per-domain actions,
//! the fixed per-ordinal table, and the per-connection first-AnyIllegal
//! latch. Tarpit is deferred and has no type here.

use crate::config::ALLOWLIST_MAX;

/// Block/Flare supplement scope; the legal per-domain action scopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Scope {
    Connection = 0,
    Domain = 1,
    All = 2,
}

/// The legal scope of the AnyIllegal first-slot `Block`. `Domain` is invalid
/// configuration for the AnyIllegal action and is therefore not representable
/// here (docs/alumina-proxy.md tripwire amendment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AnyIllegalScope {
    Connection = 0,
    All = 1,
}

/// Per-domain action kind. `Tarpit` is deferred and is not a legal
/// operational action; configuration selecting it is rejected at parse with
/// an explicit deferred-status diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ActionKind {
    FlareOnly = 0,
    Block = 1,
}

/// Exactly one configured per-domain action: one kind and one scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainAction {
    kind: ActionKind,
    scope: Scope,
}

impl DomainAction {
    /// Build a domain action from a kind and scope.
    pub fn new(kind: ActionKind, scope: Scope) -> DomainAction {
        DomainAction { kind, scope }
    }

    /// The action kind.
    pub fn kind(self) -> ActionKind {
        self.kind
    }

    /// The action scope: enforcement scope for `Block`, reporting scope for
    /// `FlareOnly`. An implicit Flare for an applied `Block` inherits that
    /// Block's scope.
    pub fn scope(self) -> Scope {
        self.scope
    }
}

/// A 0-based configured-allowlist ordinal whose range is bound by the table
/// that minted it (`ControlTable::ordinal`). The constructor is private: an
/// ordinal is produced only against a specific table's entry count, so a
/// value outside that table's configured range cannot be minted from it.
/// Attacker-controlled hostnames or IP strings are never keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainOrdinal(u8);

impl DomainOrdinal {
    fn mint(index: usize, count: usize) -> Option<DomainOrdinal> {
        if index < count && count <= ALLOWLIST_MAX {
            Some(DomainOrdinal(index as u8))
        } else {
            None
        }
    }

    /// The 0-based ordinal value, always below the allowlist bound.
    pub fn get(self) -> usize {
        self.0 as usize
    }
}

/// Per-connection first-AnyIllegal state: armed once, then spent forever, so
/// the special first-slot action can apply at most once per connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FirstSlot {
    #[default]
    Armed,
    Spent,
}

impl FirstSlot {
    /// A fresh per-connection latch, armed for the first AnyIllegal.
    pub fn new() -> FirstSlot {
        FirstSlot::Armed
    }

    /// Whether this is the first AnyIllegal on the connection; consumes the
    /// latch exactly once.
    pub fn take_if_armed(&mut self) -> bool {
        if *self == FirstSlot::Armed {
            *self = FirstSlot::Spent;
            true
        } else {
            false
        }
    }
}

/// Boot-fixed per-ordinal domain-action table plus the AnyIllegal special
/// scope. Storage is a fixed `[DomainAction; ALLOWLIST_MAX]` with the exact
/// configured count; construction rejects an empty or over-limit set, `at` is
/// checked against that count, and ordinals are minted only from the table, so
/// no unconfigured position carries a fabricated configured action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlTable {
    any_illegal: AnyIllegalScope,
    per_domain: [DomainAction; ALLOWLIST_MAX],
    count: usize,
}

impl ControlTable {
    /// Build the table from the configured per-domain actions (crate-internal;
    /// the config path supplies exactly the allowlist count, within bound).
    /// `None` when the set is empty or exceeds the allowlist bound.
    pub(crate) fn new(
        any_illegal: AnyIllegalScope,
        actions: &[DomainAction],
    ) -> Option<ControlTable> {
        let count = actions.len();
        if count == 0 || count > ALLOWLIST_MAX {
            return None;
        }
        let mut per_domain =
            [DomainAction::new(ActionKind::FlareOnly, Scope::Connection); ALLOWLIST_MAX];
        per_domain[..count].copy_from_slice(actions);
        Some(ControlTable {
            any_illegal,
            per_domain,
            count,
        })
    }

    /// The AnyIllegal first-slot scope.
    pub fn any_illegal(&self) -> AnyIllegalScope {
        self.any_illegal
    }

    /// Number of configured domain entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// The configured action position (0-based) for this table, or `None`
    /// when the index is not within this table's configured count.
    pub fn ordinal(&self, index: usize) -> Option<DomainOrdinal> {
        DomainOrdinal::mint(index, self.count)
    }

    /// The configured action for an ordinal, or `None` when the ordinal is not
    /// within this table's configured count (including an ordinal minted by a
    /// different, larger table). A filler entry is never reachable.
    pub fn at(&self, ordinal: DomainOrdinal) -> Option<&DomainAction> {
        if ordinal.get() < self.count {
            Some(&self.per_domain[ordinal.get()])
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: usize) -> DomainAction {
        let kind = if i.is_multiple_of(2) {
            ActionKind::FlareOnly
        } else {
            ActionKind::Block
        };
        DomainAction::new(kind, Scope::Connection)
    }

    fn table(count: usize) -> ControlTable {
        let actions: Vec<DomainAction> = (0..count).map(entry).collect();
        ControlTable::new(AnyIllegalScope::All, &actions).expect("in-bound test table")
    }

    #[test]
    fn new_rejects_empty_and_over_limit_sets() {
        assert!(ControlTable::new(AnyIllegalScope::All, &[]).is_none());
        let over: Vec<DomainAction> = (0..=ALLOWLIST_MAX).map(entry).collect();
        assert!(ControlTable::new(AnyIllegalScope::All, &over).is_none());
        let max: Vec<DomainAction> = (0..ALLOWLIST_MAX).map(entry).collect();
        assert!(ControlTable::new(AnyIllegalScope::All, &max).is_some());
    }

    #[test]
    fn two_entry_table_mints_only_its_configured_range() {
        let t = table(2);
        assert!(t.ordinal(0).is_some());
        assert!(t.ordinal(1).is_some());
        assert!(t.ordinal(2).is_none());
        assert!(
            t.ordinal(5).is_none(),
            "two-entry/index5 witness: index 5 is not configured"
        );
    }

    #[test]
    fn at_is_none_for_ordinal_outside_this_tables_count() {
        let t = table(2);
        let out = DomainOrdinal::mint(5, ALLOWLIST_MAX).expect("lawful in a bound-level table");
        assert_eq!(
            t.at(out),
            None,
            "no fabricated configured action for an unconfigured ordinal"
        );
        let in_range = t.ordinal(1).expect("in table range");
        assert_eq!(t.at(in_range), Some(&entry(1)));
    }

    #[test]
    fn at_rejects_a_cross_table_ordinal() {
        let small = table(2);
        let big = table(ALLOWLIST_MAX);
        let cross = big
            .ordinal(5)
            .expect("index 5 configured in a 32-entry table");
        assert_eq!(
            small.at(cross),
            None,
            "an ordinal minted by another table must not index this one"
        );
    }
}
