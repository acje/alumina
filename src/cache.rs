use crate::config::{ALLOWLIST_MAX, Config};
use crate::eligibility::NumericAddr;
use std::fmt;
use std::net::Ipv4Addr;

/// Fixed address capacity per configured name and family.
pub const MAX_ADDRESSES: usize = 16;

/// Stale DNS authorization grace after TTL expiry, in seconds.
pub const STALE_GRACE: u64 = 259_200;

const UNUSED_SLOT: NumericAddr = NumericAddr::V4(Ipv4Addr::UNSPECIFIED);

/// The two DNS record families a cache entry is keyed by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    A,
    Aaaa,
}

impl Family {
    pub const ALL: [Family; 2] = [Family::A, Family::Aaaa];

    fn index(self) -> usize {
        match self {
            Family::A => 0,
            Family::Aaaa => 1,
        }
    }
}

/// A name index admitted by the configured allowlist, never from unchecked input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NameIndex(u8);

impl NameIndex {
    fn get(self) -> usize {
        usize::from(self.0)
    }
}

/// A generation tag carried by validated in-flight results.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Generation(u64);

impl Generation {
    pub const INITIAL: Generation = Generation(0);

    /// Returns the next generation, or `None` at the maximum value so exhaustion
    /// is explicit and no entry is mutated on failure.
    pub fn checked_next(self) -> Option<Generation> {
        self.0.checked_add(1).map(Generation)
    }
}

/// Freshness view computed from deadlines, never stored on the entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    Empty,
    Fresh,
    Stale,
    Retired,
}

/// A single cache entry: bindings, one freshness deadline, one retirement
/// deadline, and a generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    generation: Generation,
    freshness_deadline: Option<u64>,
    retirement_deadline: Option<u64>,
    bindings: [NumericAddr; MAX_ADDRESSES],
    binding_len: u8,
}

impl Entry {
    const EMPTY: Entry = Entry {
        generation: Generation::INITIAL,
        freshness_deadline: None,
        retirement_deadline: None,
        bindings: [UNUSED_SLOT; MAX_ADDRESSES],
        binding_len: 0,
    };

    pub fn generation(&self) -> Generation {
        self.generation
    }

    pub fn is_empty(&self) -> bool {
        self.binding_len == 0
    }

    /// The currently authorized eligible bindings.
    pub fn bindings(&self) -> &[NumericAddr] {
        &self.bindings[..usize::from(self.binding_len)]
    }

    /// The freshness and retirement deadlines, present exactly when non-empty.
    pub fn deadlines(&self) -> (Option<u64>, Option<u64>) {
        (self.freshness_deadline, self.retirement_deadline)
    }

    /// Computes freshness at `now`; a valid instance yields the same result no
    /// matter how delayed timer processing was.
    pub fn state(&self, now: u64) -> EntryState {
        match self.retirement_deadline {
            None => EntryState::Empty,
            Some(retirement) if now >= retirement => EntryState::Retired,
            Some(_) => match self.freshness_deadline {
                Some(freshness) if now < freshness => EntryState::Fresh,
                Some(_) | None => EntryState::Stale,
            },
        }
    }
}

fn empty_with_generation(generation: Generation) -> Entry {
    Entry {
        generation,
        ..Entry::EMPTY
    }
}

/// A complete validated positive outcome staged for atomic publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedPositive {
    name: NameIndex,
    family: Family,
    generation: Generation,
    bindings: [NumericAddr; MAX_ADDRESSES],
    binding_len: u8,
    receipt: u64,
    ttl: u64,
}

impl StagedPositive {
    /// Stages validated numeric candidate addresses for one name and family.
    ///
    /// The route is crate-private, reserved for the validated DNS outcome
    /// adapter of a later increment. Cross-family and capacity membership are
    /// runtime-validated here; configured-range membership is enforced at
    /// publication time by the admitting cache.
    ///
    /// # Errors
    ///
    /// Returns `BindingCapacityExceeded` when `bindings` exceeds
    /// `MAX_ADDRESSES` (never truncating), or `FamilyMismatch` when a binding
    /// does not match `family`.
    #[allow(dead_code)]
    pub(crate) fn stage(
        name: NameIndex,
        family: Family,
        generation: Generation,
        bindings: &[NumericAddr],
        receipt: u64,
        ttl: u64,
    ) -> Result<StagedPositive, CacheError> {
        if bindings.len() > MAX_ADDRESSES {
            return Err(CacheError::BindingCapacityExceeded);
        }
        if bindings.iter().any(|&addr| {
            matches!(
                (family, addr),
                (Family::A, NumericAddr::V6(_)) | (Family::Aaaa, NumericAddr::V4(_))
            )
        }) {
            return Err(CacheError::FamilyMismatch);
        }
        let mut slots = [UNUSED_SLOT; MAX_ADDRESSES];
        slots[..bindings.len()].copy_from_slice(bindings);
        Ok(StagedPositive {
            name,
            family,
            generation,
            bindings: slots,
            binding_len: bindings.len() as u8,
            receipt,
            ttl,
        })
    }
}

/// Reasons a cache operation can refuse, always leaving prior entries intact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheError {
    NameOutOfRange,
    BindingCapacityExceeded,
    FamilyMismatch,
    GenerationExhausted,
    StaleGeneration,
    DeadlineOverflow,
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detail = match self {
            CacheError::NameOutOfRange => "admitted name range",
            CacheError::BindingCapacityExceeded => "entry address capacity",
            CacheError::FamilyMismatch => "entry record family",
            CacheError::GenerationExhausted => "entry generation",
            CacheError::StaleGeneration => "stale generation",
            CacheError::DeadlineOverflow => "cache deadline overflow",
        };
        write!(f, "cache {detail}")
    }
}

/// The fixed-capacity cache: one entry per admitted name and family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cache {
    name_count: u8,
    entries: [[Entry; 2]; ALLOWLIST_MAX],
}

impl Cache {
    /// Constructs a cache admitting `name_count` allowlist names.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name_count` is zero or exceeds
    /// `ALLOWLIST_MAX`.
    pub fn new(name_count: usize) -> Result<Cache, CacheError> {
        if name_count == 0 || name_count > ALLOWLIST_MAX {
            return Err(CacheError::NameOutOfRange);
        }
        let name_count = u8::try_from(name_count).map_err(|_| CacheError::NameOutOfRange)?;
        Ok(Cache {
            name_count,
            entries: [[Entry::EMPTY; 2]; ALLOWLIST_MAX],
        })
    }

    /// Constructs a cache whose name count exactly matches the validated
    /// allowlist of `config`, so allowlist ordinals index the same names in
    /// the cache (destination-binding, alumina.md:145). The single
    /// running-path constructor: a worker never pairs a config with an
    /// independently sized cache (9pac M4).
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when the allowlist is empty or exceeds
    /// `ALLOWLIST_MAX` (configuration validation already rejects both).
    pub fn for_config(config: &Config) -> Result<Cache, CacheError> {
        Cache::new(config.allowlist().len())
    }

    /// The number of admitted names.
    pub fn name_count(&self) -> usize {
        usize::from(self.name_count)
    }

    /// Returns the admitted index for `index`, or `None` when out of range.
    pub fn name_index(&self, index: usize) -> Option<NameIndex> {
        if index < self.name_count() {
            u8::try_from(index).ok().map(NameIndex)
        } else {
            None
        }
    }

    fn admit(&self, name: NameIndex) -> Result<(), CacheError> {
        if name.get() < self.name_count() {
            Ok(())
        } else {
            Err(CacheError::NameOutOfRange)
        }
    }

    /// A read-level snapshot of one entry by value; the cache never lends
    /// references into its own storage.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted by this cache.
    pub fn entry(&self, name: NameIndex, family: Family) -> Result<Entry, CacheError> {
        self.admit(name)?;
        Ok(*self.entry_ref(name, family))
    }

    fn entry_ref(&self, name: NameIndex, family: Family) -> &Entry {
        &self.entries[name.get()][family.index()]
    }

    fn entry_mut(&mut self, name: NameIndex, family: Family) -> &mut Entry {
        &mut self.entries[name.get()][family.index()]
    }

    /// Publishes a staged positive for the queried family following candidate
    /// eligibility and TTL validation, atomically replacing the entry.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange`, `StaleGeneration`, `GenerationExhausted`, or
    /// `DeadlineOverflow` when respectively the name is not admitted by this
    /// cache, the staged request tag no longer matches the current entry
    /// generation, advancing past the maximum generation, or the
    /// receipt-derived deadlines overflow. The entry is unchanged on every
    /// error path.
    pub fn publish_positive(&mut self, staged: &StagedPositive) -> Result<(), CacheError> {
        self.admit(staged.name)?;
        let entry = self.entry_mut(staged.name, staged.family);
        if staged.generation != entry.generation {
            return Err(CacheError::StaleGeneration);
        }
        let next_generation = entry
            .generation
            .checked_next()
            .ok_or(CacheError::GenerationExhausted)?;
        let ttl = staged.ttl.max(1);
        let freshness = staged
            .receipt
            .checked_add(ttl)
            .ok_or(CacheError::DeadlineOverflow)?;
        let retirement = freshness
            .checked_add(STALE_GRACE)
            .ok_or(CacheError::DeadlineOverflow)?;
        let mut eligible = [UNUSED_SLOT; MAX_ADDRESSES];
        let mut eligible_len = 0usize;
        for &addr in &staged.bindings[..usize::from(staged.binding_len)] {
            if addr.is_eligible() {
                eligible[eligible_len] = addr;
                eligible_len += 1;
            }
        }
        let new_entry = if eligible_len == 0 {
            Entry {
                generation: next_generation,
                ..Entry::EMPTY
            }
        } else {
            Entry {
                generation: next_generation,
                freshness_deadline: Some(freshness),
                retirement_deadline: Some(retirement),
                bindings: eligible,
                binding_len: eligible_len as u8,
            }
        };
        *entry = new_entry;
        Ok(())
    }

    /// Evicts both families of a name following a validated NXDOMAIN.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted by this cache, or
    /// `GenerationExhausted` and leaves both entries unchanged when either
    /// generation cannot advance.
    pub fn evict_nxdomain(&mut self, name: NameIndex) -> Result<(), CacheError> {
        self.admit(name)?;
        let a_next = self
            .entry_ref(name, Family::A)
            .generation
            .checked_next()
            .ok_or(CacheError::GenerationExhausted)?;
        let aaaa_next = self
            .entry_ref(name, Family::Aaaa)
            .generation
            .checked_next()
            .ok_or(CacheError::GenerationExhausted)?;
        *self.entry_mut(name, Family::A) = empty_with_generation(a_next);
        *self.entry_mut(name, Family::Aaaa) = empty_with_generation(aaaa_next);
        Ok(())
    }

    /// Evicts only the queried family following a validated NODATA.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted by this cache, or
    /// `GenerationExhausted` and leaves the entry unchanged when its
    /// generation cannot advance.
    pub fn evict_nodata(&mut self, name: NameIndex, family: Family) -> Result<(), CacheError> {
        self.admit(name)?;
        let next = self
            .entry_ref(name, family)
            .generation
            .checked_next()
            .ok_or(CacheError::GenerationExhausted)?;
        *self.entry_mut(name, family) = empty_with_generation(next);
        Ok(())
    }

    /// Records an exchange failure for an admitted name and family without any
    /// cache mutation, so bindings survive only within existing deadlines.
    ///
    /// # Errors
    ///
    /// Returns `NameOutOfRange` when `name` is not admitted by this cache;
    /// otherwise the call records nothing and never changes a deadline.
    pub fn note_exchange_failure(
        &self,
        name: NameIndex,
        _family: Family,
    ) -> Result<(), CacheError> {
        self.admit(name)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eligibility::NumericAddr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(octets: [u8; 4]) -> NumericAddr {
        NumericAddr::V4(Ipv4Addr::from(octets))
    }

    fn pub_addr() -> NumericAddr {
        v4([1, 1, 1, 1])
    }

    fn priv_addr() -> NumericAddr {
        v4([10, 0, 0, 1])
    }

    fn publish_simple(
        cache: &mut Cache,
        name: NameIndex,
        family: Family,
        tag: Generation,
        addrs: &[NumericAddr],
        receipt: u64,
        ttl: u64,
    ) {
        let staged = StagedPositive::stage(name, family, tag, addrs, receipt, ttl).unwrap();
        cache
            .publish_positive(&staged)
            .unwrap_or_else(|e| panic!("publish failed: {e:?}"));
    }

    fn current_gen(cache: &Cache, name: NameIndex, family: Family) -> Generation {
        cache.entry(name, family).unwrap().generation()
    }

    fn read(cache: &Cache, name: NameIndex, family: Family) -> Entry {
        cache.entry(name, family).unwrap()
    }

    #[test]
    fn cache_new_rejects_out_of_range_name_count() {
        assert_eq!(Cache::new(0), Err(CacheError::NameOutOfRange));
        assert_eq!(
            Cache::new(ALLOWLIST_MAX + 1),
            Err(CacheError::NameOutOfRange)
        );
        assert_eq!(
            Cache::new(1),
            Ok(Cache {
                name_count: 1,
                entries: [[Entry::EMPTY; 2]; ALLOWLIST_MAX],
            })
        );
        assert_eq!(
            Cache::new(ALLOWLIST_MAX).unwrap().name_count(),
            ALLOWLIST_MAX
        );
    }

    #[test]
    fn name_index_admission_is_bounded() {
        let cache = Cache::new(2).unwrap();
        assert_eq!(cache.name_index(0), Some(NameIndex(0)));
        assert_eq!(cache.name_index(1), Some(NameIndex(1)));
        assert_eq!(cache.name_index(2), None);
        assert_eq!(cache.name_index(999), None);
    }

    #[test]
    fn ttl_zero_is_treated_as_one_second() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        publish_simple(
            &mut cache,
            name,
            Family::A,
            Generation::INITIAL,
            &[pub_addr()],
            1000,
            0,
        );
        let entry = read(&cache, name, Family::A);
        assert_eq!(entry.deadlines(), (Some(1001), Some(1001 + STALE_GRACE)));
        assert_eq!(entry.state(1000), EntryState::Fresh);
    }

    #[test]
    fn fresh_stale_retired_boundaries_across_receipt_ttls() {
        for ttl in [0u64, 1, 29, 30, 31, 299, 300, 301] {
            let mut cache = Cache::new(1).unwrap();
            let name = NameIndex(0);
            let effective = ttl.max(1);
            publish_simple(
                &mut cache,
                name,
                Family::A,
                Generation::INITIAL,
                &[pub_addr()],
                1000,
                ttl,
            );
            let entry = read(&cache, name, Family::A);
            let retirement = 1000 + effective + STALE_GRACE;
            assert_eq!(
                entry.state(1000 + effective - 1),
                EntryState::Fresh,
                "ttl={ttl}, before freshness"
            );
            assert_eq!(
                entry.state(1000 + effective),
                EntryState::Stale,
                "ttl={ttl}, at freshness"
            );
            assert_eq!(
                entry.state(retirement - 1),
                EntryState::Stale,
                "ttl={ttl}, before retirement"
            );
            assert_eq!(
                entry.state(retirement),
                EntryState::Retired,
                "ttl={ttl}, at retirement"
            );
            assert_eq!(
                entry.state(retirement + 1),
                EntryState::Retired,
                "ttl={ttl}, after retirement"
            );
        }
    }

    #[test]
    fn delayed_timer_reports_retired_when_now_past_deadline() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        publish_simple(
            &mut cache,
            name,
            Family::Aaaa,
            Generation::INITIAL,
            &[NumericAddr::V6(Ipv6Addr::from(
                0x2606_4700_4700_0000_0000_0000_0000_1111_u128,
            ))],
            500,
            30,
        );
        let retirement = 500 + 30 + STALE_GRACE;
        assert_eq!(
            read(&cache, name, Family::Aaaa).state(retirement + 7000),
            EntryState::Retired
        );
    }

    #[test]
    fn positive_publish_replaces_not_merges() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        publish_simple(
            &mut cache,
            name,
            Family::A,
            Generation::INITIAL,
            &[v4([8, 8, 8, 8]), v4([9, 9, 9, 9])],
            100,
            60,
        );
        let first_gen = current_gen(&cache, name, Family::A);
        assert_eq!(
            read(&cache, name, Family::A).bindings(),
            &[v4([8, 8, 8, 8]), v4([9, 9, 9, 9])]
        );
        let first_retirement = read(&cache, name, Family::A).deadlines().1;

        publish_simple(
            &mut cache,
            name,
            Family::A,
            first_gen,
            &[v4([8, 8, 8, 8])],
            200,
            30,
        );
        let entry = read(&cache, name, Family::A);
        assert_eq!(entry.bindings(), &[v4([8, 8, 8, 8])]);
        assert_ne!(entry.deadlines().1, first_retirement);
        assert_ne!(current_gen(&cache, name, Family::A), first_gen);
    }

    #[test]
    fn empty_eligible_positive_evicts_and_advances_generation() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        publish_simple(
            &mut cache,
            name,
            Family::A,
            Generation::INITIAL,
            &[pub_addr()],
            100,
            60,
        );
        let first_gen = current_gen(&cache, name, Family::A);

        publish_simple(
            &mut cache,
            name,
            Family::A,
            first_gen,
            &[priv_addr()],
            200,
            60,
        );
        let entry = read(&cache, name, Family::A);
        assert!(entry.is_empty());
        assert_eq!(entry.deadlines(), (None, None));
        assert_eq!(entry.state(300), EntryState::Empty);
        assert_ne!(current_gen(&cache, name, Family::A), first_gen);
    }

    #[test]
    fn stale_generation_positive_rejected_state_unchanged() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        publish_simple(
            &mut cache,
            name,
            Family::A,
            Generation::INITIAL,
            &[pub_addr()],
            100,
            60,
        );
        let current = current_gen(&cache, name, Family::A);
        let bindings_before = read(&cache, name, Family::A).bindings().to_vec();

        let stale = StagedPositive::stage(
            name,
            Family::A,
            Generation::INITIAL,
            &[v4([8, 8, 8, 8])],
            200,
            60,
        )
        .unwrap();
        assert_eq!(
            cache.publish_positive(&stale),
            Err(CacheError::StaleGeneration)
        );
        assert_eq!(read(&cache, name, Family::A).bindings(), bindings_before);
        assert_eq!(current_gen(&cache, name, Family::A), current);
    }

    #[test]
    fn nxdomain_evicts_both_families() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        publish_simple(
            &mut cache,
            name,
            Family::A,
            Generation::INITIAL,
            &[pub_addr()],
            100,
            60,
        );
        publish_simple(
            &mut cache,
            name,
            Family::Aaaa,
            Generation::INITIAL,
            &[NumericAddr::V6(Ipv6Addr::from(
                0x2606_4700_4700_0000_0000_0000_0000_1111_u128,
            ))],
            100,
            60,
        );
        let a_gen = current_gen(&cache, name, Family::A);
        let aaaa_gen = current_gen(&cache, name, Family::Aaaa);

        cache.evict_nxdomain(name).unwrap();
        assert!(read(&cache, name, Family::A).is_empty());
        assert!(read(&cache, name, Family::Aaaa).is_empty());
        assert_ne!(current_gen(&cache, name, Family::A), a_gen);
        assert_ne!(current_gen(&cache, name, Family::Aaaa), aaaa_gen);
    }

    #[test]
    fn nodata_evicts_only_queried_family() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        publish_simple(
            &mut cache,
            name,
            Family::A,
            Generation::INITIAL,
            &[pub_addr()],
            100,
            60,
        );
        publish_simple(
            &mut cache,
            name,
            Family::Aaaa,
            Generation::INITIAL,
            &[NumericAddr::V6(Ipv6Addr::from(
                0x2606_4700_4700_0000_0000_0000_0000_1111_u128,
            ))],
            100,
            60,
        );

        let a_gen_before = current_gen(&cache, name, Family::A);
        let aaaa_gen_before = current_gen(&cache, name, Family::Aaaa);

        cache.evict_nodata(name, Family::A).unwrap();
        assert!(read(&cache, name, Family::A).is_empty());
        assert!(!read(&cache, name, Family::Aaaa).is_empty());
        assert_ne!(current_gen(&cache, name, Family::A), a_gen_before);
        assert_eq!(current_gen(&cache, name, Family::Aaaa), aaaa_gen_before);
    }

    #[test]
    fn exchange_failure_retains_bindings_and_never_extends_retirement() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        publish_simple(
            &mut cache,
            name,
            Family::A,
            Generation::INITIAL,
            &[pub_addr(), v4([8, 8, 8, 8])],
            1000,
            30,
        );
        let before = read(&cache, name, Family::A);
        let retirement = before.deadlines().1.unwrap();

        cache.note_exchange_failure(name, Family::A).unwrap();
        cache.note_exchange_failure(name, Family::A).unwrap();
        let after = read(&cache, name, Family::A);
        assert_eq!(after.bindings(), &[pub_addr(), v4([8, 8, 8, 8])]);
        assert_eq!(after.deadlines().1, Some(retirement));
        assert_eq!(after.state(retirement - 1), EntryState::Stale);
        assert_eq!(after.state(retirement), EntryState::Retired);
    }

    #[test]
    fn stage_rejects_overflow_without_truncation() {
        let addrs: Vec<NumericAddr> = (0..=16).map(|i| v4([10, 0, 0, i as u8])).collect();
        let err =
            StagedPositive::stage(NameIndex(0), Family::A, Generation::INITIAL, &addrs, 1, 60);
        assert_eq!(err, Err(CacheError::BindingCapacityExceeded));
    }

    #[test]
    fn stage_rejects_family_mismatch() {
        let err = StagedPositive::stage(
            NameIndex(0),
            Family::A,
            Generation::INITIAL,
            &[NumericAddr::V6(Ipv6Addr::from(
                0x2606_4700_4700_0000_0000_0000_0000_1111_u128,
            ))],
            1,
            60,
        );
        assert_eq!(err, Err(CacheError::FamilyMismatch));
        let err2 = StagedPositive::stage(
            NameIndex(0),
            Family::Aaaa,
            Generation::INITIAL,
            &[pub_addr()],
            1,
            60,
        );
        assert_eq!(err2, Err(CacheError::FamilyMismatch));
    }

    #[test]
    fn generation_exhaustion_is_controlled_and_preserves_state() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        cache.entry_mut(name, Family::A).generation = Generation(u64::MAX);
        let staged =
            StagedPositive::stage(name, Family::A, Generation(u64::MAX), &[pub_addr()], 1, 60)
                .unwrap();
        assert_eq!(
            cache.publish_positive(&staged),
            Err(CacheError::GenerationExhausted)
        );
        assert_eq!(current_gen(&cache, name, Family::A), Generation(u64::MAX));
        assert!(read(&cache, name, Family::A).is_empty());
    }

    fn v6_addr() -> NumericAddr {
        NumericAddr::V6(Ipv6Addr::from(
            0x2606_4700_4700_0000_0000_0000_0000_1111_u128,
        ))
    }

    #[test]
    fn foreign_cache_index_ops_rejected_at_boundary() {
        let mut small = Cache::new(1).unwrap();
        let foreign = Cache::new(2).unwrap().name_index(1).unwrap();

        let staged = StagedPositive::stage(
            foreign,
            Family::A,
            Generation::INITIAL,
            &[pub_addr()],
            1,
            60,
        )
        .unwrap();
        assert_eq!(
            small.publish_positive(&staged),
            Err(CacheError::NameOutOfRange)
        );
        assert_eq!(
            small.evict_nxdomain(foreign),
            Err(CacheError::NameOutOfRange)
        );
        assert_eq!(
            small.evict_nodata(foreign, Family::A),
            Err(CacheError::NameOutOfRange)
        );
        assert_eq!(
            small.note_exchange_failure(foreign, Family::A),
            Err(CacheError::NameOutOfRange)
        );
    }

    #[test]
    fn nxdomain_generation_exhaustion_aaaa_at_max_leaves_both_unchanged() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        publish_simple(
            &mut cache,
            name,
            Family::A,
            Generation::INITIAL,
            &[pub_addr()],
            100,
            60,
        );
        cache.entry_mut(name, Family::Aaaa).generation = Generation(u64::MAX);
        let a_bindings = read(&cache, name, Family::A).bindings().to_vec();
        let a_gen = current_gen(&cache, name, Family::A);
        let aaaa_gen = current_gen(&cache, name, Family::Aaaa);

        assert_eq!(
            cache.evict_nxdomain(name),
            Err(CacheError::GenerationExhausted)
        );
        assert_eq!(
            read(&cache, name, Family::A).bindings(),
            a_bindings.as_slice()
        );
        assert_eq!(current_gen(&cache, name, Family::A), a_gen);
        assert!(read(&cache, name, Family::Aaaa).is_empty());
        assert_eq!(current_gen(&cache, name, Family::Aaaa), aaaa_gen);
    }

    #[test]
    fn nxdomain_generation_exhaustion_a_at_max_leaves_both_unchanged() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        publish_simple(
            &mut cache,
            name,
            Family::Aaaa,
            Generation::INITIAL,
            &[v6_addr()],
            100,
            60,
        );
        cache.entry_mut(name, Family::A).generation = Generation(u64::MAX);
        let aaaa_bindings = read(&cache, name, Family::Aaaa).bindings().to_vec();
        let a_gen = current_gen(&cache, name, Family::A);
        let aaaa_gen = current_gen(&cache, name, Family::Aaaa);

        assert_eq!(
            cache.evict_nxdomain(name),
            Err(CacheError::GenerationExhausted)
        );
        assert_eq!(
            read(&cache, name, Family::Aaaa).bindings(),
            aaaa_bindings.as_slice()
        );
        assert!(read(&cache, name, Family::A).is_empty());
        assert_eq!(current_gen(&cache, name, Family::A), a_gen);
        assert_eq!(current_gen(&cache, name, Family::Aaaa), aaaa_gen);
    }

    #[test]
    fn nodata_generation_exhaustion_preserves_other_family() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        cache.entry_mut(name, Family::A).generation = Generation(u64::MAX);
        publish_simple(
            &mut cache,
            name,
            Family::Aaaa,
            Generation::INITIAL,
            &[v6_addr()],
            100,
            60,
        );
        let aaaa_bindings = read(&cache, name, Family::Aaaa).bindings().to_vec();
        let a_gen = current_gen(&cache, name, Family::A);
        let aaaa_gen = current_gen(&cache, name, Family::Aaaa);

        assert_eq!(
            cache.evict_nodata(name, Family::A),
            Err(CacheError::GenerationExhausted)
        );
        assert_eq!(current_gen(&cache, name, Family::A), a_gen);
        assert_eq!(current_gen(&cache, name, Family::Aaaa), aaaa_gen);
        assert_eq!(
            read(&cache, name, Family::Aaaa).bindings(),
            aaaa_bindings.as_slice()
        );
    }

    #[test]
    fn freshness_deadline_overflow_leaves_entry_unchanged() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        publish_simple(
            &mut cache,
            name,
            Family::A,
            Generation::INITIAL,
            &[pub_addr()],
            100,
            60,
        );
        let before = read(&cache, name, Family::A);
        let staged = StagedPositive::stage(
            name,
            Family::A,
            before.generation(),
            &[v4([8, 8, 8, 8])],
            u64::MAX,
            60,
        )
        .unwrap();
        assert_eq!(
            cache.publish_positive(&staged),
            Err(CacheError::DeadlineOverflow)
        );
        let after = read(&cache, name, Family::A);
        assert_eq!(after.bindings(), before.bindings());
        assert_eq!(after.deadlines(), before.deadlines());
        assert_eq!(after.generation(), before.generation());
    }

    #[test]
    fn grace_deadline_overflow_leaves_entry_unchanged() {
        let mut cache = Cache::new(1).unwrap();
        let name = NameIndex(0);
        publish_simple(
            &mut cache,
            name,
            Family::A,
            Generation::INITIAL,
            &[pub_addr()],
            100,
            60,
        );
        let before = read(&cache, name, Family::A);
        let receipt = u64::MAX - STALE_GRACE;
        let staged = StagedPositive::stage(
            name,
            Family::A,
            before.generation(),
            &[v4([8, 8, 8, 8])],
            receipt,
            1,
        )
        .unwrap();
        assert_eq!(
            cache.publish_positive(&staged),
            Err(CacheError::DeadlineOverflow)
        );
        let after = read(&cache, name, Family::A);
        assert_eq!(after.bindings(), before.bindings());
        assert_eq!(after.deadlines(), before.deadlines());
        assert_eq!(after.generation(), before.generation());
    }

    #[test]
    #[cfg(feature = "alloc-witness")]
    fn cache_zero_heap_after_positive_control() {
        use crate::alloc::{self, Phase};
        let (_, positive) = alloc::run_phase(Phase::BackgroundRefresh, || {
            let bytes = Box::new([0u8; 64]);
            std::hint::black_box(bytes);
        });
        assert!(
            positive.allocs > 0 && positive.deallocs > 0,
            "counter must attribute a local alloc/dealloc: {positive:?}"
        );

        eprintln!(
            "size_of Entry={} Cache={}",
            size_of::<Entry>(),
            size_of::<Cache>()
        );
        let (_, counts) = alloc::run_phase(Phase::BackgroundRefresh, || {
            let mut cache = Cache::new(32).unwrap();
            let name = cache.name_index(0).unwrap();
            let aaaa = cache.name_index(31).unwrap();
            publish_simple(
                &mut cache,
                name,
                Family::A,
                Generation::INITIAL,
                &[pub_addr(), v4([8, 8, 8, 8])],
                1000,
                30,
            );
            publish_simple(
                &mut cache,
                aaaa,
                Family::Aaaa,
                Generation::INITIAL,
                &[NumericAddr::V6(Ipv6Addr::from(
                    0x2606_4700_4700_0000_0000_0000_0000_1111_u128,
                ))],
                1000,
                30,
            );
            let tag = current_gen(&cache, name, Family::A);
            publish_simple(
                &mut cache,
                name,
                Family::A,
                tag,
                &[priv_addr(), v4([8, 8, 8, 8])],
                2000,
                300,
            );
            cache.evict_nxdomain(aaaa).unwrap();
            cache.evict_nodata(name, Family::A).unwrap();
            cache.note_exchange_failure(name, Family::Aaaa).unwrap();
            let mut sink = 0u128;
            for i in 0..32 {
                let n = cache.name_index(i).unwrap();
                for f in Family::ALL {
                    let entry = read(&cache, n, f);
                    sink = sink
                        .wrapping_add(u128::from(
                            entry.state(5000 + u64::from(i as u8)) == EntryState::Fresh,
                        ))
                        .wrapping_add(u128::from(entry.generation().0))
                        .wrapping_add(entry.bindings().len() as u128);
                }
            }
            std::hint::black_box((cache, sink));
        });
        assert!(
            counts.all_zero(),
            "cache core must not allocate: {counts:?}"
        );
    }

    #[test]
    fn foreign_cache_index_read_rejected_and_local_legal() {
        let small = Cache::new(1).unwrap();
        let local = small.name_index(0).unwrap();
        let foreign = Cache::new(2).unwrap().name_index(1).unwrap();
        assert_eq!(
            small.entry(foreign, Family::A),
            Err(CacheError::NameOutOfRange)
        );
        assert_eq!(
            small.entry(foreign, Family::Aaaa),
            Err(CacheError::NameOutOfRange)
        );
        assert!(read(&small, local, Family::A).is_empty());
    }

    #[test]
    #[cfg(feature = "alloc-witness")]
    fn cache_zero_heap_on_error_paths() {
        use crate::alloc::{self, Phase};
        let (_, positive) = alloc::run_phase(Phase::BackgroundRefresh, || {
            let bytes = Box::new([0u8; 64]);
            std::hint::black_box(bytes);
        });
        assert!(
            positive.allocs > 0 && positive.deallocs > 0,
            "counter must attribute a local alloc/dealloc: {positive:?}"
        );

        let (_, counts) = alloc::run_phase(Phase::BackgroundRefresh, || {
            let mut cache = Cache::new(1).unwrap();
            let local = cache.name_index(0).unwrap();
            let foreign = Cache::new(2).unwrap().name_index(1).unwrap();

            let _ = cache.entry(foreign, Family::A);
            let _ = cache.evict_nxdomain(foreign);
            let _ = cache.evict_nodata(foreign, Family::A);
            let _ = cache.note_exchange_failure(foreign, Family::A);
            let staged_f = StagedPositive::stage(
                foreign,
                Family::A,
                Generation::INITIAL,
                &[pub_addr()],
                1,
                60,
            )
            .unwrap();
            let _ = cache.publish_positive(&staged_f);

            cache.entry_mut(local, Family::A).generation = Generation(u64::MAX);
            let staged_gen =
                StagedPositive::stage(local, Family::A, Generation(u64::MAX), &[pub_addr()], 1, 60)
                    .unwrap();
            let _ = cache.publish_positive(&staged_gen);
            let staged_stale = StagedPositive::stage(
                local,
                Family::A,
                Generation(u64::MAX - 1),
                &[pub_addr()],
                1,
                60,
            )
            .unwrap();
            let _ = cache.publish_positive(&staged_stale);

            cache.entry_mut(local, Family::A).generation = Generation::INITIAL;
            let staged_ovf = StagedPositive::stage(
                local,
                Family::A,
                Generation::INITIAL,
                &[v4([8, 8, 8, 8])],
                u64::MAX,
                60,
            )
            .unwrap();
            let _ = cache.publish_positive(&staged_ovf);

            std::hint::black_box((cache, local));
        });
        assert!(
            counts.all_zero(),
            "cache error paths must not allocate: {counts:?}"
        );
    }
}
