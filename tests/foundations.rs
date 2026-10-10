#[cfg(feature = "alloc-witness")]
use alumina::alloc::{self, Phase};
use alumina::fault::{Clock, Outcome, REQUIRED_CATEGORIES, Replay, Replayed, Script};
use alumina::fuzz::{
    CorpusOwnership, DeterministicGen, ParserTarget, RegisterError, Seed, fnv1a64,
};

#[test]
#[cfg(feature = "alloc-witness")]
fn alloc_witness_positive_and_negative_attribution() {
    let (_, counted) = alloc::run_phase(Phase::Serving, || {
        let bytes = Box::new([1u8; 512]);
        std::hint::black_box(&bytes);
        drop(bytes);
        let mut items = Vec::with_capacity(4);
        items.push(1u64);
        items.push(2u64);
        let n = items.len();
        std::hint::black_box(n);
        drop(items);
    });
    assert!(
        counted.allocs > 0,
        "positive: in-phase allocation must be counted"
    );
    assert!(
        counted.deallocs > 0,
        "positive: in-phase deallocation must be counted"
    );

    let stray = vec![2u8; 128];
    std::hint::black_box(&stray);

    let (_, unattributed) = alloc::run_phase(Phase::StartupDns, || {
        let x: u64 = 0;
        std::hint::black_box(x);
    });
    assert!(
        unattributed.all_zero(),
        "negative: out-of-phase allocation must not be attributed: {:?}",
        unattributed
    );
    assert_ne!(alloc::active_phase(), Some(Phase::StartupDns));
}

#[test]
#[cfg(feature = "alloc-witness")]
fn alloc_witness_catches_realloc_in_named_phase() {
    let (_, counts) = alloc::run_phase(Phase::BackgroundRefresh, || {
        let mut v = Vec::with_capacity(1);
        for i in 0..64 {
            v.push(i as u64);
        }
        let len = v.len();
        std::hint::black_box(len);
        drop(v);
    });
    assert!(
        counts.reallocs > 0,
        "witness must observe reallocation (grow) as its own counter"
    );
}

#[test]
#[cfg(feature = "alloc-witness")]
fn alloc_witness_attribution_is_isolated_across_threads() {
    let workers: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                for _ in 0..100 {
                    let _ = alloc::run_phase(Phase::Serving, || {
                        let b = Box::new([1u8; 64]);
                        std::hint::black_box(&b);
                        drop(b);
                    });
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().expect("worker joined");
    }
    for phase in Phase::ALL {
        let (_, counts) = alloc::run_phase(phase, || {
            let a: u64 = 0;
            std::hint::black_box(a);
        });
        assert!(
            counts.all_zero(),
            "phase {:?} must not observe cross-thread allocations: {:?}",
            phase,
            counts
        );
    }
}

#[test]
#[cfg(feature = "alloc-witness")]
fn empty_loop_green_across_all_named_phases() {
    for phase in Phase::ALL {
        let (_, counts) = alloc::run_phase(phase, || {
            let mut acc = 0u64;
            for i in 0..1000_u64 {
                acc = acc.wrapping_add(i);
            }
            std::hint::black_box(acc);
        });
        assert!(
            counts.all_zero(),
            "named phase {:?} must be allocation-free on an empty loop: {:?}",
            phase,
            counts
        );
    }
}

#[test]
fn f2_all_outcome_categories_are_representable() {
    let script = Script::new("every-category")
        .at(
            "read",
            vec![
                Outcome::PartialRead { delivered: 4 },
                Outcome::PartialRead { delivered: 0 },
                Outcome::WouldBlock,
                Outcome::ReadinessWithoutData,
                Outcome::CombinedReadWrite,
                Outcome::Data {
                    bytes: b"abc".to_vec(),
                },
                Outcome::Eof,
            ],
        )
        .at(
            "write",
            vec![Outcome::PartialWrite { accepted: 900 }, Outcome::WouldBlock],
        )
        .at("upstream", vec![Outcome::Reset])
        .at("timer", vec![Outcome::TimerExpiry { at: 5000 }])
        .at("clock", vec![Outcome::Clock { now: 1000 }]);

    let present: Vec<_> = script
        .points()
        .flat_map(|(_, outcomes)| outcomes.iter())
        .map(alumina::fault::Outcome::category)
        .collect();
    for required in REQUIRED_CATEGORIES {
        assert!(
            present.contains(&required),
            "required F2 category {:?} must be scriptable",
            required
        );
    }

    let mut replay = Replay::new(script);
    assert_eq!(replay.script_id(), "every-category");
    assert!(matches!(
        replay.next("read"),
        Some(Replayed {
            outcome: Outcome::PartialRead { delivered: 4 },
            ..
        })
    ));
    assert!(matches!(
        replay.next("write"),
        Some(Replayed {
            outcome: Outcome::PartialWrite { accepted: 900 },
            ..
        })
    ));
}

#[test]
fn f2_replay_iterates_then_exhausts_explicitly() {
    let script = Script::new("det")
        .at(
            "a",
            vec![Outcome::WouldBlock, Outcome::Data { bytes: vec![1] }],
        )
        .at("b", vec![Outcome::Eof]);
    let mut replay = Replay::new(script);
    assert!(matches!(
        replay.next("a"),
        Some(Replayed {
            index: 0,
            outcome: Outcome::WouldBlock,
            ..
        })
    ));
    assert!(matches!(
        replay.next("a"),
        Some(Replayed {
            index: 1,
            outcome: Outcome::Data { .. },
            ..
        })
    ));
    assert_eq!(
        replay.next("a"),
        None,
        "exhausted script point must return None, never repeat its last outcome"
    );
    assert_eq!(replay.next("missing-point"), None);
}

#[test]
fn f2_replay_is_deterministic() {
    let script = Script::new("det")
        .at(
            "a",
            vec![Outcome::WouldBlock, Outcome::Data { bytes: vec![1] }],
        )
        .at("b", vec![Outcome::Eof]);
    let sequence = |replay: &mut Replay| -> Vec<Outcome> {
        ["a", "b", "a", "b"]
            .iter()
            .filter_map(|point| replay.next(point))
            .map(|replayed| replayed.outcome)
            .collect()
    };
    let mut first = Replay::new(script.clone());
    let mut second = Replay::new(script);
    assert_eq!(sequence(&mut first), sequence(&mut second));
}

#[test]
fn f2_clock_outcomes_are_deterministic_and_exhaust() {
    let mut clock = Clock::new(vec![10, 20, 30]);
    assert_eq!(clock.now(), Some(10));
    assert_eq!(clock.now(), Some(20));
    assert_eq!(clock.now(), Some(30));
    assert_eq!(
        clock.now(),
        None,
        "clock must exhaust rather than reuse a last-tick sentinel"
    );
    let mut again = Clock::new(vec![10, 20, 30]);
    assert_eq!(
        [again.now(), again.now(), again.now()],
        [Some(10), Some(20), Some(30)]
    );
}

#[test]
fn f4_same_seed_is_deterministic_and_distinct_seeds_differ() {
    let seed_a = Seed::from_bytes([7u8; 32]);
    let mut first = DeterministicGen::new(seed_a.clone());
    let mut second = DeterministicGen::new(seed_a.clone());
    assert_eq!(
        first.bytes(1024),
        second.bytes(1024),
        "same seed must reproduce the same corpus bytes"
    );
    assert_eq!(first.seed(), &seed_a);

    let bytes_a = DeterministicGen::new(Seed::from_bytes([1u8; 32])).bytes(256);
    let bytes_b = DeterministicGen::new(Seed::from_bytes([2u8; 32])).bytes(256);
    assert_ne!(
        bytes_a, bytes_b,
        "distinct seeds must derive distinct generator state"
    );
}

#[test]
fn f4_target_registration_is_unique_and_stores_hash() {
    let seed = Seed::from_bytes([9u8; 32]);
    let mut generator = DeterministicGen::new(seed.clone());
    let corpus = generator.bytes(256);
    let hash = fnv1a64(corpus.iter().copied());
    assert_eq!(
        hash.hex().len(),
        16,
        "honest 64-bit FNV input hash renders as 16 hex chars"
    );

    let mut ownership = CorpusOwnership::new();
    for target in ParserTarget::ALL {
        ownership
            .register(target, seed.clone())
            .expect("fresh target registers once");
    }
    assert_eq!(ownership.records().len(), ParserTarget::ALL.len());
    for target in ParserTarget::ALL {
        let record = ownership.find(target).expect("registered target");
        assert_eq!(*record.seed(), seed);
        assert_eq!(record.generated_inputs(), 0);
        assert_eq!(record.target().status(), "scaffold");
    }

    assert!(matches!(
        ownership.register(ParserTarget::ConnectHeaders, seed.clone()),
        Err(RegisterError::DuplicateTarget(ParserTarget::ConnectHeaders))
    ));

    for target in ParserTarget::ALL {
        let record = ownership.record_mut(target).expect("registered target");
        record.set_last_input_hash(hash);
        record.add_generated(1);
        assert_eq!(record.last_input_hash(), Some(&hash));
        assert_eq!(record.generated_inputs(), 1);
        assert_eq!(record.target().owning_slice(), target.owning_slice());
    }

    assert_eq!(
        ParserTarget::DnsWire.owning_slice(),
        2,
        "DNS wire parser owns Slice 2"
    );
    assert_eq!(
        ParserTarget::ConnectHeaders.owning_slice(),
        3,
        "CONNECT header parser owns Slice 3"
    );
    assert_eq!(
        ParserTarget::ClientHello.owning_slice(),
        4,
        "ClientHello parser owns Slice 4"
    );
    assert_eq!(
        ParserTarget::LogRecord.owning_slice(),
        6,
        "log-record encoding owns Slice 6"
    );
}
