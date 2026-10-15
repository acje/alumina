use super::*;
use crate::config::parse_config_document;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

enum Step {
    PositiveA {
        ttl: u32,
        octets: [u8; 4],
    },
    PositiveAaaa {
        ttl: u32,
        octets: [u8; 16],
    },
    NodataWithSoa {
        ttl: u32,
        min: u32,
    },
    NxdomainWithSoa {
        ttl: u32,
        min: u32,
    },
    PositiveAMismatchedTid {
        ttl: u32,
        octets: [u8; 4],
    },
    FragmentedPositive {
        ttl: u32,
        octets: [u8; 4],
        chunk: usize,
        gap: Duration,
    },
    Stall(Duration),
    Malformed(Vec<u8>),
    Close,
}

struct Responder {
    addr: SocketAddr,
    handle: Option<thread::JoinHandle<()>>,
    connections: Arc<AtomicUsize>,
}

impl Responder {
    fn port(&self) -> u16 {
        self.addr.port()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .expect("responder thread panicked; test result is unreliable");
        }
    }
}

fn qname_bytes(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn soa_rdata(apex: &str, minimum: u32) -> Vec<u8> {
    let mut rd = qname_bytes(&format!("ns1.{apex}"));
    rd.extend_from_slice(&qname_bytes(&format!("hostmaster.{apex}")));
    for v in [1u32, 3600, 600, 86400, minimum] {
        rd.extend_from_slice(&v.to_be_bytes());
    }
    rd
}

fn question_from(query: &[u8]) -> Vec<u8> {
    query[12..].to_vec()
}

fn record(owner: &[u8], ty: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut rec = owner.to_vec();
    rec.extend_from_slice(&ty.to_be_bytes());
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.extend_from_slice(&ttl.to_be_bytes());
    rec.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    rec.extend_from_slice(rdata);
    rec
}

fn respond_for(query: &[u8], step: &Step) -> Option<Vec<u8>> {
    let tid = u16::from_be_bytes([query[0], query[1]]);
    let qname = &query[12..query.len() - 4];
    let question = question_from(query);
    let mut msg = Vec::new();
    msg.extend_from_slice(&tid.to_be_bytes());
    let (rcode, an, ns, answers, authority): (u16, u16, u16, Vec<Vec<u8>>, Vec<Vec<u8>>) =
        match step {
            Step::PositiveA { ttl, octets } => {
                (0, 1, 0, vec![record(qname, 1, *ttl, octets)], vec![])
            }
            Step::PositiveAMismatchedTid { ttl, octets } => {
                (0, 1, 0, vec![record(qname, 1, *ttl, octets)], vec![])
            }
            Step::PositiveAaaa { ttl, octets } => {
                (0, 1, 0, vec![record(qname, 28, *ttl, octets)], vec![])
            }
            Step::NodataWithSoa { ttl, min } => {
                let soa = soa_rdata("example.org", *min);
                let owner = qname_bytes("example.org");
                (0, 0, 1, vec![], vec![record(&owner, 6, *ttl, &soa)])
            }
            Step::NxdomainWithSoa { ttl, min } => {
                let soa = soa_rdata("example.org", *min);
                let owner = qname_bytes("example.org");
                (3, 0, 1, vec![], vec![record(&owner, 6, *ttl, &soa)])
            }
            Step::Stall(_) | Step::Malformed(_) | Step::FragmentedPositive { .. } | Step::Close => {
                return None;
            }
        };
    let flags = 0x8000 | rcode;
    msg.extend_from_slice(&flags.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&an.to_be_bytes());
    msg.extend_from_slice(&ns.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&question);
    for rec in answers {
        msg.extend_from_slice(&rec);
    }
    for rec in authority {
        msg.extend_from_slice(&rec);
    }
    Some(msg)
}

fn spawn_responder(conn_scripts: Vec<Vec<Step>>) -> Responder {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind responder");
    let addr = listener.local_addr().expect("responder addr");
    let connections = Arc::new(AtomicUsize::new(0));
    let connections_thread = Arc::clone(&connections);
    let handle = thread::spawn(move || {
        let scripts = conn_scripts.into_iter();
        for conn_steps in scripts {
            let (mut sock, _) = match listener.accept() {
                Ok(x) => x,
                Err(_) => break,
            };
            connections_thread.fetch_add(1, Ordering::Relaxed);
            for step in conn_steps {
                match step {
                    Step::Stall(d) => thread::sleep(d),
                    Step::Close => break,
                    Step::Malformed(bytes) => {
                        let mut lenb = [0u8; 2];
                        if read_exact(&mut sock, &mut lenb).is_err() {
                            break;
                        }
                        let qlen = usize::from(u16::from_be_bytes(lenb));
                        let mut q = vec![0u8; qlen];
                        if qlen == 0 || read_exact(&mut sock, &mut q).is_err() {
                            break;
                        }
                        let mut out = Vec::with_capacity(bytes.len() + 2);
                        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                        out.extend_from_slice(&bytes);
                        if sock.write_all(&out).is_err() {
                            break;
                        }
                    }
                    Step::FragmentedPositive {
                        ttl,
                        octets,
                        chunk,
                        gap,
                    } => {
                        let Some(q) = read_query(&mut sock) else {
                            break;
                        };
                        let msg = positive_a_message(&q, ttl, &octets);
                        let mut out = Vec::with_capacity(msg.len() + 2);
                        out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
                        out.extend_from_slice(&msg);
                        let mut at = 0;
                        while at < out.len() {
                            let take = (out.len() - at).min(chunk.max(1));
                            if sock.write_all(&out[at..at + take]).is_err() {
                                break;
                            }
                            at += take;
                            if at < out.len() {
                                thread::sleep(gap);
                            }
                        }
                    }
                    step => {
                        let Some(q) = read_query(&mut sock) else {
                            break;
                        };
                        let reply = respond_for(&q, &step);
                        if let Some(mut bytes) = reply {
                            if matches!(step, Step::PositiveAMismatchedTid { .. }) {
                                let mismatched =
                                    u16::from_be_bytes([bytes[0], bytes[1]]).wrapping_add(1);
                                bytes[0] = (mismatched >> 8) as u8;
                                bytes[1] = mismatched as u8;
                            }
                            let mut out = Vec::with_capacity(bytes.len() + 2);
                            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                            out.extend_from_slice(&bytes);
                            if sock.write_all(&out).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    });
    Responder {
        addr,
        handle: Some(handle),
        connections,
    }
}

fn read_query(sock: &mut TcpStream) -> Option<Vec<u8>> {
    let mut lenb = [0u8; 2];
    if read_exact(sock, &mut lenb).is_err() {
        return None;
    }
    let qlen = usize::from(u16::from_be_bytes(lenb));
    let mut q = vec![0u8; qlen];
    if qlen == 0 || read_exact(sock, &mut q).is_err() {
        return None;
    }
    Some(q)
}

fn positive_a_message(q: &[u8], ttl: u32, octets: &[u8; 4]) -> Vec<u8> {
    let tid = u16::from_be_bytes([q[0], q[1]]);
    let qname = &q[12..q.len() - 4];
    let mut msg = Vec::new();
    msg.extend_from_slice(&tid.to_be_bytes());
    msg.extend_from_slice(&0x8000u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&question_from(q));
    msg.extend_from_slice(&record(qname, 1, ttl, octets));
    msg
}

fn read_exact(sock: &mut TcpStream, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = sock.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
        }
        filled += n;
    }
    Ok(())
}

fn config() -> Config {
    parse_config_document(
        "allowlist = [\"alpha.example.org:443\", \"beta.example.org:443\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\n[any_illegal]\nscope = \"connection\"\n[actions]\nkind = [\"flare_only\", \"flare_only\"]\nscope = [\"connection\", \"connection\"]\n",
    )
    .expect("valid config")
}

fn ns(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)
}

fn bindings_of(
    cache: &Cache,
    ordinal: usize,
    family: Family,
) -> Vec<crate::eligibility::NumericAddr> {
    cache
        .entry(cache.name_index(ordinal).unwrap(), family)
        .unwrap()
        .bindings()
        .to_vec()
}

#[test]
fn token_generation_exhaustion_is_rejected_not_wrapped() {
    let cfg = config();
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.token_gen = usize::MAX;
    let err = transport
        .resolve(&cfg, &mut cache, &mut schedules, ns(0), 1_000_000)
        .expect_err("token generation exhaustion must be a typed error, never a wrap");
    assert_eq!(err, StartupDnsError::TokenExhausted);
}

#[test]
fn storage_failure_escapes_resolve_as_err_not_a_counted_failure() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![
        Step::PositiveA {
            ttl: 120,
            octets: [93, 184, 216, 34],
        },
        Step::NodataWithSoa { ttl: 300, min: 60 },
        Step::PositiveA {
            ttl: 90,
            octets: [1, 1, 1, 1],
        },
        Step::NodataWithSoa { ttl: 300, min: 60 },
    ]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(1).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let err = transport
        .resolve(
            &cfg,
            &mut cache,
            &mut schedules,
            ns(responder.port()),
            1_000_000,
        )
        .expect_err(
            "a schedule-storage refusal on a later name must escape resolve as a fatal error",
        );
    assert!(
        matches!(err, StartupDnsError::Dns(dns::DnsError::Cache(_))),
        "storage refusal surfaces as Dns(Cache): {err:?}"
    );
}

#[test]
fn connect_refused_counts_failure_and_sets_schedule_due() {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let dead_port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    let cfg = config();
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let report = transport
        .resolve(&cfg, &mut cache, &mut schedules, ns(dead_port), 1_000_000)
        .unwrap();
    assert_eq!(report.exchanges, 0);
    assert_eq!(report.failed, 4);
    assert_eq!(report.resolved_names, 0);
    for ordinal in 0..2 {
        for family in Family::ALL {
            assert!(
                schedules.due_time(ordinal, family).unwrap().is_some(),
                "a connect-refused exchange must still advance the schedule for ({ordinal}, {family:?})"
            );
        }
    }
}

#[test]
fn mismatched_tid_fails_exchange_and_nothing_published_for_that_name() {
    let cfg = config();
    let responder = spawn_responder(vec![
        vec![Step::PositiveAMismatchedTid {
            ttl: 120,
            octets: [93, 184, 216, 34],
        }],
        vec![
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ],
    ]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let report = transport
        .resolve(
            &cfg,
            &mut cache,
            &mut schedules,
            ns(responder.port()),
            1_000_000,
        )
        .unwrap();
    assert_eq!(report.exchanges, 3);
    assert_eq!(report.failed, 1);
    assert!(
        bindings_of(&cache, 0, Family::A).is_empty(),
        "a mismatched-tid response must never publish"
    );
    assert_eq!(
        bindings_of(&cache, 1, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(1, 1, 1, 1)
        )]
    );
}

#[test]
fn fragmented_partial_read_response_is_assembled_across_reads() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![
        Step::FragmentedPositive {
            ttl: 120,
            octets: [93, 184, 216, 34],
            chunk: 1,
            gap: Duration::from_millis(2),
        },
        Step::NodataWithSoa { ttl: 300, min: 60 },
        Step::PositiveA {
            ttl: 90,
            octets: [1, 1, 1, 1],
        },
        Step::NodataWithSoa { ttl: 300, min: 60 },
    ]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let report = transport
        .resolve(
            &cfg,
            &mut cache,
            &mut schedules,
            ns(responder.port()),
            1_000_000,
        )
        .unwrap();
    assert_eq!(report.exchanges, 4);
    assert_eq!(report.failed, 0);
    assert_eq!(
        bindings_of(&cache, 0, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(93, 184, 216, 34)
        )]
    );
}

#[test]
fn deadline_expiry_fails_exchange_without_publish_and_reconnects() {
    let cfg = config();
    let responder = spawn_responder(vec![
        vec![Step::Stall(Duration::from_secs(3)), Step::Close],
        vec![
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ],
    ]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let report = transport
        .resolve(
            &cfg,
            &mut cache,
            &mut schedules,
            ns(responder.port()),
            1_000_000,
        )
        .unwrap();
    assert_eq!(report.exchanges, 3);
    assert_eq!(report.failed, 1);
    assert!(bindings_of(&cache, 0, Family::A).is_empty());
    assert_eq!(
        bindings_of(&cache, 1, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(1, 1, 1, 1)
        )]
    );
}

#[test]
fn resolve_publishes_positives_and_nodata_across_one_connection() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![
        Step::PositiveA {
            ttl: 120,
            octets: [93, 184, 216, 34],
        },
        Step::NodataWithSoa { ttl: 300, min: 60 },
        Step::PositiveA {
            ttl: 90,
            octets: [1, 1, 1, 1],
        },
        Step::NodataWithSoa { ttl: 300, min: 60 },
    ]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let report = transport
        .resolve(
            &cfg,
            &mut cache,
            &mut schedules,
            ns(responder.port()),
            1_000_000,
        )
        .unwrap();
    assert_eq!(report.exchanges, 4);
    assert_eq!(report.failed, 0);
    assert_eq!(report.cancelled, 0);
    assert_eq!(report.resolved_names, 2);
    assert_eq!(
        bindings_of(&cache, 0, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(93, 184, 216, 34)
        )]
    );
    assert!(bindings_of(&cache, 0, Family::Aaaa).is_empty());
    assert_eq!(
        bindings_of(&cache, 1, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(1, 1, 1, 1)
        )]
    );
    let due = schedules.due_time(1, Family::A).unwrap().expect("due");
    let interval = due - 1_000_000;
    assert!(
        (90..=95).contains(&interval),
        "refresh from receipt + min(300, max(30,90)): {interval}"
    );
}

#[test]
fn positive_aaaa_publishes_v6_binding_and_schedule() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![
        Step::PositiveA {
            ttl: 120,
            octets: [93, 184, 216, 34],
        },
        Step::PositiveAaaa {
            ttl: 120,
            octets: [
                0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
            ],
        },
        Step::PositiveA {
            ttl: 90,
            octets: [1, 1, 1, 1],
        },
        Step::NodataWithSoa { ttl: 300, min: 60 },
    ]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let report = transport
        .resolve(
            &cfg,
            &mut cache,
            &mut schedules,
            ns(responder.port()),
            1_000_000,
        )
        .unwrap();
    assert_eq!(report.exchanges, 4);
    assert_eq!(report.failed, 0);
    assert_eq!(report.resolved_names, 2);
    assert_eq!(
        bindings_of(&cache, 0, Family::Aaaa),
        vec![crate::eligibility::NumericAddr::V6(
            std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)
        )]
    );
    let due = schedules.due_time(0, Family::Aaaa).unwrap().expect("due");
    let interval = due - 1_000_000;
    assert!(
        (120..=125).contains(&interval),
        "v6 refresh from receipt + min(300, max(30,120)): {interval}"
    );
}

#[test]
fn startup_outcomes_report_latest_validated_negative_not_not_attempted() {
    let cfg = config();
    let responder = spawn_responder(vec![
        vec![
            Step::NxdomainWithSoa { ttl: 300, min: 60 },
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::Stall(Duration::from_secs(3)),
            Step::Close,
        ],
        vec![Step::NodataWithSoa { ttl: 300, min: 60 }],
    ]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let report = transport
        .resolve(
            &cfg,
            &mut cache,
            &mut schedules,
            ns(responder.port()),
            1_000_000,
        )
        .unwrap();
    assert_eq!(report.exchanges, 3, "name0 A, name0 AAAA, name1 AAAA");
    assert_eq!(
        report.failed, 1,
        "name1 A timed out on the stalled connection"
    );
    assert_eq!(
        report.outcomes[0],
        NameOutcome::Negative,
        "a validated NXDOMAIN/NODATA pair is negative, never not_attempted (T1)"
    );
    assert_eq!(
        report.outcomes[1],
        NameOutcome::Negative,
        "name1 AAAA NODATA is the latest concluded outcome, overriding the earlier timeout"
    );
}

#[test]
fn startup_outcome_failed_carries_latest_failure_reason() {
    let cfg = config();
    let responder = spawn_responder(vec![
        vec![
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::Stall(Duration::from_secs(3)),
            Step::Close,
        ],
        vec![Step::Stall(Duration::from_secs(3)), Step::Close],
    ]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let report = transport
        .resolve(
            &cfg,
            &mut cache,
            &mut schedules,
            ns(responder.port()),
            1_000_000,
        )
        .unwrap();
    assert_eq!(report.exchanges, 2);
    assert_eq!(report.failed, 2, "name1 A and AAAA both timed out");
    assert_eq!(
        report.outcomes[0],
        NameOutcome::Negative,
        "name0 stayed a validated negative"
    );
    assert_eq!(
        report.outcomes[1],
        NameOutcome::Failed(FailureReason::Timeout),
        "a name whose latest concluded exchanges all timed out carries the failure reason (T1)"
    );
}

#[test]
fn malformed_response_fails_exchange_and_connection_is_reused_next() {
    let cfg = config();
    let responder = spawn_responder(vec![
        vec![Step::Malformed(vec![1, 2, 3, 4])],
        vec![
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ],
    ]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let report = transport
        .resolve(
            &cfg,
            &mut cache,
            &mut schedules,
            ns(responder.port()),
            1_000_000,
        )
        .unwrap();
    assert_eq!(report.exchanges, 3);
    assert_eq!(report.failed, 1);
    assert!(bindings_of(&cache, 0, Family::A).is_empty());
    assert_eq!(
        bindings_of(&cache, 1, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(1, 1, 1, 1)
        )]
    );
}

#[test]
fn stalled_responder_times_out_exchange_and_reconnects() {
    let cfg = config();
    let responder = spawn_responder(vec![
        vec![Step::Stall(Duration::from_secs(1)), Step::Close],
        vec![
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::PositiveA {
                ttl: 90,
                octets: [1, 1, 1, 1],
            },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ],
    ]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let report = transport
        .resolve(
            &cfg,
            &mut cache,
            &mut schedules,
            ns(responder.port()),
            1_000_000,
        )
        .unwrap();
    assert_eq!(report.exchanges, 3);
    assert_eq!(report.failed, 1);
    assert!(
        responder.connections() >= 2,
        "a stalled-then-closed exchange must reconnect on a fresh connection"
    );
    assert!(bindings_of(&cache, 0, Family::A).is_empty());
    assert_eq!(
        bindings_of(&cache, 1, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(1, 1, 1, 1)
        )]
    );
}

#[test]
fn cooperative_silent_peer_yields_pending_before_deadline() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![Step::Stall(Duration::from_secs(1)), Step::Close]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_millis(400);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline)
        .unwrap();
    let first = transport
        .advance_exchange(fqdn, &mut cache, &mut schedules)
        .unwrap();
    assert!(
        matches!(first, TurnResult::Pending),
        "a turn with an unready peer must yield Pending without concluding, got {first:?}"
    );
    assert!(
        Instant::now() < deadline,
        "the exchange must not conclude before its absolute deadline"
    );
    let mut failures = 0;
    loop {
        match transport
            .advance_exchange(fqdn, &mut cache, &mut schedules)
            .unwrap()
        {
            TurnResult::Pending => {
                let _ = transport.wait_dns_readiness(deadline).unwrap();
            }
            TurnResult::Failed => {
                failures += 1;
                break;
            }
            other => panic!("a silent peer must conclude as a counted failure, got {other:?}"),
        }
    }
    assert_eq!(
        failures, 1,
        "the exchange must settle its counted failure exactly once"
    );
    assert!(
        schedules.due_time(0, Family::A).unwrap().is_some(),
        "a silent-peer failure must still advance the schedule backoff"
    );
    assert!(
        cache
            .entry(cache.name_index(0).unwrap(), Family::A)
            .unwrap()
            .bindings()
            .is_empty(),
        "a silent-peer exchange must not publish"
    );
    assert!(
        transport.stream.is_none(),
        "a failed exchange must close the connection for the next attempt"
    );
    drop(responder);
}

#[test]
fn cooperative_advance_returns_control_to_worker_between_turns() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![Step::Stall(Duration::from_secs(1)), Step::Close]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_millis(400);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline)
        .unwrap();
    let mut worker_turns = 0u32;
    let mut terminal = None;
    for _ in 0..64 {
        match transport
            .advance_exchange(fqdn, &mut cache, &mut schedules)
            .unwrap()
        {
            TurnResult::Pending => {
                worker_turns += 1;
                if transport
                    .exchange_deadline()
                    .is_some_and(|d| Instant::now() >= d)
                {
                    continue;
                }
                let _ = transport.wait_dns_readiness(deadline).unwrap();
            }
            other => {
                terminal = Some(other);
                break;
            }
        }
    }
    assert_eq!(
        terminal,
        Some(TurnResult::Failed),
        "a silent peer must conclude as a counted failure"
    );
    assert!(
        worker_turns >= 2,
        "the worker must observe at least two bounded nonblocking turns before conclusion: {worker_turns}"
    );
    drop(responder);
}

#[test]
fn cooperative_exchange_publishes_on_valid_response() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![
        Step::PositiveA {
            ttl: 120,
            octets: [93, 184, 216, 34],
        },
        Step::Close,
    ]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline)
        .unwrap();
    let mut result = None;
    for _ in 0..256 {
        match transport
            .advance_exchange(fqdn, &mut cache, &mut schedules)
            .unwrap()
        {
            TurnResult::Pending => {
                if transport
                    .exchange_deadline()
                    .is_some_and(|d| Instant::now() >= d)
                {
                    continue;
                }
                let _ = transport.wait_dns_readiness(deadline).unwrap();
            }
            term => {
                result = Some(term);
                break;
            }
        }
    }
    assert_eq!(
        result,
        Some(TurnResult::Published),
        "a valid response must publish at the primitive level"
    );
    assert_eq!(
        bindings_of(&cache, 0, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(93, 184, 216, 34)
        )]
    );
    let due = schedules.due_time(0, Family::A).unwrap().expect("due");
    let interval = due - 1_000_000;
    assert!(
        (120..=125).contains(&interval),
        "refresh from receipt + min(300, max(30,120)): {interval}"
    );
    drop(responder);
}

#[cfg(feature = "alloc-witness")]
#[test]
fn startup_dns_phase_is_allocation_free_including_reconnect() {
    use crate::alloc::{self, Phase};
    use crate::serve::{ServeStorage, StartupDecision};

    let (_, control) = alloc::run_phase(Phase::StartupDns, || {
        let bytes = Box::new([0u8; 64]);
        std::hint::black_box(bytes);
    });
    assert!(
        control.allocs > 0 && control.deallocs > 0,
        "counter must attribute a local alloc/dealloc: {control:?}"
    );

    let cfg = config();
    let responder = spawn_responder(vec![
        vec![Step::Malformed(vec![0xff, 0xff, 0xff, 0xff])],
        vec![
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::NodataWithSoa { ttl: 300, min: 60 },
            Step::NodataWithSoa { ttl: 300, min: 60 },
        ],
    ]);
    let mut storage = ServeStorage::boot(&cfg).expect("boot storage outside the measured window");

    let (outcome, counts) = alloc::run_phase(Phase::StartupDns, || {
        storage
            .run_startup_within(ns(responder.port()), 1_000_000, Duration::from_millis(700))
            .expect("production startup window")
    });
    assert!(
        counts.all_zero(),
        "the ACTUAL startup DNS window (resolve_window over booted storage, not the test driver resolve_body) must be allocation-free including a reconnect: {counts:?}"
    );
    assert!(
        matches!(outcome.decision, StartupDecision::Exit75 { .. }),
        "both names unresolved under allowance 1 must exit 75 without binding a listener"
    );
    assert_eq!(outcome.report.resolved_names, 0);
    assert!(
        outcome.report.failed > 0,
        "the malformed first exchange plus the negative responses must count failures"
    );
    assert!(
        responder.connections() >= 2,
        "the malformed response must force a transport reconnect inside the measured window"
    );
    drop(responder);
}

#[test]
fn nxdomain_evicts_for_the_name_via_cache() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![
        Step::NxdomainWithSoa { ttl: 300, min: 60 },
        Step::NxdomainWithSoa { ttl: 300, min: 60 },
        Step::PositiveA {
            ttl: 90,
            octets: [1, 1, 1, 1],
        },
        Step::NodataWithSoa { ttl: 300, min: 60 },
    ]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    let report = transport
        .resolve(
            &cfg,
            &mut cache,
            &mut schedules,
            ns(responder.port()),
            1_000_000,
        )
        .unwrap();
    assert_eq!(report.exchanges, 4);
    assert_eq!(report.resolved_names, 1);
    assert!(bindings_of(&cache, 0, Family::A).is_empty());
    assert!(bindings_of(&cache, 0, Family::Aaaa).is_empty());
    assert_eq!(
        bindings_of(&cache, 1, Family::A),
        vec![crate::eligibility::NumericAddr::V4(
            std::net::Ipv4Addr::new(1, 1, 1, 1)
        )]
    );
}

#[test]
fn wait_until_next_step_with_no_scheduled_step_does_not_decide_early() {
    let transport = StartupDns::new().unwrap();
    let schedules = Schedules::new(2).unwrap();
    let resolved = [false, true];
    let wait = wait_until_next_step(&transport, &schedules, 2, &resolved).unwrap();
    assert!(
        wait > Duration::from_millis(100),
        "an unresolved name with no scheduled step must sleep toward the \
         window deadline, not break early: {wait:?}"
    );
}

#[test]
fn start_active_exchange_is_refused_and_first_survives() {
    let cfg = config();
    let fqdn0 = cfg.allowlist().get(0).unwrap();
    let fqdn1 = cfg.allowlist().get(1).unwrap();
    let deadline = Instant::now() + Duration::from_secs(EXCHANGE_DEADLINE_SECS);
    {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let dead_port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(dead_port);
        transport.now0 = 1_000_000;
        transport
            .start_exchange(fqdn0, Family::A, 0, deadline)
            .unwrap();
        let err = transport
            .start_exchange(fqdn1, Family::A, 1, deadline)
            .expect_err(
                "a second start on an active exchange must be refused, never silently \
                 replace the outstanding exchange",
            );
        assert_eq!(
            err,
            StartupDnsError::ExchangeActive,
            "the refusal must be the typed ExchangeActive error"
        );
    }
    {
        let responder = spawn_responder(vec![vec![
            Step::PositiveA {
                ttl: 120,
                octets: [93, 184, 216, 34],
            },
            Step::Close,
        ]]);
        let mut cache = Cache::new(2).unwrap();
        let mut schedules = Schedules::new(2).unwrap();
        let mut transport = StartupDns::new().unwrap();
        transport.addr = ns(responder.port());
        transport.now0 = 1_000_000;
        transport
            .start_exchange(fqdn0, Family::A, 0, deadline)
            .unwrap();
        let err = transport
            .start_exchange(fqdn1, Family::A, 1, deadline)
            .expect_err("a refused second start must not be absorbed or deferred; it is typed");
        assert_eq!(err, StartupDnsError::ExchangeActive);
        let mut result = None;
        for _ in 0..200 {
            match transport
                .advance_exchange(fqdn0, &mut cache, &mut schedules)
                .unwrap()
            {
                TurnResult::Pending => {
                    if transport
                        .exchange_deadline()
                        .is_some_and(|d| Instant::now() >= d)
                    {
                        continue;
                    }
                    let _ = transport.wait_dns_readiness(deadline).unwrap();
                }
                term => {
                    result = Some(term);
                    break;
                }
            }
        }
        assert_eq!(
            result,
            Some(TurnResult::Published),
            "the first exchange must still conclude despite the refused second start"
        );
        assert_eq!(
            bindings_of(&cache, 0, Family::A),
            vec![crate::eligibility::NumericAddr::V4(
                std::net::Ipv4Addr::new(93, 184, 216, 34)
            )]
        );
        assert!(
            bindings_of(&cache, 1, Family::A).is_empty(),
            "the refused second start must publish nothing and not advance its schedule"
        );
        drop(responder);
    }
}

#[test]
fn cooperative_turn_performs_zero_blocking_polls() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![Step::Stall(Duration::from_secs(1)), Step::Close]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline)
        .unwrap();
    for _ in 0..32 {
        let before = transport.poll_ticks;
        let res = transport
            .advance_exchange(fqdn, &mut cache, &mut schedules)
            .unwrap();
        assert_eq!(
            transport.poll_ticks, before,
            "advance_exchange must perform zero blocking polls per turn \
             (readiness waiting is the single owner's job), got turn {res:?}"
        );
    }
    let before = transport.poll_ticks;
    let _ready = transport
        .wait_dns_readiness(Instant::now() + Duration::from_millis(10))
        .unwrap();
    assert!(
        transport.poll_ticks > before,
        "only the owner-owned wait_dns_readiness is the sanctioned poll site"
    );
    drop(responder);
}

#[test]
fn cooperative_send_wouldblock_makes_owner_wait_instead_of_busy_looping() {
    let cfg = config();
    let responder = spawn_responder(vec![vec![
        Step::PositiveA {
            ttl: 120,
            octets: [93, 184, 216, 34],
        },
        Step::Close,
    ]]);
    let mut cache = Cache::new(2).unwrap();
    let mut schedules = Schedules::new(2).unwrap();
    let mut transport = StartupDns::new().unwrap();
    transport.addr = ns(responder.port());
    transport.now0 = 1_000_000;
    let fqdn = cfg.allowlist().get(0).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    transport
        .start_exchange(fqdn, Family::A, 0, deadline)
        .unwrap();
    transport.arm_write(WriteForce::Partial(1));
    let mut guard = 0;
    loop {
        match transport.active_step() {
            Some(ExchangeStep::Connecting) => {
                assert!(matches!(
                    transport
                        .advance_exchange(fqdn, &mut cache, &mut schedules)
                        .unwrap(),
                    TurnResult::Pending
                ));
                let _ = transport.wait_dns_readiness(deadline).unwrap();
            }
            Some(ExchangeStep::SendReady) => break,
            other => panic!("unexpected stage reaching the send path: {other:?}"),
        }
        guard += 1;
        assert!(guard < 16, "exchange did not reach the sending stage");
    }
    assert!(matches!(
        transport
            .advance_exchange(fqdn, &mut cache, &mut schedules)
            .unwrap(),
        TurnResult::Pending
    ));
    let before = transport.poll_ticks;
    let _ = transport.wait_dns_readiness(deadline).unwrap();
    assert_eq!(
        transport.poll_ticks, before,
        "after send progress the owner must not wait; the first send has \
         no wait and the next turn keeps pushing"
    );
    transport.arm_write(WriteForce::WouldBlock);
    assert!(matches!(
        transport
            .advance_exchange(fqdn, &mut cache, &mut schedules)
            .unwrap(),
        TurnResult::Pending
    ));
    let before = transport.poll_ticks;
    let _ = transport.wait_dns_readiness(deadline).unwrap();
    assert!(
        transport.poll_ticks > before,
        "after an actual sending WouldBlock the owner wait must perform a \
         real poll (awaiting-writable), not an instant-returning busy loop"
    );
    let mut result = None;
    for _ in 0..200 {
        match transport
            .advance_exchange(fqdn, &mut cache, &mut schedules)
            .unwrap()
        {
            TurnResult::Pending => {
                if transport
                    .exchange_deadline()
                    .is_some_and(|d| Instant::now() >= d)
                {
                    continue;
                }
                let _ = transport.wait_dns_readiness(deadline).unwrap();
            }
            term => {
                result = Some(term);
                break;
            }
        }
    }
    assert_eq!(
        result,
        Some(TurnResult::Published),
        "a valid response must publish after an awaited would-block send"
    );
    assert!(!bindings_of(&cache, 0, Family::A).is_empty());
    drop(responder);
}
