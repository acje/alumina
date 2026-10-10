use std::fmt;

use crate::config::{FQDN_MAX_LEN, FixedHostname};

/// Maximum inspected ClientHello size including TLS record framing.
pub const MAX_CLIENT_HELLO: usize = 64 * 1024;

/// Maximum plaintext payload per TLS record during inspection.
pub const RECORD_PAYLOAD_LIMIT: usize = 16 * 1024;

/// Maximum number of offered supported_versions entries retained.
const MAX_VERSIONS: usize = 32;

/// Maximum number of distinct extensions tracked for duplicate rejection.
const MAX_EXTENSIONS: usize = 64;

const RANDOM_LEN: usize = 32;

const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;

const SUPPORTED_VERSIONS: u16 = 43;
const SERVER_NAME: u16 = 0;
const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

const TLS13: u16 = 0x0304;
const TLS12: u16 = 0x0303;
const TLS10: u16 = 0x0301;

/// A parsed and framed ClientHello, before profile validation. All fields are
/// fixed-capacity so the gate allocates nothing on the serving path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    versions: [u16; MAX_VERSIONS],
    versions_len: usize,
    sni: [u8; FQDN_MAX_LEN],
    sni_len: usize,
    sni_entries: u8,
    has_ech: bool,
}

impl ClientHello {
    /// The offered non-GREASE supported versions, filtered and ordered.
    pub fn offered_versions(&self) -> &[u16] {
        &self.versions[..self.versions_len]
    }

    /// The first normalized SNI host_name offered.
    pub fn server_name(&self) -> &[u8] {
        &self.sni[..self.sni_len]
    }

    /// The number of host_name entries offered in the server_name extension.
    pub fn sni_entries(&self) -> u8 {
        self.sni_entries
    }

    /// Whether the `encrypted_client_hello` (ECH) extension was present.
    pub fn has_ech(&self) -> bool {
        self.has_ech
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelloAccepted {
    _private: (),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChError {
    TooLarge,
    RecordTooLarge { got: usize },
    ZeroLengthRecord,
    NotHandshake { content_type: u8 },
    Sslv2Framing,
    BadRecordVersion { got: u16 },
    TruncatedRecord,
    NotClientHello { handshake_type: u8 },
    TruncatedHandshake,
    MalformedBody { detail: &'static str },
    UnsupportedLegacyVersion { got: u16 },
    MissingSupportedVersions,
    InvalidVersionOffer { version: u16 },
    MissingCompressionMethods,
    NonNullCompression,
    DuplicateExtension { ext: u16 },
    MalformedExtension { ext: u16 },
    TooManyExtensions,
    EchPresent,
    InvalidServerName { detail: &'static str },
    ServerNameMismatch,
}

impl fmt::Display for ChError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChError::TooLarge => write!(f, "ClientHello exceeds 64 KiB inspection bound"),
            ChError::RecordTooLarge { got } => {
                write!(f, "TLS record payload {got} exceeds 16 KiB")
            }
            ChError::ZeroLengthRecord => write!(f, "TLS handshake record has zero payload"),
            ChError::NotHandshake { content_type } => {
                write!(
                    f,
                    "TLS content type {content_type} is not handshake before ClientHello"
                )
            }
            ChError::Sslv2Framing => write!(f, "SSLv2 ClientHello framing rejected"),
            ChError::BadRecordVersion { got } => {
                write!(
                    f,
                    "TLS record legacy version {got:04x} not accepted for initial ClientHello"
                )
            }
            ChError::TruncatedRecord => write!(f, "TLS record truncated"),
            ChError::NotClientHello { handshake_type } => {
                write!(f, "handshake type {handshake_type} is not ClientHello")
            }
            ChError::TruncatedHandshake => write!(f, "handshake message truncated"),
            ChError::MalformedBody { detail } => write!(f, "ClientHello body malformed: {detail}"),
            ChError::UnsupportedLegacyVersion { got } => {
                write!(
                    f,
                    "legacy_version {got:04x} is not TLS 1.2 compatibility 0x0303"
                )
            }
            ChError::MissingSupportedVersions => write!(
                f,
                "ClientHello lacks the supported_versions extension (TLS 1.3-only profile)"
            ),
            ChError::InvalidVersionOffer { version } => {
                write!(
                    f,
                    "supported_versions offers non-GREASE version {version:04x} other than TLS 1.3"
                )
            }
            ChError::MissingCompressionMethods => {
                write!(f, "ClientHello lacks compression methods")
            }
            ChError::NonNullCompression => write!(
                f,
                "ClientHello compression method is not the single null method"
            ),
            ChError::DuplicateExtension { ext } => {
                write!(f, "duplicate ClientHello extension {ext}")
            }
            ChError::MalformedExtension { ext } => {
                write!(f, "ClientHello extension {ext} malformed")
            }
            ChError::TooManyExtensions => {
                write!(f, "ClientHello carries more than 64 distinct extensions")
            }
            ChError::EchPresent => write!(
                f,
                "encrypted_client_hello (ECH) extension present; rejected"
            ),
            ChError::InvalidServerName { detail } => {
                write!(f, "server_name extension invalid: {detail}")
            }
            ChError::ServerNameMismatch => write!(f, "SNI does not match the approved hostname"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Inspect {
    /// The full ClientHello handshake message is not yet buffered.
    NeedMore,
    /// The ClientHello is framed, parsed, and fully captured. `consumed` is the
    /// number of fed bytes that ended the ClientHello message, so a forwarding
    /// gate can forward exactly those bytes upstream while retaining the rest.
    /// The parsed message is available via [`ChInspector::hello`].
    Complete { consumed: usize },
}

/// Incremental TLS record/handshake inspector that preserves all fed bytes and
/// produces a `ClientHello` once the complete initial ClientHello message is
/// available across one or more consecutive handshake records. It rejects
/// SSLv2 framing, non-handshake records seen before the ClientHello completes,
/// zero-length handshake records, record payloads over 16 KiB, and an
/// inspection total over 64 KiB.
///
/// The inspector retains its scan position and flattened-message scratch
/// across feeds, so each record payload is copied exactly once regardless of
/// the peer's fragmentation pattern. It is sized for boot-owned slot storage
/// (one instance per in-flight setup, reused across connections); it must not
/// be constructed per connection on the stack.
#[derive(Clone, Debug)]
pub struct ChInspector {
    buf: [u8; MAX_CLIENT_HELLO],
    len: usize,
    scan_pos: usize,
    flat: usize,
    scratch: [u8; MAX_CLIENT_HELLO],
    hello: Option<ClientHello>,
    consumed: usize,
}

impl Default for ChInspector {
    fn default() -> Self {
        ChInspector::new()
    }
}

impl ChInspector {
    pub fn new() -> Self {
        ChInspector {
            buf: [0u8; MAX_CLIENT_HELLO],
            len: 0,
            scan_pos: 0,
            flat: 0,
            scratch: [0u8; MAX_CLIENT_HELLO],
            hello: None,
            consumed: 0,
        }
    }

    /// The parsed ClientHello, present once `feed` returned `Inspect::Complete`.
    pub fn hello(&self) -> Option<&ClientHello> {
        self.hello.as_ref()
    }

    /// Feeds bytes into the inspector.
    ///
    /// # Errors
    ///
    /// Returns `TooLarge` when the fed bytes exceed the remaining inspection
    /// capacity before a complete ClientHello was reached, and the framing or
    /// profile errors above at the earliest decidable byte count.
    pub fn feed(&mut self, data: &[u8]) -> Result<Inspect, ChError> {
        if self.hello.is_some() {
            return Ok(Inspect::Complete {
                consumed: self.consumed,
            });
        }
        let room = MAX_CLIENT_HELLO - self.len;
        let take = data.len().min(room);
        if take > 0 {
            self.buf[self.len..self.len + take].copy_from_slice(&data[..take]);
            self.len += take;
        }
        match self.scan_available()? {
            None => {
                if take < data.len() || self.len >= MAX_CLIENT_HELLO {
                    return Err(ChError::TooLarge);
                }
                Ok(Inspect::NeedMore)
            }
            Some((msg_len, consumed)) => {
                self.hello = Some(parse_body(&self.scratch[4..4 + msg_len])?);
                self.consumed = consumed;
                Ok(Inspect::Complete { consumed })
            }
        }
    }

    /// Continues flattening fully-buffered leading handshake records into the
    /// persistent scratch, copying each record payload exactly once. Returns
    /// `Some((msg_len, consumed))` once the complete ClientHello handshake
    /// message (4-byte header plus body) is captured, with the stream byte
    /// count consumed to the end of that message.
    fn scan_available(&mut self) -> Result<Option<(usize, usize)>, ChError> {
        loop {
            if self.scan_pos >= self.len {
                return Ok(None);
            }
            let pos = self.scan_pos;
            if self.buf[pos] & 0x80 != 0 {
                return Err(ChError::Sslv2Framing);
            }
            if pos + 5 > self.len {
                return Ok(None);
            }
            if self.buf[pos] != CONTENT_HANDSHAKE {
                return Err(ChError::NotHandshake {
                    content_type: self.buf[pos],
                });
            }
            let record_version = u16::from_be_bytes([self.buf[pos + 1], self.buf[pos + 2]]);
            if record_version != TLS10 && record_version != TLS12 {
                return Err(ChError::BadRecordVersion {
                    got: record_version,
                });
            }
            let rlen = usize::from(u16::from_be_bytes([self.buf[pos + 3], self.buf[pos + 4]]));
            if rlen > RECORD_PAYLOAD_LIMIT {
                return Err(ChError::RecordTooLarge { got: rlen });
            }
            if rlen == 0 {
                return Err(ChError::ZeroLengthRecord);
            }
            let rec_end = pos + 5 + rlen;
            if rec_end > self.len {
                return Ok(None);
            }
            if self.flat == 0 && rlen < 4 {
                return Err(ChError::TruncatedHandshake);
            }
            if self.flat + rlen > MAX_CLIENT_HELLO {
                return Err(ChError::TooLarge);
            }
            self.scratch[self.flat..self.flat + rlen].copy_from_slice(&self.buf[pos + 5..rec_end]);
            self.flat += rlen;
            self.scan_pos = rec_end;
            if self.flat >= 4 {
                if self.scratch[0] != HANDSHAKE_CLIENT_HELLO {
                    return Err(ChError::NotClientHello {
                        handshake_type: self.scratch[0],
                    });
                }
                let msg_len = (usize::from(self.scratch[1]) << 16)
                    | (usize::from(self.scratch[2]) << 8)
                    | usize::from(self.scratch[3]);
                let need = 4 + msg_len;
                if need > MAX_CLIENT_HELLO {
                    return Err(ChError::TooLarge);
                }
                if self.flat >= need {
                    let consumed = self.scan_pos + need - self.flat;
                    return Ok(Some((msg_len, consumed)));
                }
            }
        }
    }
}

fn u16_at(buf: &[u8], at: usize) -> Result<u16, ChError> {
    let hi = *buf.get(at).ok_or(ChError::MalformedBody {
        detail: "short read u16",
    })?;
    let lo = *buf.get(at + 1).ok_or(ChError::MalformedBody {
        detail: "short read u16",
    })?;
    Ok(u16::from_be_bytes([hi, lo]))
}

fn u8_at(buf: &[u8], at: usize) -> Result<u8, ChError> {
    buf.get(at).copied().ok_or(ChError::MalformedBody {
        detail: "short read u8",
    })
}

fn parse_body(body: &[u8]) -> Result<ClientHello, ChError> {
    let legacy = u16_at(body, 0)?;
    if legacy != TLS12 {
        return Err(ChError::UnsupportedLegacyVersion { got: legacy });
    }
    let mut pos = 2 + RANDOM_LEN;
    let sid_len = usize::from(u8_at(body, pos)?);
    pos += 1 + sid_len;
    let cs_len = usize::from(u16_at(body, pos)?);
    if cs_len % 2 != 0 {
        return Err(ChError::MalformedBody {
            detail: "odd cipher-suite list",
        });
    }
    pos += 2 + cs_len;
    let comp_len = usize::from(u8_at(body, pos)?);
    if comp_len != 1 {
        if comp_len == 0 {
            return Err(ChError::MissingCompressionMethods);
        }
        return Err(ChError::NonNullCompression);
    }
    let comp = u8_at(body, pos + 1)?;
    if comp != 0 {
        return Err(ChError::NonNullCompression);
    }
    pos += 1 + comp_len;
    let ext_total = usize::from(u16_at(body, pos)?);
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end != body.len() {
        return Err(ChError::MalformedBody {
            detail: "extensions do not fill the ClientHello body",
        });
    }
    let mut versions = [0u16; MAX_VERSIONS];
    let mut versions_len = 0usize;
    let mut sv_present = false;
    let mut sni = [0u8; FQDN_MAX_LEN];
    let mut sni_len = 0usize;
    let mut sni_entries = 0u8;
    let mut has_ech = false;
    let mut seen = [0u16; MAX_EXTENSIONS];
    let mut seen_count = 0usize;
    while pos < ext_end {
        let ext_type = u16_at(body, pos)?;
        if seen[..seen_count].contains(&ext_type) {
            return Err(ChError::DuplicateExtension { ext: ext_type });
        }
        if seen_count == seen.len() {
            return Err(ChError::TooManyExtensions);
        }
        seen[seen_count] = ext_type;
        seen_count += 1;
        let ext_len = usize::from(u16_at(body, pos + 2)?);
        let ext_start = pos + 4;
        let ext_end_i = ext_start + ext_len;
        if ext_end_i > body.len() {
            return Err(ChError::MalformedExtension { ext: ext_type });
        }
        let ext_data = &body[ext_start..ext_end_i];
        match ext_type {
            SUPPORTED_VERSIONS => {
                versions_len = parse_supported_versions(ext_data, &mut versions)?;
                sv_present = true;
            }
            SERVER_NAME => {
                parse_server_names(ext_data, &mut sni, &mut sni_len, &mut sni_entries)?;
            }
            ENCRYPTED_CLIENT_HELLO => {
                has_ech = true;
            }
            _ => {}
        }
        pos = ext_end_i;
    }
    if !sv_present {
        return Err(ChError::MissingSupportedVersions);
    }
    validate_versions(&versions[..versions_len])?;
    Ok(ClientHello {
        versions,
        versions_len,
        sni,
        sni_len,
        sni_entries,
        has_ech,
    })
}

fn validate_versions(versions: &[u16]) -> Result<(), ChError> {
    let mut has_tls13 = false;
    for &version in versions {
        if is_grease(version) {
            continue;
        }
        if version != TLS13 {
            return Err(ChError::InvalidVersionOffer { version });
        }
        has_tls13 = true;
    }
    if !has_tls13 {
        return Err(ChError::InvalidVersionOffer { version: 0 });
    }
    Ok(())
}

fn is_grease(value: u16) -> bool {
    let hi = value >> 8;
    let lo = value & 0xff;
    hi == lo
        && matches!(
            hi,
            0x0a | 0x1a
                | 0x2a
                | 0x3a
                | 0x4a
                | 0x5a
                | 0x6a
                | 0x7a
                | 0x8a
                | 0x9a
                | 0xaa
                | 0xba
                | 0xca
                | 0xda
                | 0xea
                | 0xfa
        )
}

fn parse_supported_versions(data: &[u8], out: &mut [u16; MAX_VERSIONS]) -> Result<usize, ChError> {
    if data.is_empty() || usize::from(data[0]) + 1 != data.len() {
        return Err(ChError::MalformedExtension {
            ext: SUPPORTED_VERSIONS,
        });
    }
    let count = usize::from(data[0]);
    if count % 2 != 0 || count / 2 > MAX_VERSIONS {
        return Err(ChError::MalformedExtension {
            ext: SUPPORTED_VERSIONS,
        });
    }
    let mut at = 1usize;
    let mut n = 0usize;
    while at < data.len() {
        out[n] = u16_at(data, at)?;
        n += 1;
        at += 2;
    }
    Ok(n)
}

fn parse_server_names(
    data: &[u8],
    sni: &mut [u8; FQDN_MAX_LEN],
    sni_len: &mut usize,
    entries: &mut u8,
) -> Result<(), ChError> {
    if data.len() < 2 || usize::from(u16_at(data, 0)?) + 2 != data.len() {
        return Err(ChError::InvalidServerName {
            detail: "list-length mismatch",
        });
    }
    let mut at = 2usize;
    while at < data.len() {
        let name_type = u8_at(data, at)?;
        let len = usize::from(u16_at(data, at + 1)?);
        let start = at + 3;
        let end = start + len;
        if end > data.len() {
            return Err(ChError::InvalidServerName {
                detail: "name overflows list",
            });
        }
        if name_type == 0 {
            *entries = entries.checked_add(1).ok_or(ChError::InvalidServerName {
                detail: "too many host_name entries",
            })?;
            if *entries == 1 {
                let raw = &data[start..end];
                let normalized =
                    FixedHostname::normalize(raw).ok_or(ChError::InvalidServerName {
                        detail: "host_name is not a legal FQDN",
                    })?;
                let bytes = normalized.as_bytes();
                sni[..bytes.len()].copy_from_slice(bytes);
                *sni_len = bytes.len();
            }
        }
        at = end;
    }
    Ok(())
}

/// Validates the parsed `ClientHello` against the TLS 1.3-only golden path and
/// the approved CONNECT hostname. Unknown and GREASE extensions were already
/// skipped by length during parsing; ECH is rejected here as a profile rule.
///
/// On success mints the [`HelloAccepted`] capability: its field is private and
/// no constructor exists outside this module, so the returned witness can only
/// be produced by an actual validation (xz3f N7), never by caller discipline.
///
/// # Errors
///
/// Returns `ServerNameMismatch` when the SNI does not equal `approved`, and
/// the profile errors above when the ECH or identity rules fail.
pub fn validate(ch: &ClientHello, approved: &FixedHostname) -> Result<HelloAccepted, ChError> {
    if ch.has_ech {
        return Err(ChError::EchPresent);
    }
    if ch.sni_entries != 1 {
        return Err(ChError::InvalidServerName {
            detail: "requires exactly one host_name entry",
        });
    }
    if ch.server_name() != approved.as_bytes() {
        return Err(ChError::ServerNameMismatch);
    }
    Ok(HelloAccepted { _private: () })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello_msg(legacy: u16, versions: &[u16], snis: &[&str], ech: bool) -> Vec<u8> {
        hello_msg_comp(legacy, versions, snis, ech, 0)
    }

    fn hello_msg_comp(
        legacy: u16,
        versions: &[u16],
        snis: &[&str],
        ech: bool,
        comp: u8,
    ) -> Vec<u8> {
        let mut versions_data = vec![(versions.len() * 2) as u8];
        for v in versions {
            versions_data.extend_from_slice(&v.to_be_bytes());
        }
        let mut snis_data = Vec::new();
        let mut names_data = Vec::new();
        for name in snis {
            names_data.push(0u8);
            names_data.extend_from_slice(&(name.len() as u16).to_be_bytes());
            names_data.extend_from_slice(name.as_bytes());
        }
        snis_data.extend_from_slice(&(names_data.len() as u16).to_be_bytes());
        snis_data.extend_from_slice(&names_data);

        let mut exts = Vec::new();
        exts.extend_from_slice(&SUPPORTED_VERSIONS.to_be_bytes());
        exts.extend_from_slice(&(versions_data.len() as u16).to_be_bytes());
        exts.extend_from_slice(&versions_data);
        exts.extend_from_slice(&SERVER_NAME.to_be_bytes());
        exts.extend_from_slice(&(snis_data.len() as u16).to_be_bytes());
        exts.extend_from_slice(&snis_data);
        if ech {
            exts.extend_from_slice(&ENCRYPTED_CLIENT_HELLO.to_be_bytes());
            exts.extend_from_slice(&0u16.to_be_bytes());
        }

        let mut body = Vec::new();
        body.extend_from_slice(&legacy.to_be_bytes());
        body.extend_from_slice(&[0u8; RANDOM_LEN]);
        body.push(0);
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]);
        body.push(1);
        body.push(comp);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        let hl = body.len() as u32;
        handshake.extend_from_slice(&[(hl >> 16) as u8, (hl >> 8) as u8, hl as u8]);
        handshake.extend_from_slice(&body);

        let mut record = vec![CONTENT_HANDSHAKE];
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut record = vec![CONTENT_HANDSHAKE];
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn parse_one(bytes: &[u8]) -> Result<ClientHello, ChError> {
        let mut inspector = ChInspector::new();
        match inspector.feed(bytes)? {
            Inspect::Complete { .. } => Ok(inspector.hello().expect("complete has hello").clone()),
            Inspect::NeedMore => Err(ChError::TruncatedRecord),
        }
    }

    fn approved(name: &str) -> FixedHostname {
        FixedHostname::normalize(name.as_bytes()).expect("valid approved name")
    }

    #[test]
    fn accepts_tls13_with_single_sni() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
        let ch = parse_one(&msg).expect("parse");
        let v = validate(&ch, &approved("sub.example.org"));
        assert!(v.is_ok(), "valid TLS1.3 ClientHello: {v:?}");
        assert_eq!(ch.offered_versions(), &[TLS13]);
        assert_eq!(ch.server_name(), b"sub.example.org");
        assert_eq!(ch.sni_entries(), 1);
        assert!(!ch.has_ech());
    }

    #[test]
    fn fragmented_records_are_boundary_independent() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
        let mut inspector = ChInspector::new();
        for chunk in msg.chunks(4) {
            match inspector.feed(chunk).expect("feed") {
                Inspect::NeedMore => {}
                Inspect::Complete { .. } => {
                    let hello = inspector.hello().expect("complete has hello");
                    validate(hello, &approved("sub.example.org")).expect("valid");
                    return;
                }
            }
        }
        panic!("never completed");
    }

    #[test]
    fn handshake_split_across_records_completes() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
        let mut split = record(&msg[5..5 + 12]);
        split.extend_from_slice(&record(&msg[5 + 12..]));
        let mut inspector = ChInspector::new();
        match inspector.feed(&split).expect("feed") {
            Inspect::Complete { consumed } => {
                let hello = inspector.hello().expect("complete has hello");
                validate(hello, &approved("sub.example.org")).expect("valid");
                assert_eq!(consumed, split.len(), "consumed ends at the hello");
            }
            Inspect::NeedMore => panic!("multi-record handshake must complete"),
        }
    }

    #[test]
    fn rejects_tls12_only_offer() {
        let msg = hello_msg(TLS12, &[TLS12], &["sub.example.org"], false);
        assert_eq!(
            parse_one(&msg),
            Err(ChError::InvalidVersionOffer { version: TLS12 })
        );
    }

    #[test]
    fn rejects_mixed_offer_with_extra_non_grease() {
        let msg = hello_msg(TLS12, &[TLS13, TLS12], &["sub.example.org"], false);
        assert_eq!(
            parse_one(&msg),
            Err(ChError::InvalidVersionOffer { version: TLS12 })
        );
    }

    #[test]
    fn allows_grease_versions_alongside_tls13() {
        let msg = hello_msg(TLS12, &[0x0a0a, TLS13, 0x1a1a], &["sub.example.org"], false);
        parse_one(&msg).expect("grease allowed");
    }

    #[test]
    fn rejects_grease_only_versions() {
        let msg = hello_msg(TLS12, &[0x0a0a], &["sub.example.org"], false);
        assert_eq!(
            parse_one(&msg),
            Err(ChError::InvalidVersionOffer { version: 0 })
        );
    }

    #[test]
    fn rejects_missing_supported_versions() {
        let no_ext = [0u8, 0u8];
        let mut body = Vec::new();
        body.extend_from_slice(&TLS12.to_be_bytes());
        body.extend_from_slice(&[0u8; RANDOM_LEN]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&no_ext);
        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        let hl = body.len() as u32;
        handshake.extend_from_slice(&[(hl >> 16) as u8, (hl >> 8) as u8, hl as u8]);
        handshake.extend_from_slice(&body);
        let record = record(&handshake);
        assert_eq!(parse_one(&record), Err(ChError::MissingSupportedVersions));
    }

    #[test]
    fn rejects_non_null_compression() {
        let msg = hello_msg_comp(TLS12, &[TLS13], &["sub.example.org"], false, 1);
        assert_eq!(parse_one(&msg), Err(ChError::NonNullCompression));
    }

    #[test]
    fn rejects_multiple_compression_methods() {
        let msg = hello_msg_comp(TLS12, &[TLS13], &["sub.example.org"], false, 0);
        let mut multi = vec![HANDSHAKE_CLIENT_HELLO];
        let handshake = &msg[5..];
        let body = &handshake[4..];
        let hl = body.len() as u32;
        multi.extend_from_slice(&[(hl >> 16) as u8, (hl >> 8) as u8, hl as u8]);
        multi.extend_from_slice(&body[..41]);
        multi.push(2);
        multi.push(0);
        multi.push(1);
        multi.extend_from_slice(&body[44..]);
        let record = record(&multi);
        assert_eq!(parse_one(&record), Err(ChError::NonNullCompression));
    }

    #[test]
    fn trailing_bytes_after_extensions_rejected() {
        let mut body = Vec::new();
        body.extend_from_slice(&TLS12.to_be_bytes());
        body.extend_from_slice(&[0u8; RANDOM_LEN]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1);
        body.push(0);
        let sv = [0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
        body.extend_from_slice(&(sv.len() as u16).to_be_bytes());
        body.extend_from_slice(&sv);
        body.extend_from_slice(&[0xab; 5]);
        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        let hl = body.len() as u32;
        handshake.extend_from_slice(&[(hl >> 16) as u8, (hl >> 8) as u8, hl as u8]);
        handshake.extend_from_slice(&body);
        let record = record(&handshake);
        assert!(matches!(
            parse_one(&record),
            Err(ChError::MalformedBody { .. })
        ));
    }

    #[test]
    fn rejects_ech() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], true);
        let ch = parse_one(&msg).expect("parse");
        assert_eq!(
            validate(&ch, &approved("sub.example.org")),
            Err(ChError::EchPresent)
        );
    }

    #[test]
    fn rejects_mismatched_sni() {
        let msg = hello_msg(TLS12, &[TLS13], &["other.example.net"], false);
        let ch = parse_one(&msg).expect("parse");
        assert_eq!(
            validate(&ch, &approved("sub.example.org")),
            Err(ChError::ServerNameMismatch)
        );
    }

    #[test]
    fn trailing_dot_sni_matches_approved() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org."], false);
        let ch = parse_one(&msg).expect("parse");
        assert_eq!(ch.server_name(), b"sub.example.org");
        assert!(validate(&ch, &approved("sub.example.org")).is_ok());
    }

    #[test]
    fn uppercase_sni_matches_approved() {
        let msg = hello_msg(TLS12, &[TLS13], &["SUB.Example.ORG"], false);
        let ch = parse_one(&msg).expect("parse");
        assert_eq!(ch.server_name(), b"sub.example.org");
        assert!(validate(&ch, &approved("sub.example.org")).is_ok());
    }

    #[test]
    fn rejects_two_sni_entries() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org", "other.test"], false);
        let ch = parse_one(&msg).expect("parse");
        assert_eq!(
            validate(&ch, &approved("sub.example.org")),
            Err(ChError::InvalidServerName {
                detail: "requires exactly one host_name entry",
            })
        );
    }

    #[test]
    fn rejects_duplicate_extension() {
        let mut body = Vec::new();
        body.extend_from_slice(&TLS12.to_be_bytes());
        body.extend_from_slice(&[0u8; RANDOM_LEN]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1);
        body.push(0);
        let mut exts = Vec::new();
        for _ in 0..2 {
            exts.extend_from_slice(&0xfe00u16.to_be_bytes());
            exts.extend_from_slice(&0u16.to_be_bytes());
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        let hl = body.len() as u32;
        handshake.extend_from_slice(&[(hl >> 16) as u8, (hl >> 8) as u8, hl as u8]);
        handshake.extend_from_slice(&body);
        let record = record(&handshake);
        assert_eq!(
            parse_one(&record),
            Err(ChError::DuplicateExtension { ext: 0xfe00 })
        );
    }

    #[test]
    fn rejects_ssl_framing_first_byte() {
        let mut msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
        msg[0] = 0x80;
        assert_eq!(parse_one(&msg), Err(ChError::Sslv2Framing));
    }

    #[test]
    fn rejects_ssl_framing_feed_time() {
        let mut inspector = ChInspector::new();
        assert_eq!(inspector.feed(&[0x80]), Err(ChError::Sslv2Framing));
    }

    #[test]
    fn rejects_non_handshake_at_feed_time() {
        let mut inspector = ChInspector::new();
        let mut header = vec![23u8, 0x03, 0x01, 0x00, 0x00];
        header.extend_from_slice(&[0xab; 4]);
        assert_eq!(
            inspector.feed(&header),
            Err(ChError::NotHandshake { content_type: 23 })
        );
    }

    #[test]
    fn short_record_does_not_panic() {
        let mut inspector = ChInspector::new();
        let result = inspector.feed(&[22, 3, 1, 0, 0]);
        assert_eq!(result, Err(ChError::ZeroLengthRecord));
    }

    #[test]
    fn short_two_byte_payload_does_not_panic() {
        let mut inspector = ChInspector::new();
        let result = inspector.feed(&[22, 3, 1, 0, 2, 1, 0]);
        assert_eq!(result, Err(ChError::TruncatedHandshake));
    }

    #[test]
    fn rejects_record_payload_over_limit() {
        let big = vec![0xabu8; RECORD_PAYLOAD_LIMIT + 1];
        let mut record = vec![CONTENT_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(big.len() as u16).to_be_bytes());
        record.extend_from_slice(&big);
        assert_eq!(
            parse_one(&record),
            Err(ChError::RecordTooLarge {
                got: RECORD_PAYLOAD_LIMIT + 1
            })
        );
    }

    #[test]
    fn rejects_zero_length_handshake_record_between_fragments() {
        let msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
        let mut split = record(&msg[5..5 + 12]);
        split.extend_from_slice(&record(&[]));
        split.extend_from_slice(&record(&msg[5 + 12..]));
        assert_eq!(parse_one(&split), Err(ChError::ZeroLengthRecord));
    }

    #[test]
    fn exact_fill_64k_incomplete_stream_does_not_panic() {
        let mut wire = Vec::with_capacity(MAX_CLIENT_HELLO);
        let mut first = vec![HANDSHAKE_CLIENT_HELLO, 0x00, 0xff, 0xfc];
        first.extend_from_slice(&[0u8; 16380]);
        for payload in [first, vec![0u8; 16384], vec![0u8; 16384], vec![0u8; 16364]] {
            wire.push(CONTENT_HANDSHAKE);
            wire.extend_from_slice(&0x0301u16.to_be_bytes());
            wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            wire.extend_from_slice(&payload);
        }
        assert_eq!(
            wire.len(),
            MAX_CLIENT_HELLO,
            "exactly fills the inspection budget"
        );
        let mut inspector = ChInspector::new();
        let result = inspector.feed(&wire);
        assert_eq!(
            result,
            Err(ChError::TooLarge),
            "full buffer without a complete hello must not panic"
        );
    }

    #[test]
    fn non_handshake_pre_clienthello_rejected() {
        let mut msg = hello_msg(TLS12, &[TLS13], &["sub.example.org"], false);
        msg[0] = 23;
        assert_eq!(
            parse_one(&msg),
            Err(ChError::NotHandshake { content_type: 23 })
        );
    }
}
