use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::cache::{Cache, CacheError, Family, Generation, MAX_ADDRESSES, StagedPositive};
use crate::config::Fqdn;
use crate::eligibility::NumericAddr;
use crate::schedule::{Schedules, Soa};

/// Maximum DNS message size accepted over the wire (16 KiB).
pub const DNS_MSG_LIMIT: usize = 16 * 1024;

/// Maximum rooted CNAME chain length accepted in one answer.
pub const MAX_CNAME_LINKS: usize = 8;

/// Maximum total resource records (question excluded) inspected per message,
/// bounded before any per-record work so a peer header cannot drive
/// allocation.
pub const MAX_TOTAL_RR: usize = 128;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_DNAME: u16 = 39;
const CLASS_IN: u16 = 1;

const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;

const MAX_NAME_BYTES: usize = 255;
const NAME_CAP: usize = 256;

/// A decoded DNS name (lowercase, without a trailing root label), stored in a
/// fixed buffer so the response path allocates nothing after boot. The decoded
/// length bound is `MAX_NAME_BYTES` per the canonical wire contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DnsName {
    bytes: [u8; NAME_CAP],
    len: usize,
}

impl Default for DnsName {
    fn default() -> Self {
        DnsName {
            bytes: [0; NAME_CAP],
            len: 0,
        }
    }
}

impl DnsName {
    fn from_exact(source: &[u8]) -> DnsName {
        let mut out = DnsName::default();
        out.bytes[..source.len()].copy_from_slice(source);
        out.len = source.len();
        out
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn eq_bytes(&self, other: &[u8]) -> bool {
        self.len == other.len() && &self.bytes[..self.len] == other
    }

    fn push(&mut self, byte: u8) -> Result<(), DnsError> {
        if self.len >= MAX_NAME_BYTES {
            return Err(DnsError::NameTooLong);
        }
        self.bytes[self.len] = byte;
        self.len += 1;
        Ok(())
    }
}

/// Up to `MAX_ADDRESSES` validated numeric candidates in fixed storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingList {
    addrs: [NumericAddr; MAX_ADDRESSES],
    len: u8,
}

impl Default for BindingList {
    fn default() -> Self {
        BindingList {
            addrs: [NumericAddr::V4(Ipv4Addr::UNSPECIFIED); MAX_ADDRESSES],
            len: 0,
        }
    }
}

impl BindingList {
    /// The eligible candidate addresses.
    pub fn as_slice(&self) -> &[NumericAddr] {
        &self.addrs[..usize::from(self.len)]
    }

    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, addr: NumericAddr) -> Result<(), DnsError> {
        if self.len >= MAX_ADDRESSES as u8 {
            return Err(DnsError::CandidatesExceeded {
                limit: MAX_ADDRESSES,
            });
        }
        self.addrs[usize::from(self.len)] = addr;
        self.len += 1;
        Ok(())
    }

    /// Builds a list from validated candidates, rejecting any set that exceeds
    /// `MAX_ADDRESSES` rather than retaining a truncated subset.
    pub fn from_slice(addrs: &[NumericAddr]) -> Result<BindingList, DnsError> {
        if addrs.len() > MAX_ADDRESSES {
            return Err(DnsError::CandidatesExceeded {
                limit: MAX_ADDRESSES,
            });
        }
        let mut out = BindingList::default();
        out.addrs[..addrs.len()].copy_from_slice(addrs);
        out.len = addrs.len() as u8;
        Ok(out)
    }
}

/// A validated DNS outcome, ready for cache and schedule application.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum Outcome {
    /// Validated positive answer with eligible candidates and the earliest
    /// supporting TTL across the rooted CNAME chain.
    Positive {
        family: Family,
        bindings: BindingList,
        ttl: u64,
    },
    /// Name-wide validated NXDOMAIN; the SOA, when present, governs negative
    /// refresh scheduling.
    NxDomain { soa: Option<Soa> },
    /// Per-type validated NODATA; a covering SOA is required for NODATA.
    NoData { family: Family, soa: Option<Soa> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsError {
    BufferExhausted,
    MessageTooLong,
    QueryTooLong,
    BadTid {
        expected: u16,
        got: u16,
    },
    NotResponse,
    BadOpcode {
        got: u8,
    },
    BadRcode {
        code: u8,
    },
    Truncated,
    QuestionCount {
        got: usize,
    },
    QuestionMismatch,
    ExcessiveRecords {
        total: usize,
        limit: usize,
    },
    BadClass {
        got: u16,
    },
    BadType {
        got: u16,
    },
    BadRdataLength {
        ty: u16,
        got: usize,
        expected: usize,
    },
    MalformedSoa,
    TrailingBytes,
    ReservedLabelType {
        offset: usize,
    },
    LabelTooLong {
        len: usize,
    },
    NameTooLong,
    PointerNotBackward,
    PointerCycle,
    ConflictingCname,
    CnameCoexist,
    CnameLoop,
    CnameTooDeep {
        links: usize,
    },
    TerminalWithoutData,
    DnameUnsupported,
    CandidatesExceeded {
        limit: usize,
    },
    SoaCount {
        got: usize,
    },
    NonCoveringSoa,
    EmptyNoerrorWithoutSoa,
    Cache(CacheError),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::BufferExhausted => write!(f, "DNS encoding buffer exhausted"),
            DnsError::MessageTooLong => write!(f, "DNS message exceeds 16 KiB"),
            DnsError::QueryTooLong => write!(f, "DNS query name too long"),
            DnsError::BadTid { expected, got } => {
                write!(
                    f,
                    "DNS transaction id mismatch: expected {expected}, got {got}"
                )
            }
            DnsError::NotResponse => write!(f, "DNS message is not a response"),
            DnsError::BadOpcode { got } => write!(f, "DNS response opcode {got} is not QUERY"),
            DnsError::BadRcode { code } => write!(f, "DNS response code {code} not handled"),
            DnsError::Truncated => write!(f, "DNS response truncated"),
            DnsError::QuestionCount { got } => write!(f, "DNS question count {got}, expected 1"),
            DnsError::QuestionMismatch => write!(f, "DNS question does not match the query"),
            DnsError::ExcessiveRecords { total, limit } => write!(
                f,
                "DNS record count {total} exceeds the {limit} inspection bound"
            ),
            DnsError::BadClass { got } => write!(f, "DNS record class {got} is not IN"),
            DnsError::BadType { got } => write!(f, "DNS unsupported record type {got}"),
            DnsError::BadRdataLength { ty, got, expected } => {
                write!(f, "DNS type {ty} rdata {got} bytes, expected {expected}")
            }
            DnsError::MalformedSoa => write!(f, "DNS SOA rdata malformed"),
            DnsError::TrailingBytes => write!(f, "DNS message has trailing bytes"),
            DnsError::ReservedLabelType { offset } => {
                write!(f, "DNS reserved label type at offset {offset}")
            }
            DnsError::LabelTooLong { len } => write!(f, "DNS label {len} bytes exceeds 63"),
            DnsError::NameTooLong => write!(f, "DNS name exceeds 255 bytes"),
            DnsError::PointerNotBackward => write!(f, "DNS compression pointer not backward"),
            DnsError::PointerCycle => write!(f, "DNS compression pointer cycle"),
            DnsError::ConflictingCname => write!(f, "DNS conflicting CNAME targets"),
            DnsError::CnameCoexist => {
                write!(f, "DNS CNAME coexists with address data at the same owner")
            }
            DnsError::CnameLoop => write!(f, "DNS CNAME chain loop"),
            DnsError::CnameTooDeep { links } => {
                write!(f, "DNS CNAME chain exceeds 8 links ({links})")
            }
            DnsError::TerminalWithoutData => write!(
                f,
                "DNS terminal owner carries address data contradicting NXDOMAIN"
            ),
            DnsError::DnameUnsupported => write!(f, "DNS DNAME present; unsupported"),
            DnsError::CandidatesExceeded { limit } => write!(
                f,
                "DNS candidate addresses exceed the {limit} inspection bound"
            ),
            DnsError::SoaCount { got } => {
                write!(f, "DNS authority SOA count {got}, expected at most 1")
            }
            DnsError::NonCoveringSoa => write!(f, "DNS SOA does not cover the terminal name"),
            DnsError::EmptyNoerrorWithoutSoa => write!(
                f,
                "DNS empty NOERROR answer without covering SOA is not NODATA"
            ),
            DnsError::Cache(err) => write!(f, "DNS cache refused: {err:?}"),
        }
    }
}

/// Applies a validated `outcome` to the cache and schedule for one allowlist
/// `index`, using the in-flight `generation` and the monotonic `receipt` and
/// `now` values. Only validated outcomes mutate state.
///
/// # Errors
///
/// Returns `DnsError::Cache` when the cache or schedule refuses the mutation
/// without changing any entry.
pub fn apply_outcome(
    cache: &mut Cache,
    schedules: &mut Schedules,
    index: usize,
    generation: Generation,
    receipt: u64,
    now: u64,
    outcome: Outcome,
) -> Result<(), DnsError> {
    let name = cache
        .name_index(index)
        .ok_or(DnsError::Cache(CacheError::NameOutOfRange))?;
    match outcome {
        Outcome::Positive {
            bindings,
            ttl,
            family: positive_family,
        } => {
            let staged = StagedPositive::stage(
                name,
                positive_family,
                generation,
                bindings.as_slice(),
                receipt,
                ttl,
            )
            .map_err(DnsError::Cache)?;
            cache.publish_positive(&staged).map_err(DnsError::Cache)?;
            schedules
                .note_positive(
                    index,
                    positive_family,
                    receipt,
                    ttl,
                    !bindings.is_empty(),
                    now,
                )
                .map_err(|err| DnsError::Cache(map_schedule(err)))?;
        }
        Outcome::NxDomain { soa } => {
            cache.evict_nxdomain(name).map_err(DnsError::Cache)?;
            schedules
                .note_nxdomain(index, soa, receipt, now)
                .map_err(|err| DnsError::Cache(map_schedule(err)))?;
        }
        Outcome::NoData {
            family: no_data_family,
            soa,
        } => {
            cache
                .evict_nodata(name, no_data_family)
                .map_err(DnsError::Cache)?;
            schedules
                .note_nodata(index, no_data_family, soa, receipt, now)
                .map_err(|err| DnsError::Cache(map_schedule(err)))?;
        }
    }
    Ok(())
}

fn map_schedule(err: crate::schedule::ScheduleError) -> CacheError {
    match err {
        crate::schedule::ScheduleError::NameOutOfRange => CacheError::NameOutOfRange,
        crate::schedule::ScheduleError::DeadlineOverflow => CacheError::DeadlineOverflow,
    }
}

fn family_qtype(family: Family) -> u16 {
    match family {
        Family::A => TYPE_A,
        Family::Aaaa => TYPE_AAAA,
    }
}

const HEADER_LEN: usize = 12;

fn write_header(buf: &mut [u8], tid: u16) -> Result<(), DnsError> {
    if buf.len() < HEADER_LEN {
        return Err(DnsError::BufferExhausted);
    }
    buf[0] = (tid >> 8) as u8;
    buf[1] = (tid & 0xff) as u8;
    buf[2] = 0x01;
    buf[3] = 0x00;
    buf[4] = 0x00;
    buf[5] = 0x01;
    buf[6..12].fill(0);
    Ok(())
}

fn write_qname(buf: &mut [u8], mut pos: usize, name: &str) -> Result<usize, DnsError> {
    let bytes = name.as_bytes();
    let mut label_start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'.' {
            let label_len = i - label_start;
            if label_len == 0 || label_len > 63 {
                return Err(DnsError::QueryTooLong);
            }
            if pos + 1 + label_len > buf.len() {
                return Err(DnsError::BufferExhausted);
            }
            buf[pos] = label_len as u8;
            buf[pos + 1..pos + 1 + label_len]
                .copy_from_slice(&bytes[label_start..label_start + label_len]);
            pos += 1 + label_len;
            label_start = i + 1;
        }
    }
    let tail = bytes.len() - label_start;
    if tail > 0 {
        if tail > 63 {
            return Err(DnsError::QueryTooLong);
        }
        if pos + 1 + tail > buf.len() {
            return Err(DnsError::BufferExhausted);
        }
        buf[pos] = tail as u8;
        buf[pos + 1..pos + 1 + tail].copy_from_slice(&bytes[label_start..]);
        pos += 1 + tail;
    }
    if pos >= buf.len() {
        return Err(DnsError::BufferExhausted);
    }
    buf[pos] = 0;
    Ok(pos + 1)
}

/// Builds a single-question IN DNS query for the exact allowlisted `name` and
/// `family` with transaction id `tid`, returning the message length written
/// into `buf`.
///
/// # Errors
///
/// Returns `QueryTooLong` or `BufferExhausted` when the name cannot be encoded
/// into `buf`.
pub fn build_query(
    fqdn: &Fqdn,
    family: Family,
    tid: u16,
    buf: &mut [u8],
) -> Result<usize, DnsError> {
    write_header(buf, tid)?;
    let mut pos = HEADER_LEN;
    pos = write_qname(buf, pos, fqdn.as_str())?;
    if pos + 4 > buf.len() {
        return Err(DnsError::BufferExhausted);
    }
    buf[pos] = (family_qtype(family) >> 8) as u8;
    buf[pos + 1] = family_qtype(family) as u8;
    buf[pos + 2] = 0;
    buf[pos + 3] = CLASS_IN as u8;
    Ok(pos + 4)
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Result<u8, DnsError> {
        let byte = self
            .data
            .get(self.pos)
            .copied()
            .ok_or(DnsError::MessageTooLong)?;
        self.pos += 1;
        Ok(byte)
    }

    fn u16(&mut self) -> Result<u16, DnsError> {
        let hi = self.u8()?;
        let lo = self.u8()?;
        Ok(u16::from_be_bytes([hi, lo]))
    }

    fn u32(&mut self) -> Result<u32, DnsError> {
        let hi = self.u16()?;
        let lo = self.u16()?;
        Ok((u32::from(hi) << 16) | u32::from(lo))
    }

    fn skip(&mut self, n: usize) -> Result<(), DnsError> {
        if self.remaining() < n {
            return Err(DnsError::MessageTooLong);
        }
        self.pos += n;
        Ok(())
    }
}

/// Decodes a (possibly compressed) name at `at`, returning the decoded bytes
/// without a trailing root label plus the cursor just past the name. Names
/// follow only backward compression pointers with a bounded visited set.
fn read_name(msg: &[u8], at: usize) -> Result<(DnsName, usize), DnsError> {
    let mut out = DnsName::default();
    let mut cursor = at;
    let mut total = 0usize;
    let mut pointers = 0usize;
    loop {
        let byte = msg.get(cursor).copied().ok_or(DnsError::MessageTooLong)?;
        match byte & 0xc0 {
            0x00 => {
                let len = usize::from(byte);
                if len == 0 {
                    return Ok((out, cursor + 1));
                }
                if len > 63 {
                    return Err(DnsError::LabelTooLong { len });
                }
                total += len + 1;
                if total > MAX_NAME_BYTES {
                    return Err(DnsError::NameTooLong);
                }
                let start = cursor + 1;
                let end = start + len;
                if end >= msg.len() {
                    return Err(DnsError::MessageTooLong);
                }
                if !out.is_empty() {
                    out.push(b'.')?;
                }
                for &b in &msg[start..end] {
                    out.push(b.to_ascii_lowercase())?;
                }
                cursor = end;
            }
            0xc0 => {
                let hi = usize::from(byte & 0x3f);
                let lo = usize::from(
                    msg.get(cursor + 1)
                        .copied()
                        .ok_or(DnsError::MessageTooLong)?,
                );
                let target = (hi << 8) | lo;
                if target >= cursor {
                    return Err(DnsError::PointerNotBackward);
                }
                cursor = target;
                pointers += 1;
                if pointers > 8 {
                    return Err(DnsError::PointerCycle);
                }
            }
            _ => return Err(DnsError::ReservedLabelType { offset: cursor }),
        }
    }
}

fn read_rr(msg: &[u8], reader: &mut Reader) -> Result<(DnsName, u16, u16, u32), DnsError> {
    let start = reader.pos;
    let (owner, end) = read_name(msg, start)?;
    reader.pos = end;
    let ty = reader.u16()?;
    let class = reader.u16()?;
    let ttl = reader.u32()?;
    Ok((owner, ty, class, ttl))
}

#[allow(clippy::large_enum_variant)]
enum Rdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(DnsName),
    Soa { minimum: u32 },
}

fn parse_rdata(msg: &[u8], rd_start: usize, rdlen: usize, ty: u16) -> Result<Rdata, DnsError> {
    let end = rd_start
        .checked_add(rdlen)
        .ok_or(DnsError::MessageTooLong)?;
    if end > msg.len() {
        return Err(DnsError::MessageTooLong);
    }
    match ty {
        TYPE_A => {
            if rdlen != 4 {
                return Err(DnsError::BadRdataLength {
                    ty,
                    got: rdlen,
                    expected: 4,
                });
            }
            Ok(Rdata::A(Ipv4Addr::new(
                msg[rd_start],
                msg[rd_start + 1],
                msg[rd_start + 2],
                msg[rd_start + 3],
            )))
        }
        TYPE_AAAA => {
            if rdlen != 16 {
                return Err(DnsError::BadRdataLength {
                    ty,
                    got: rdlen,
                    expected: 16,
                });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&msg[rd_start..rd_start + 16]);
            Ok(Rdata::Aaaa(Ipv6Addr::from(octets)))
        }
        TYPE_CNAME => {
            let (target, used) = read_name(msg, rd_start)?;
            if used != end {
                return Err(DnsError::BadRdataLength {
                    ty,
                    got: rdlen,
                    expected: used - rd_start,
                });
            }
            Ok(Rdata::Cname(target))
        }
        TYPE_SOA => {
            let (_, used) = read_name(msg, rd_start)?;
            let (_, used2) = read_name(msg, used)?;
            if rdlen != (used2 - rd_start) + 20 || used2 + 20 != end {
                return Err(DnsError::MalformedSoa);
            }
            let mut r = Reader::new(&msg[used2..end]);
            r.skip(16)?;
            let minimum = r.u32()?;
            Ok(Rdata::Soa { minimum })
        }
        TYPE_DNAME => Err(DnsError::DnameUnsupported),
        _ => Err(DnsError::BadType { got: ty }),
    }
}

#[derive(Clone, Copy, Debug)]
struct Owner {
    name: DnsName,
    cname: Option<(DnsName, u32)>,
    addrs: [(NumericAddr, u32); MAX_ADDRESSES],
    addr_len: u8,
    has_any_addr: bool,
}

impl Owner {
    fn empty() -> Owner {
        Owner {
            name: DnsName::default(),
            cname: None,
            addrs: [(NumericAddr::V4(Ipv4Addr::UNSPECIFIED), 0); MAX_ADDRESSES],
            addr_len: 0,
            has_any_addr: false,
        }
    }
}

/// Reusable fixed-capacity response-parse workspace, owned by the caller (a
/// boot slot) and reused across responses so the parse path performs no heap
/// allocation or deallocation after boot.
#[derive(Clone, Debug)]
pub struct ResponseWorkspace {
    owners: [Owner; MAX_TOTAL_RR],
    owner_len: usize,
    soa: Option<(DnsName, u32, u32)>,
}

impl Default for ResponseWorkspace {
    fn default() -> Self {
        ResponseWorkspace {
            owners: [Owner::empty(); MAX_TOTAL_RR],
            owner_len: 0,
            soa: None,
        }
    }
}

fn ensure_owner(ws: &mut ResponseWorkspace, name: &DnsName) -> Result<usize, DnsError> {
    for (index, owner) in ws.owners[..ws.owner_len].iter().enumerate() {
        if owner.name.eq_bytes(name.as_slice()) {
            return Ok(index);
        }
    }
    if ws.owner_len >= MAX_TOTAL_RR {
        return Err(DnsError::ExcessiveRecords {
            total: ws.owner_len + 1,
            limit: MAX_TOTAL_RR,
        });
    }
    ws.owners[ws.owner_len] = Owner {
        name: *name,
        cname: None,
        addrs: [(NumericAddr::V4(Ipv4Addr::UNSPECIFIED), 0); MAX_ADDRESSES],
        addr_len: 0,
        has_any_addr: false,
    };
    ws.owner_len += 1;
    Ok(ws.owner_len - 1)
}

/// Parses and validates a DNS response against the exact outstanding query,
/// returning a classified outcome. The caller supplies a reusable
/// [`ResponseWorkspace`]; the parse path performs no heap allocation or
/// deallocation after boot. Unknown-but-well-formed records are ignored; only
/// validated outcomes classify. DNAME anywhere is rejected.
///
/// # Errors
///
/// Returns every refusal in `DnsError` without any cache mutation.
pub fn parse_response(
    ws: &mut ResponseWorkspace,
    fqdn: &Fqdn,
    family: Family,
    tid: u16,
    msg: &[u8],
) -> Result<Outcome, DnsError> {
    if msg.len() > DNS_MSG_LIMIT {
        return Err(DnsError::MessageTooLong);
    }
    ws.owner_len = 0;
    ws.soa = None;
    let mut reader = Reader::new(msg);
    let got_tid = reader.u16()?;
    if got_tid != tid {
        return Err(DnsError::BadTid {
            expected: tid,
            got: got_tid,
        });
    }
    let flags = reader.u16()?;
    let qr = (flags >> 15) & 1;
    let opcode = ((flags >> 11) & 0x0f) as u8;
    let tc = (flags >> 9) & 1;
    let rcode = (flags & 0x0f) as u8;
    if qr != 1 {
        return Err(DnsError::NotResponse);
    }
    if opcode != 0 {
        return Err(DnsError::BadOpcode { got: opcode });
    }
    if tc == 1 {
        return Err(DnsError::Truncated);
    }
    let qdcount = usize::from(reader.u16()?);
    let ancount = usize::from(reader.u16()?);
    let nscount = usize::from(reader.u16()?);
    let arcount = usize::from(reader.u16()?);
    if qdcount != 1 {
        return Err(DnsError::QuestionCount { got: qdcount });
    }
    let total_rr = ancount + nscount + arcount;
    if total_rr > MAX_TOTAL_RR {
        return Err(DnsError::ExcessiveRecords {
            total: total_rr,
            limit: MAX_TOTAL_RR,
        });
    }
    let (qname, after_q) = read_name(msg, reader.pos)?;
    reader.pos = after_q;
    let qtype = reader.u16()?;
    let qclass = reader.u16()?;
    if qname.as_slice() != fqdn.as_str().as_bytes()
        || qtype != family_qtype(family)
        || qclass != CLASS_IN
    {
        return Err(DnsError::QuestionMismatch);
    }

    for _ in 0..ancount {
        let (owner, ty, class, ttl) = read_rr(msg, &mut reader)?;
        let rdlen = usize::from(reader.u16()?);
        let rd_start = reader.pos;
        if class != CLASS_IN {
            return Err(DnsError::BadClass { got: class });
        }
        match ty {
            TYPE_A | TYPE_AAAA | TYPE_CNAME | TYPE_SOA => {
                let rdata = parse_rdata(msg, rd_start, rdlen, ty)?;
                match rdata {
                    Rdata::A(ip) => {
                        if family != Family::A {
                            reader.skip(rdlen)?;
                            continue;
                        }
                        let idx = ensure_owner(ws, &owner)?;
                        if ws.owners[idx].cname.is_some() {
                            return Err(DnsError::CnameCoexist);
                        }
                        ws.owners[idx].has_any_addr = true;
                        let slot = ws.owners[idx].addr_len as usize;
                        if slot >= MAX_ADDRESSES {
                            return Err(DnsError::CandidatesExceeded {
                                limit: MAX_ADDRESSES,
                            });
                        }
                        ws.owners[idx].addrs[slot] = (NumericAddr::V4(ip), ttl);
                        ws.owners[idx].addr_len += 1;
                    }
                    Rdata::Aaaa(ip) => {
                        if family != Family::Aaaa {
                            reader.skip(rdlen)?;
                            continue;
                        }
                        let idx = ensure_owner(ws, &owner)?;
                        if ws.owners[idx].cname.is_some() {
                            return Err(DnsError::CnameCoexist);
                        }
                        ws.owners[idx].has_any_addr = true;
                        let slot = ws.owners[idx].addr_len as usize;
                        if slot >= MAX_ADDRESSES {
                            return Err(DnsError::CandidatesExceeded {
                                limit: MAX_ADDRESSES,
                            });
                        }
                        ws.owners[idx].addrs[slot] = (NumericAddr::V6(ip), ttl);
                        ws.owners[idx].addr_len += 1;
                    }
                    Rdata::Cname(target) => {
                        let idx = ensure_owner(ws, &owner)?;
                        if let Some((existing, _)) = &ws.owners[idx].cname {
                            if !existing.eq_bytes(target.as_slice()) {
                                return Err(DnsError::ConflictingCname);
                            }
                        } else if ws.owners[idx].has_any_addr || ws.owners[idx].addr_len != 0 {
                            return Err(DnsError::CnameCoexist);
                        } else {
                            ws.owners[idx].cname = Some((target, ttl));
                        }
                    }
                    Rdata::Soa { .. } => {}
                }
            }
            TYPE_DNAME => return Err(DnsError::DnameUnsupported),
            _ => {}
        }
        reader.skip(rdlen)?;
    }

    for _ in 0..nscount {
        let (owner, ty, class, ttl) = read_rr(msg, &mut reader)?;
        let rdlen = usize::from(reader.u16()?);
        let rd_start = reader.pos;
        if class != CLASS_IN {
            return Err(DnsError::BadClass { got: class });
        }
        if ty == TYPE_DNAME {
            return Err(DnsError::DnameUnsupported);
        }
        if ty == TYPE_SOA
            && let Rdata::Soa { minimum } = parse_rdata(msg, rd_start, rdlen, ty)?
        {
            if ws.soa.is_some() {
                return Err(DnsError::SoaCount { got: 2 });
            }
            ws.soa = Some((owner, ttl, minimum));
        }
        reader.skip(rdlen)?;
    }

    for _ in 0..arcount {
        let (_, ty, _, _) = read_rr(msg, &mut reader)?;
        let rdlen = usize::from(reader.u16()?);
        if ty == TYPE_DNAME {
            return Err(DnsError::DnameUnsupported);
        }
        reader.skip(rdlen)?;
    }

    if reader.remaining() > 0 {
        return Err(DnsError::TrailingBytes);
    }

    let root = DnsName::from_exact(fqdn.as_str().as_bytes());
    let (chain, chain_ttl) = root_chain(&root, ws)?;
    let terminal = chain.terminal.as_slice();

    let soa = classify_soa(terminal, ws.soa.as_ref())?;

    let mut bindings = BindingList::default();
    if let Some(owner) = ws.owners[..ws.owner_len]
        .iter()
        .find(|o| o.name.eq_bytes(terminal))
    {
        for (addr, _) in &owner.addrs[..usize::from(owner.addr_len)] {
            bindings.push(*addr)?;
        }
    }

    match rcode {
        RCODE_NOERROR => {
            if !bindings.is_empty() {
                let mut earliest = chain_ttl;
                for (_, addr_ttl) in ws.owners[..ws.owner_len]
                    .iter()
                    .filter(|o| o.name.eq_bytes(terminal))
                    .flat_map(|o| o.addrs[..usize::from(o.addr_len)].iter())
                {
                    earliest = earliest.min(u64::from(*addr_ttl));
                }
                if earliest == u64::MAX {
                    earliest = 1;
                }
                return Ok(Outcome::Positive {
                    family,
                    bindings,
                    ttl: earliest,
                });
            }
            match soa {
                Some(soa) => Ok(Outcome::NoData {
                    family,
                    soa: Some(soa),
                }),
                None => Err(DnsError::EmptyNoerrorWithoutSoa),
            }
        }
        RCODE_NXDOMAIN => {
            let terminal_data = ws.owners[..ws.owner_len]
                .iter()
                .find(|o| o.name.eq_bytes(terminal))
                .map(|o| o.has_any_addr)
                .unwrap_or(false);
            if terminal_data {
                return Err(DnsError::TerminalWithoutData);
            }
            Ok(Outcome::NxDomain { soa })
        }
        code => Err(DnsError::BadRcode { code }),
    }
}

struct Chain {
    terminal: DnsName,
}

fn root_chain(root: &DnsName, ws: &ResponseWorkspace) -> Result<(Chain, u64), DnsError> {
    let mut current = *root;
    let mut links = 0usize;
    let mut cname_ttl = u64::MAX;
    let mut visited = [DnsName::default(); MAX_CNAME_LINKS + 2];
    let mut visited_len = 0usize;
    loop {
        if visited[..visited_len]
            .iter()
            .any(|v| v.eq_bytes(current.as_slice()))
        {
            return Err(DnsError::CnameLoop);
        }
        visited[visited_len] = current;
        visited_len += 1;
        let entry = ws.owners[..ws.owner_len]
            .iter()
            .find(|o| o.name.eq_bytes(current.as_slice()));
        let Some(entry) = entry else {
            break;
        };
        let Some((target, ttl)) = &entry.cname else {
            break;
        };
        if target.eq_bytes(root.as_slice()) {
            return Err(DnsError::CnameLoop);
        }
        cname_ttl = cname_ttl.min(u64::from(*ttl));
        links += 1;
        if links > MAX_CNAME_LINKS {
            return Err(DnsError::CnameTooDeep { links });
        }
        let next = ws.owners[..ws.owner_len]
            .iter()
            .find(|o| o.name.eq_bytes(target.as_slice()));
        let Some(next) = next else {
            return Ok((Chain { terminal: *target }, cname_ttl));
        };
        current = next.name;
    }
    Ok((Chain { terminal: current }, cname_ttl))
}

fn classify_soa(
    terminal: &[u8],
    soa: Option<&(DnsName, u32, u32)>,
) -> Result<Option<Soa>, DnsError> {
    match soa {
        None => Ok(None),
        Some((owner, ttl, minimum)) => {
            if !soa_covers(terminal, owner.as_slice()) {
                return Err(DnsError::NonCoveringSoa);
            }
            Ok(Some(Soa::new(u64::from(*ttl), u64::from(*minimum))))
        }
    }
}

fn soa_covers(name: &[u8], soa_owner: &[u8]) -> bool {
    if name == soa_owner {
        return true;
    }
    if soa_owner.len() >= name.len() {
        return false;
    }
    let boundary = name.len() - soa_owner.len() - 1;
    let suffix = &name[name.len() - soa_owner.len()..];
    suffix == soa_owner && name[boundary] == b'.'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::Cache;
    use crate::config::{Config, parse_config_document};
    use crate::schedule::Schedules;

    fn config() -> Config {
        parse_config_document(
            "allowlist = [\"sub.example.org\", \"other.test\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 1\n",
        )
        .expect("valid config")
    }

    fn fqdn(name: &str) -> Fqdn {
        config()
            .allowlist()
            .iter()
            .find(|f| f.as_str() == name)
            .expect("allowlisted")
            .clone()
    }

    fn header(tid: u16, qr_flag: bool, rcode: u8, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[0] = (tid >> 8) as u8;
        m[1] = tid as u8;
        let mut flags = rcode as u16;
        if qr_flag {
            flags |= 0x8000;
        }
        m[2] = (flags >> 8) as u8;
        m[3] = flags as u8;
        m[4] = (qd >> 8) as u8;
        m[5] = qd as u8;
        m[6] = (an >> 8) as u8;
        m[7] = an as u8;
        m[8] = (ns >> 8) as u8;
        m[9] = ns as u8;
        m[10] = (ar >> 8) as u8;
        m[11] = ar as u8;
        m
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

    fn a_record(owner: &str, octets: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut m = qname_bytes(owner);
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&octets);
        m
    }

    fn cname_record(owner: &str, target: &str, ttl: u32) -> Vec<u8> {
        let mut m = qname_bytes(owner);
        m.extend_from_slice(&5u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&ttl.to_be_bytes());
        let target_bytes = qname_bytes(target);
        m.extend_from_slice(&(target_bytes.len() as u16).to_be_bytes());
        m.extend_from_slice(&target_bytes);
        m
    }

    fn soa_record(owner: &str, ttl: u32, minimum: u32) -> Vec<u8> {
        let mname = qname_bytes("ns1.example.org");
        let rname = qname_bytes("hostmaster.example.org");
        let rdata_len = mname.len() + rname.len() + 20;
        let mut m = qname_bytes(owner);
        m.extend_from_slice(&6u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        m.extend_from_slice(&mname);
        m.extend_from_slice(&rname);
        let mut fields = Vec::new();
        for v in [1u32, 3600, 600, 86400, minimum] {
            fields.extend_from_slice(&v.to_be_bytes());
        }
        m.extend_from_slice(&fields);
        m
    }

    fn direct_a(name: &str, tid: u16, octets: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut m = header(tid, true, 0, 1, 1, 0, 0);
        m.extend_from_slice(&qname_bytes(name));
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&a_record(name, octets, ttl));
        m
    }

    fn parse_response_ws(
        name: &str,
        family: Family,
        tid: u16,
        msg: &[u8],
    ) -> Result<Outcome, DnsError> {
        let mut ws = ResponseWorkspace::default();
        parse_response(&mut ws, &fqdn(name), family, tid, msg)
    }

    #[test]
    fn parses_direct_a_positive() {
        let msg = direct_a("sub.example.org", 0x1234, [93, 184, 216, 34], 120);
        let out = parse_response_ws("sub.example.org", Family::A, 0x1234, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::Positive {
                family: Family::A,
                bindings: BindingList::from_slice(&[NumericAddr::V4(Ipv4Addr::new(
                    93, 184, 216, 34
                ))])
                .expect("bindings"),
                ttl: 120,
            }
        );
    }

    #[test]
    fn rejects_tid_mismatch() {
        let msg = direct_a("sub.example.org", 0x1234, [1, 1, 1, 1], 60);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 0xbeef, &msg),
            Err(DnsError::BadTid {
                expected: 0xbeef,
                got: 0x1234
            })
        );
    }

    #[test]
    fn rejects_question_mismatch() {
        let mut msg = header(7, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("other.test"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("other.test", [1, 2, 3, 4], 60));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 7, &msg),
            Err(DnsError::QuestionMismatch)
        );
    }

    #[test]
    fn cname_chain_positive() {
        let mut msg = header(9, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "edge.test", 200));
        msg.extend_from_slice(&a_record("edge.test", [203, 0, 113, 7], 40));
        let out = parse_response_ws("sub.example.org", Family::A, 9, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]
                );
                assert_eq!(ttl, 40, "earliest supporting TTL across chain");
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn rejects_cname_loop() {
        let mut msg = header(10, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "edge.test", 100));
        msg.extend_from_slice(&cname_record("edge.test", "sub.example.org", 100));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 10, &msg),
            Err(DnsError::CnameLoop)
        );
    }

    #[test]
    fn parses_nxdomain_with_soa() {
        let mut msg = header(11, true, 3, 1, 0, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 11, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::NxDomain {
                soa: Some(Soa::new(300, 60)),
            }
        );
    }

    #[test]
    fn parses_nodata_with_soa() {
        let mut msg = header(12, true, 0, 1, 0, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 12, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::NoData {
                family: Family::A,
                soa: Some(Soa::new(300, 60)),
            }
        );
    }

    #[test]
    fn empty_noerror_without_soa_is_not_nodata() {
        let mut msg = header(13, true, 0, 1, 0, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 13, &msg),
            Err(DnsError::EmptyNoerrorWithoutSoa)
        );
    }

    #[test]
    fn rejects_servfail_rcode() {
        let mut msg = header(14, true, 2, 1, 0, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 14, &msg),
            Err(DnsError::BadRcode { code: 2 })
        );
    }

    #[test]
    fn rejects_non_covering_soa() {
        let mut msg = header(15, true, 0, 1, 0, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&soa_record("other.example.net", 300, 60));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 15, &msg),
            Err(DnsError::NonCoveringSoa)
        );
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut msg = direct_a("sub.example.org", 16, [1, 1, 1, 1], 60);
        msg.push(0);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 16, &msg),
            Err(DnsError::TrailingBytes)
        );
    }

    #[test]
    fn rejects_bad_rdata_length() {
        let mut msg = header(17, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        let mut rec = qname_bytes("sub.example.org");
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.extend_from_slice(&60u32.to_be_bytes());
        rec.extend_from_slice(&3u16.to_be_bytes());
        rec.extend_from_slice(&[1, 2, 3]);
        msg.extend_from_slice(&rec);
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 17, &msg),
            Err(DnsError::BadRdataLength {
                ty: 1,
                got: 3,
                expected: 4
            })
        );
    }

    #[test]
    fn apply_publishes_positive_to_cache_and_schedule() {
        let mut cache = Cache::new(2).expect("cache");
        let mut schedules = Schedules::new(2).expect("schedules");
        let name = cache.name_index(0).expect("index");
        let generation = cache.entry(name, Family::A).expect("entry").generation();
        let outcome = Outcome::Positive {
            family: Family::A,
            bindings: BindingList::from_slice(&[NumericAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
                .expect("bindings"),
            ttl: 120,
        };
        apply_outcome(
            &mut cache,
            &mut schedules,
            0,
            generation,
            1000,
            1000,
            outcome,
        )
        .expect("apply");
        let entry = cache.entry(name, Family::A).expect("entry");
        assert_eq!(entry.deadlines(), (Some(1120), Some(1120 + 259_200)));
        assert_eq!(entry.state(1100), crate::cache::EntryState::Fresh);
        let due = schedules
            .due_time(0, Family::A)
            .expect("due")
            .expect("some");
        assert_eq!(due, 1000 + 120, "normal refresh from receipt");
    }

    #[test]
    fn apply_nxdomain_evicts_both_families() {
        let mut cache = Cache::new(2).expect("cache");
        let mut schedules = Schedules::new(2).expect("schedules");
        let name = cache.name_index(0).expect("index");
        let gen_a = cache.entry(name, Family::A).expect("entry").generation();
        let gen_aaaa = cache.entry(name, Family::Aaaa).expect("entry").generation();
        let outcome = Outcome::NxDomain { soa: None };
        apply_outcome(&mut cache, &mut schedules, 0, gen_a, 1000, 1000, outcome).expect("apply");
        assert!(cache.entry(name, Family::A).expect("entry").is_empty());
        assert!(cache.entry(name, Family::Aaaa).expect("entry").is_empty());
        assert_ne!(
            cache.entry(name, Family::Aaaa).expect("entry").generation(),
            gen_aaaa
        );
    }

    #[test]
    fn nodata_through_cname_target_without_owner_is_negative() {
        let mut msg = header(20, true, 0, 1, 1, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "edge.example.org", 200));
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 20, &msg).expect("parse");
        assert_eq!(
            out,
            Outcome::NoData {
                family: Family::A,
                soa: Some(Soa::new(300, 60)),
            }
        );
    }

    #[test]
    fn rejects_over_record_count_bound() {
        let mut msg = header(21, true, 0, 1, (MAX_TOTAL_RR + 1) as u16, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 21, &msg),
            Err(DnsError::ExcessiveRecords {
                total: MAX_TOTAL_RR + 1,
                limit: MAX_TOTAL_RR,
            })
        );
    }

    #[test]
    fn owners_match_case_insensitively() {
        let mut msg = header(22, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("Sub.Example.Org", "Edge.Test", 200));
        msg.extend_from_slice(&a_record("edge.test", [203, 0, 113, 7], 40));
        let out = parse_response_ws("sub.example.org", Family::A, 22, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]
                );
                assert_eq!(ttl, 40);
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn unknown_answer_type_is_skipped_and_does_not_break_parse() {
        let mut msg = header(23, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        let mut unknown = qname_bytes("sub.example.org");
        unknown.extend_from_slice(&99u16.to_be_bytes());
        unknown.extend_from_slice(&1u16.to_be_bytes());
        unknown.extend_from_slice(&60u32.to_be_bytes());
        unknown.extend_from_slice(&4u16.to_be_bytes());
        unknown.extend_from_slice(&[10, 11, 12, 13]);
        msg.extend_from_slice(&unknown);
        msg.extend_from_slice(&a_record("sub.example.org", [93, 184, 216, 34], 120));
        let out = parse_response_ws("sub.example.org", Family::A, 23, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                );
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn rejects_coexist_cname_then_address() {
        let mut msg = header(24, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&cname_record("sub.example.org", "edge.test", 200));
        msg.extend_from_slice(&a_record("sub.example.org", [1, 2, 3, 4], 60));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 24, &msg),
            Err(DnsError::CnameCoexist)
        );
    }

    #[test]
    fn rejects_coexist_address_then_cname() {
        let mut msg = header(25, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [1, 2, 3, 4], 60));
        msg.extend_from_slice(&cname_record("sub.example.org", "edge.test", 200));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 25, &msg),
            Err(DnsError::CnameCoexist)
        );
    }

    #[test]
    fn nodata_requires_authority_not_answer_soa() {
        let mut msg = header(26, true, 0, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 26, &msg),
            Err(DnsError::EmptyNoerrorWithoutSoa)
        );
    }

    #[test]
    fn nxdomain_ignores_answer_soa_for_scheduling() {
        let mut msg = header(27, true, 3, 1, 1, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 27, &msg).expect("parse");
        assert_eq!(out, Outcome::NxDomain { soa: None });
    }

    #[test]
    fn positive_ignores_unrelated_answer_soa() {
        let mut msg = header(28, true, 0, 1, 2, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&a_record("sub.example.org", [93, 184, 216, 34], 120));
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        let out = parse_response_ws("sub.example.org", Family::A, 28, &msg).expect("parse");
        match out {
            Outcome::Positive { bindings, ttl, .. } => {
                assert_eq!(
                    bindings.as_slice(),
                    &[NumericAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                );
                assert_eq!(ttl, 120);
            }
            other => panic!("expected positive, got {other:?}"),
        }
    }

    #[test]
    fn excessive_candidates_rejected() {
        let mut msg = header(29, true, 0, 1, 17, 0, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        for octet in 1..=17u8 {
            msg.extend_from_slice(&a_record("sub.example.org", [10, 0, 0, octet], 60));
        }
        assert_eq!(
            parse_response_ws("sub.example.org", Family::A, 29, &msg),
            Err(DnsError::CandidatesExceeded {
                limit: MAX_ADDRESSES
            })
        );
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn dns_parse_zero_heap_after_positive_control() {
        use crate::alloc::{self, Phase};
        let msg = direct_a("sub.example.org", 30, [93, 184, 216, 34], 120);
        let fq = fqdn("sub.example.org");
        let (_, control) = alloc::run_phase(Phase::BackgroundRefresh, || {
            let bytes = Box::new([0u8; 64]);
            std::hint::black_box(bytes);
        });
        assert!(
            control.allocs > 0 && control.deallocs > 0,
            "counter must attribute a local alloc/dealloc: {control:?}"
        );

        eprintln!(
            "size_of Owner={} ResponseWorkspace={}",
            size_of::<Owner>(),
            size_of::<ResponseWorkspace>()
        );
        let (out, counts) = alloc::run_phase(Phase::BackgroundRefresh, || {
            let mut ws = ResponseWorkspace::default();
            parse_response(&mut ws, &fq, Family::A, 30, &msg).expect("parse")
        });
        assert!(
            counts.all_zero(),
            "positive parse must be allocation-free: {counts:?}"
        );
        assert!(matches!(out, Outcome::Positive { .. }));
    }

    #[cfg(feature = "alloc-witness")]
    #[test]
    fn dns_parse_zero_heap_after_negative_control() {
        use crate::alloc::{self, Phase};
        let mut msg = header(31, true, 3, 1, 0, 1, 0);
        msg.extend_from_slice(&qname_bytes("sub.example.org"));
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&soa_record("example.org", 300, 60));
        let fq = fqdn("sub.example.org");
        let (_, control) = alloc::run_phase(Phase::BackgroundRefresh, || {
            let bytes = Box::new([0u8; 64]);
            std::hint::black_box(bytes);
        });
        assert!(
            control.allocs > 0 && control.deallocs > 0,
            "counter must attribute a local alloc/dealloc: {control:?}"
        );

        let (out, counts) = alloc::run_phase(Phase::BackgroundRefresh, || {
            let mut ws = ResponseWorkspace::default();
            parse_response(&mut ws, &fq, Family::A, 31, &msg).expect("parse")
        });
        assert!(
            counts.all_zero(),
            "negative parse must be allocation-free: {counts:?}"
        );
        assert!(matches!(out, Outcome::NxDomain { .. }));
    }
}
