use std::fmt;

use crate::config::{Allowlist, FixedHostname};

/// Maximum CONNECT request-head size, including headers and the terminating
/// CRLF sequence. The bound applies to the head only, never to tunnel bytes
/// that may arrive in the same read as the delimiter.
pub const CONNECT_LIMIT: usize = 8 * 1024;

/// The only accepted destination port.
pub const DEST_PORT: u16 = 443;

const END_OF_HEAD: &[u8] = b"\r\n\r\n";
const HTTP_11: &[u8] = b"HTTP/1.1";
const HTTP_10: &[u8] = b"HTTP/1.0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectRequest {
    hostname: FixedHostname,
}

impl ConnectRequest {
    /// The normalized lowercase hostname (no trailing dot, no port).
    pub fn hostname(&self) -> &str {
        self.hostname.as_str()
    }

    /// The fixed-capacity validated hostname type, for gate validation that
    /// compares an SNI against the approved CONNECT host without allocation.
    pub fn fixed_hostname(&self) -> &FixedHostname {
        &self.hostname
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectError {
    TooLong,
    NotHttp,
    MalformedRequestLine { detail: &'static str },
    BareLineFeed,
    ObsFold,
    InvalidHostname { detail: &'static str },
    WrongPort { got: u16 },
    TransferEncoding,
    NonzeroContentLength { got: u64 },
    DuplicateContentLength,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectError::TooLong => write!(f, "CONNECT request-head exceeds 8 KiB"),
            ConnectError::NotHttp => write!(f, "CONNECT request line is not exactly three tokens"),
            ConnectError::MalformedRequestLine { detail } => {
                write!(f, "CONNECT request line malformed: {detail}")
            }
            ConnectError::BareLineFeed => write!(f, "CONNECT request contains a bare line feed"),
            ConnectError::ObsFold => write!(f, "CONNECT request contains obsolete line folding"),
            ConnectError::InvalidHostname { detail } => {
                write!(f, "CONNECT hostname invalid: {detail}")
            }
            ConnectError::WrongPort { got } => {
                write!(f, "CONNECT port {got} denied; only 443 allowed")
            }
            ConnectError::TransferEncoding => write!(
                f,
                "CONNECT Transfer-Encoding is rejected for a tunnel setup"
            ),
            ConnectError::NonzeroContentLength { got } => {
                write!(f, "CONNECT Content-Length {got} rejected; only 0")
            }
            ConnectError::DuplicateContentLength => write!(f, "CONNECT duplicate Content-Length"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Feed {
    /// The request head is not yet delimited; supply more bytes.
    Incomplete,
    /// The request head is delimited. `head_len` is the number of bytes of
    /// the byte stream the head consumed, including the CRLFCRLF delimiter.
    /// The parsed request or first policy violation is available via
    /// [`ConnectParser::result`]. Bytes beyond `head_len` (for example an
    /// early ClientHello) belong to the tunnel gate and must not be forwarded
    /// before the gate passes.
    Complete { head_len: usize },
}

/// Incremental CONNECT request-head parser with a fixed 8 KiB storage. Parsing
/// is independent of TCP read boundaries and of bytes coalesced after the
/// delimiter: the first CRLFCRLF sequence closes the head, the parser retains
/// only head bytes, and a ClientHello arriving in the same read is left to the
/// caller via `head_len`.
#[derive(Clone, Debug)]
pub struct ConnectParser {
    head: [u8; CONNECT_LIMIT],
    head_len: usize,
    result: Option<Result<ConnectRequest, ConnectError>>,
}

impl Default for ConnectParser {
    fn default() -> Self {
        ConnectParser::new()
    }
}

impl ConnectParser {
    pub fn new() -> Self {
        ConnectParser {
            head: [0u8; CONNECT_LIMIT],
            head_len: 0,
            result: None,
        }
    }

    /// The parsed request or first policy violation, present once the head is
    /// delimited.
    pub fn result(&self) -> Option<&Result<ConnectRequest, ConnectError>> {
        self.result.as_ref()
    }

    /// Feeds bytes into the parser, returning `Complete` exactly once the head
    /// is delimited. Once `Complete` is returned the parser must not be fed
    /// again for the same connection.
    ///
    /// # Errors
    ///
    /// Returns `TooLong` when the head bytes (excluding any tunnel bytes
    /// coalesced after the delimiter) exceed `CONNECT_LIMIT`.
    pub fn feed(&mut self, data: &[u8]) -> Result<Feed, ConnectError> {
        let room = CONNECT_LIMIT - self.head_len;
        let take = data.len().min(room);
        if take > 0 {
            self.head[self.head_len..self.head_len + take].copy_from_slice(&data[..take]);
            self.head_len += take;
        }
        let buffered = &self.head[..self.head_len];
        if let Some(delim) = find_end_of_head(buffered) {
            let head = &buffered[..delim];
            self.result = Some(parse_request(head));
            return Ok(Feed::Complete {
                head_len: delim + END_OF_HEAD.len(),
            });
        }
        if take < data.len() {
            return Err(ConnectError::TooLong);
        }
        Ok(Feed::Incomplete)
    }
}

fn find_end_of_head(buf: &[u8]) -> Option<usize> {
    if buf.len() < END_OF_HEAD.len() {
        return None;
    }
    for i in 0..=buf.len() - END_OF_HEAD.len() {
        if &buf[i..i + END_OF_HEAD.len()] == END_OF_HEAD {
            return Some(i);
        }
    }
    None
}

fn parse_request(head: &[u8]) -> Result<ConnectRequest, ConnectError> {
    if bare_line_feed(head).is_some() {
        return Err(ConnectError::BareLineFeed);
    }
    let mut lines = Lines::new(head);
    let request_line = lines.next().ok_or(ConnectError::MalformedRequestLine {
        detail: "empty head",
    })?;
    let request = parse_request_line(request_line)?;
    let mut content_length: Option<u64> = None;
    while let Some(line) = lines.next() {
        if line.is_empty() {
            continue;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            return Err(ConnectError::ObsFold);
        }
        let colon =
            line.iter()
                .position(|&b| b == b':')
                .ok_or(ConnectError::MalformedRequestLine {
                    detail: "header without colon",
                })?;
        let name = &line[..colon];
        if name.is_empty() || !is_tchar_header_name(name) {
            return Err(ConnectError::MalformedRequestLine {
                detail: "header name contains whitespace or non-tchar",
            });
        }
        let value = trim_ascii(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"content-length") {
            let parsed = parse_content_length(value).ok_or(ConnectError::MalformedRequestLine {
                detail: "invalid Content-Length",
            })?;
            match content_length {
                Some(_) => return Err(ConnectError::DuplicateContentLength),
                None => content_length = Some(parsed),
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(ConnectError::TransferEncoding);
        }
    }
    if let Some(len) = content_length.filter(|&len| len != 0) {
        return Err(ConnectError::NonzeroContentLength { got: len });
    }
    Ok(request)
}

/// Returns the index of the first bare line feed, or `None` when every line
/// feed is preceded by a carriage return.
fn bare_line_feed(head: &[u8]) -> Option<usize> {
    (0..head.len()).find(|&i| head[i] == 0x0a && (i == 0 || head[i - 1] != 0x0d))
}

struct Lines<'a> {
    buf: &'a [u8],
    next: usize,
}

impl<'a> Lines<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Lines { buf, next: 0 }
    }

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.next > self.buf.len() {
            return None;
        }
        let rest = &self.buf[self.next..];
        match rest.iter().position(|&b| b == 0x0a) {
            Some(lf) => {
                let line = &rest[..lf - 1];
                self.next += lf + 1;
                Some(line)
            }
            None => {
                let line = rest.strip_suffix(b"\r").unwrap_or(rest);
                self.next = self.buf.len() + 1;
                Some(line)
            }
        }
    }
}

fn parse_request_line(line: &[u8]) -> Result<ConnectRequest, ConnectError> {
    let method_end = line
        .iter()
        .position(|&b| b == b' ')
        .ok_or(ConnectError::NotHttp)?;
    if &line[..method_end] != b"CONNECT" {
        return Err(ConnectError::NotHttp);
    }
    let after_method = method_end + 1;
    let target_end = line[after_method..]
        .iter()
        .position(|&b| b == b' ')
        .map(|p| after_method + p)
        .ok_or(ConnectError::NotHttp)?;
    let version = &line[target_end + 1..];
    if version != HTTP_11 && version != HTTP_10 {
        return Err(ConnectError::NotHttp);
    }
    parse_target(&line[after_method..target_end])
}

fn is_tchar_header_name(name: &[u8]) -> bool {
    name.iter().all(|&b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    })
}

/// Parses a Content-Length value as decimal digits only; signs and other
/// non-digit characters are rejected.
fn parse_content_length(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let mut total: u64 = 0;
    for &b in value {
        let digit = u64::from(b.checked_sub(b'0')?);
        if digit > 9 {
            return None;
        }
        total = total.checked_mul(10)?.checked_add(digit)?;
    }
    Some(total)
}

fn parse_target(target: &[u8]) -> Result<ConnectRequest, ConnectError> {
    let Some(colon) = target.iter().rposition(|&b| b == b':') else {
        return Err(ConnectError::MalformedRequestLine {
            detail: "target lacks a port",
        });
    };
    let host = &target[..colon];
    let port = &target[colon + 1..];
    if port.is_empty() || !port.iter().all(|b| b.is_ascii_digit()) {
        return Err(ConnectError::MalformedRequestLine {
            detail: "port is not numeric",
        });
    }
    let parsed_port: u16 = std::str::from_utf8(port)
        .ok()
        .and_then(|p| p.parse().ok())
        .ok_or(ConnectError::MalformedRequestLine {
            detail: "port is not numeric",
        })?;
    if parsed_port != DEST_PORT {
        return Err(ConnectError::WrongPort { got: parsed_port });
    }
    if host.contains(&b':') && !host.starts_with(b"[") {
        return Err(ConnectError::InvalidHostname {
            detail: "IPv6 literal rejected",
        });
    }
    if host.starts_with(b"[") || host.is_empty() {
        return Err(ConnectError::InvalidHostname {
            detail: "address literal rejected",
        });
    }
    let normalized = FixedHostname::normalize(host).ok_or(ConnectError::InvalidHostname {
        detail: "hostname is not a lowercase ASCII FQDN",
    })?;
    Ok(ConnectRequest {
        hostname: normalized,
    })
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|b| b.is_ascii_whitespace()) {
        value = &value[1..];
    }
    while value.last().is_some_and(|b| b.is_ascii_whitespace()) {
        value = &value[..value.len() - 1];
    }
    value
}

/// Whether the request hostname is a member of the configured allowlist.
pub fn is_allowlisted(request: &ConnectRequest, allowlist: &Allowlist) -> bool {
    allowlist
        .iter()
        .any(|entry| entry.as_str().as_bytes() == request.hostname.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, parse_config_document};

    const HEAD: &str = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";

    fn config() -> Config {
        parse_config_document(
            "allowlist = [\"sub.example.org\"]\nlisten = \"0.0.0.0:8080\"\nstartup_unresolved_allowance = 0\n",
        )
        .expect("valid config")
    }

    fn parse_full(bytes: &[u8]) -> Result<ConnectRequest, ConnectError> {
        let mut parser = ConnectParser::new();
        match parser.feed(bytes).expect("no limit error") {
            Feed::Complete { .. } => parser.result().copied().expect("complete has result"),
            Feed::Incomplete => Err(ConnectError::MalformedRequestLine {
                detail: "incomplete",
            }),
        }
    }

    #[test]
    fn parses_valid_connect_with_content_length_zero() {
        let req = parse_full(HEAD.as_bytes()).expect("valid");
        assert_eq!(req.hostname(), "sub.example.org");
        assert!(is_allowlisted(&req, config().allowlist()));
    }

    #[test]
    fn accepts_uppercase_hostname_and_normalizes() {
        let head = "CONNECT SUB.Example.ORG:443 HTTP/1.1\r\n\r\n";
        let req = parse_full(head.as_bytes()).expect("valid");
        assert_eq!(req.hostname(), "sub.example.org");
    }

    #[test]
    fn coalesced_tunnel_bytes_do_not_block_completion() {
        let mut parser = ConnectParser::new();
        let head = HEAD.as_bytes();
        let mut combined = Vec::new();
        combined.extend_from_slice(head);
        combined.push(0x16);
        match parser.feed(&combined).expect("feed") {
            Feed::Complete { head_len } => {
                let req = parser.result().copied().expect("settled");
                assert_eq!(req.expect("parse").hostname(), "sub.example.org");
                assert_eq!(head_len, head.len(), "consumed must stop at the delimiter");
            }
            Feed::Incomplete => panic!("coalesced ClientHello must not block the CONNECT head"),
        }
    }

    #[test]
    fn fragmented_feed_is_boundary_independent() {
        let mut parser = ConnectParser::new();
        for chunk in HEAD.as_bytes().chunks(5) {
            match parser.feed(chunk).expect("no limit") {
                Feed::Incomplete => {}
                Feed::Complete { .. } => {
                    let req = parser.result().copied().expect("settled");
                    assert_eq!(req.expect("parse").hostname(), "sub.example.org");
                    return;
                }
            }
        }
        panic!("never completed");
    }

    #[test]
    fn rejects_wrong_port() {
        let head = "CONNECT sub.example.org:8443 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::WrongPort { got: 8443 })
        );
    }

    #[test]
    fn rejects_ip_literal() {
        let head = "CONNECT 1.2.3.4:443 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(
            parse_full(head.as_bytes()),
            Err(ConnectError::InvalidHostname { .. })
        ));
    }

    #[test]
    fn rejects_http2_version() {
        let head = "CONNECT sub.example.org:443 HTTP/2.0\r\n\r\n";
        assert_eq!(parse_full(head.as_bytes()), Err(ConnectError::NotHttp));
    }

    #[test]
    fn rejects_bare_http_version_prefix() {
        let head = "CONNECT sub.example.org:443 HTTP/\r\n\r\n";
        assert_eq!(parse_full(head.as_bytes()), Err(ConnectError::NotHttp));
    }

    #[test]
    fn rejects_header_whitespace_before_colon() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length : 0\r\n\r\n";
        assert!(matches!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine { .. })
        ));
    }

    #[test]
    fn rejects_empty_header_name() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\n: x\r\n\r\n";
        assert!(matches!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine { .. })
        ));
    }

    #[test]
    fn rejects_plus_in_content_length() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: +0\r\n\r\n";
        assert!(matches!(
            parse_full(head.as_bytes()),
            Err(ConnectError::MalformedRequestLine { .. })
        ));
    }

    #[test]
    fn rejects_transfer_encoding() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::TransferEncoding)
        );
    }

    #[test]
    fn rejects_nonzero_content_length() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 5\r\n\r\n";
        assert_eq!(
            parse_full(head.as_bytes()),
            Err(ConnectError::NonzeroContentLength { got: 5 })
        );
    }

    #[test]
    fn rejects_bare_lf() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\nContent-Length: 0\n\r\n\r\n";
        assert_eq!(parse_full(head.as_bytes()), Err(ConnectError::BareLineFeed));
    }

    #[test]
    fn rejects_obs_fold() {
        let head = "CONNECT sub.example.org:443 HTTP/1.1\r\n Authorization: x\r\n\r\n";
        assert_eq!(parse_full(head.as_bytes()), Err(ConnectError::ObsFold));
    }

    #[test]
    fn rejects_over_limit() {
        let mut parser = ConnectParser::new();
        let filler = vec![b'a'; CONNECT_LIMIT + 1];
        assert_eq!(parser.feed(&filler), Err(ConnectError::TooLong));
    }

    #[test]
    fn over_limit_applies_to_head_not_trailing() {
        let mut parser = ConnectParser::new();
        let head = HEAD.as_bytes();
        let mut big = Vec::with_capacity(CONNECT_LIMIT + 16);
        big.extend_from_slice(head);
        big.extend_from_slice(&[0x16; CONNECT_LIMIT]);
        match parser.feed(&big).expect("feed") {
            Feed::Complete { .. } => {
                let req = parser.result().copied().expect("settled");
                assert_eq!(req.expect("parse").hostname(), "sub.example.org");
            }
            Feed::Incomplete => panic!("trailing bytes must not count toward the head bound"),
        }
    }

    #[test]
    fn not_allowlisted_host_is_forbidden() {
        let req = parse_full(b"CONNECT evil.example.net:443 HTTP/1.1\r\n\r\n").expect("parse");
        assert!(!is_allowlisted(&req, config().allowlist()));
    }
}
