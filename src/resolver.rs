use std::fmt;
use std::fs::File;
use std::io::{self, Read};

pub const RESOLVER_PORT: u16 = 53;

const KEYWORD_LIMIT: usize = 32;

const ADDR_TOKEN_LIMIT: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nameserver {
    addr: std::net::IpAddr,
}

impl Nameserver {
    pub fn addr(&self) -> std::net::IpAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        RESOLVER_PORT
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResolverError {
    Unreadable { path: String, source: String },
    BareNameserver,
    MalformedDirective { detail: String },
    InvalidAddress { value: String },
    MissingNameserver,
    NonUnicastAddress { value: String },
    ZonedAddress { value: String },
}

impl ResolverError {
    pub fn exit_status(&self) -> i32 {
        78
    }
}

impl fmt::Display for ResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolverError::Unreadable { path, source } => {
                write!(f, "resolver config unreadable: {}: {}", path, source)
            }
            ResolverError::BareNameserver => {
                write!(f, "resolver 'nameserver' directive has no address")
            }
            ResolverError::MalformedDirective { detail } => {
                write!(f, "resolver malformed nameserver declaration: {}", detail)
            }
            ResolverError::InvalidAddress { value } => {
                write!(
                    f,
                    "resolver nameserver {:?} is not a numeric IP address",
                    value
                )
            }
            ResolverError::MissingNameserver => {
                write!(f, "resolver config has no nameserver entry")
            }
            ResolverError::NonUnicastAddress { value } => {
                write!(
                    f,
                    "resolver nameserver {:?} is not unicast (multicast/broadcast/unspecified rejected)",
                    value
                )
            }
            ResolverError::ZonedAddress { value } => {
                write!(
                    f,
                    "resolver nameserver {:?} carries a zone identifier (not allowed)",
                    value
                )
            }
        }
    }
}

pub fn read_resolver_config_file(path: &str) -> Result<Nameserver, ResolverError> {
    let file = File::open(path).map_err(|source| ResolverError::Unreadable {
        path: path.to_owned(),
        source: source.to_string(),
    })?;
    parse_streaming(file, Some(path.to_owned()))
}

pub fn parse_resolver_config(text: &str) -> Result<Nameserver, ResolverError> {
    parse_streaming(text.as_bytes(), None)
}

fn parse_streaming<R: Read>(
    reader: R,
    source_path: Option<String>,
) -> Result<Nameserver, ResolverError> {
    let mut sc = Scanner::new(reader, source_path);

    loop {
        loop {
            skip_inline_ws(&mut sc)?;
            match sc.peek()? {
                None => return Err(ResolverError::MissingNameserver),
                Some(b'\n') => {
                    sc.next()?;
                }
                Some(b'#') => {
                    sc.skip_to_eol()?;
                }
                _ => break,
            }
        }

        let mut kw = [0u8; KEYWORD_LIMIT];
        let mut kw_len = 0usize;
        let mut overlong = false;
        loop {
            match sc.peek()? {
                None | Some(b' ' | b'\t' | b'\r' | b'\n' | b'#') => break,
                Some(_) => {
                    let b = sc.next()?.expect("peeked byte");
                    if kw_len < KEYWORD_LIMIT {
                        kw[kw_len] = b;
                        kw_len += 1;
                    } else {
                        overlong = true;
                    }
                }
            }
        }
        if overlong {
            sc.skip_to_eol()?;
            continue;
        }

        if kw[..kw_len] == *b"nameserver" {
            skip_inline_ws(&mut sc)?;
            let mut tok = [0u8; ADDR_TOKEN_LIMIT];
            let mut tok_len = 0usize;
            let mut overlong = false;
            loop {
                match sc.peek()? {
                    None | Some(b' ' | b'\t' | b'\r' | b'\n' | b'#') => break,
                    Some(_) => {
                        let b = sc.next()?.expect("peeked byte");
                        if !overlong {
                            if tok_len >= ADDR_TOKEN_LIMIT {
                                overlong = true;
                            } else {
                                tok[tok_len] = b;
                                tok_len += 1;
                            }
                        }
                    }
                }
            }
            if tok_len == 0 {
                return Err(ResolverError::BareNameserver);
            }
            if overlong {
                return Err(ResolverError::InvalidAddress {
                    value: String::from_utf8_lossy(&tok[..tok_len]).into_owned(),
                });
            }
            let text = match std::str::from_utf8(&tok[..tok_len]) {
                Ok(text) => text,
                Err(_) => {
                    return Err(ResolverError::InvalidAddress {
                        value: format!("<non-utf8 {} bytes>", tok_len),
                    });
                }
            };
            let ns = select(text)?;
            skip_inline_ws(&mut sc)?;
            match sc.peek()? {
                None | Some(b'\n') | Some(b'#') => return Ok(ns),
                _ => {
                    return Err(ResolverError::MalformedDirective {
                        detail: "more than one address token on the nameserver line".into(),
                    });
                }
            }
        }

        sc.skip_to_eol()?;
    }
}

fn skip_inline_ws<R: Read>(sc: &mut Scanner<R>) -> Result<(), ResolverError> {
    loop {
        match sc.peek()? {
            Some(b' ' | b'\t' | b'\r') => {
                sc.next()?;
            }
            _ => return Ok(()),
        }
    }
}

fn select(token: &str) -> Result<Nameserver, ResolverError> {
    if token.is_empty() {
        return Err(ResolverError::InvalidAddress { value: "".into() });
    }
    if token.contains(['%', '@']) {
        return Err(ResolverError::ZonedAddress {
            value: token.to_owned(),
        });
    }
    let addr: std::net::IpAddr = token.parse().map_err(|_| ResolverError::InvalidAddress {
        value: token.to_owned(),
    })?;
    if !is_unicast(addr) {
        return Err(ResolverError::NonUnicastAddress {
            value: token.to_owned(),
        });
    }
    Ok(Nameserver { addr })
}

fn is_unicast(addr: std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(ip) => {
            !ip.is_multicast() && !ip.is_broadcast() && !ip.is_unspecified()
        }
        std::net::IpAddr::V6(ip) => !ip.is_multicast() && !ip.is_unspecified(),
    }
}

struct Scanner<R: Read> {
    src: R,
    buf: [u8; 512],
    pos: usize,
    len: usize,
    source_path: Option<String>,
}

impl<R: Read> Scanner<R> {
    fn new(src: R, source_path: Option<String>) -> Self {
        Scanner {
            src,
            buf: [0u8; 512],
            pos: 0,
            len: 0,
            source_path,
        }
    }

    fn unreadable(&self, source: io::Error) -> ResolverError {
        ResolverError::Unreadable {
            path: self
                .source_path
                .clone()
                .unwrap_or_else(|| "<stream>".to_owned()),
            source: source.to_string(),
        }
    }

    fn fill(&mut self) -> Result<usize, ResolverError> {
        debug_assert!(self.pos == self.len);
        self.pos = 0;
        self.len = 0;
        let n = loop {
            match self.src.read(&mut self.buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(self.unreadable(e)),
            }
        };
        self.len = n;
        Ok(n)
    }

    fn next(&mut self) -> Result<Option<u8>, ResolverError> {
        if self.pos >= self.len && self.fill()? == 0 {
            return Ok(None);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(Some(b))
    }

    fn peek(&mut self) -> Result<Option<u8>, ResolverError> {
        if self.pos >= self.len && self.fill()? == 0 {
            return Ok(None);
        }
        Ok(Some(self.buf[self.pos]))
    }

    fn skip_to_eol(&mut self) -> Result<(), ResolverError> {
        loop {
            match self.next()? {
                None | Some(b'\n') => return Ok(()),
                Some(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    struct InterruptedOnce {
        data: &'static [u8],
        interrupted: bool,
    }

    impl Read for InterruptedOnce {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                Err(io::Error::from(ErrorKind::Interrupted))
            } else {
                let n = self.data.len().min(buf.len());
                buf[..n].copy_from_slice(&self.data[..n]);
                self.data = &self.data[n..];
                Ok(n)
            }
        }
    }

    #[test]
    fn interrupted_read_is_retried_not_unreadable() {
        let reader = InterruptedOnce {
            data: b"nameserver 1.1.1.1\n",
            interrupted: false,
        };
        let ns = parse_streaming(reader, None).expect("interrupted read must be retried");
        assert_eq!(ns.addr().to_string(), "1.1.1.1");
    }
}
