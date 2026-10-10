use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;

pub const CONFIG_DOC_LIMIT: usize = 4096;
pub const ALLOWLIST_MIN: usize = 1;
pub const ALLOWLIST_MAX: usize = 32;
pub const FQDN_MAX_LEN: usize = 253;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fqdn(String);

impl Fqdn {
    fn parse(input: &str) -> Result<Fqdn, String> {
        let name = normalize_trailing_dot(input)?;
        if name.is_empty() {
            return Err("empty hostname".into());
        }
        if name.len() > FQDN_MAX_LEN {
            return Err("hostname exceeds 253 bytes".into());
        }
        for label in name.split('.') {
            if label.is_empty() {
                return Err("empty label".into());
            }
            if label.len() > 63 {
                return Err("label exceeds 63 bytes".into());
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err("label starts or ends with hyphen".into());
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(format!("label {:?} not lowercase ASCII [a-z0-9-]", label));
            }
        }
        Ok(Fqdn(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn normalize_trailing_dot(name: &str) -> Result<&str, String> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Ok(name);
    }
    if bytes.len() > 1 && bytes[bytes.len() - 1] == b'.' && bytes[bytes.len() - 2] == b'.' {
        return Err("multiple trailing dots".into());
    }
    if bytes[bytes.len() - 1] == b'.' {
        Ok(&name[..name.len() - 1])
    } else {
        Ok(name)
    }
}

/// Fixed-capacity validated hostname (lowercase ASCII FQDN without a trailing
/// dot), used on serving paths and protocol gates to avoid per-request or
/// per-connection allocation. The label rules mirror the config `Fqdn` type;
/// the numeric-shorthand (IP-literal-looking) form is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedHostname {
    bytes: [u8; FQDN_MAX_LEN],
    len: usize,
}

impl FixedHostname {
    /// The normalized lowercase bytes, without a trailing dot.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// The normalized name as a `&str`; always ASCII by construction.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).expect("FixedHostname is ASCII")
    }

    /// Normalizes `input` into a legal lowercase FQDN without a trailing dot,
    /// returning `None` for empty, over-length, non-ASCII, IP-literal-shaped,
    /// or malformed names. A single trailing dot is stripped before the
    /// `FQDN_MAX_LEN` bound is applied, so a 254-byte input consisting of a
    /// valid 253-byte name plus a trailing dot is accepted; any other 254-byte
    /// input is rejected without copying outside the fixed buffer.
    pub fn normalize(input: &[u8]) -> Option<FixedHostname> {
        if input.is_empty() || input.len() > FQDN_MAX_LEN + 1 {
            return None;
        }
        if !input.is_ascii() {
            return None;
        }
        let len = if input[input.len() - 1] == b'.' {
            input.len() - 1
        } else {
            input.len()
        };
        if len == 0 || len > FQDN_MAX_LEN {
            return None;
        }
        let mut out = FixedHostname {
            bytes: [0u8; FQDN_MAX_LEN],
            len,
        };
        for (i, &b) in input[..len].iter().enumerate() {
            out.bytes[i] = b.to_ascii_lowercase();
        }
        let mut label_len = 0usize;
        let mut all_digits_dots = true;
        for i in 0..=out.len {
            let b = if i == out.len { b'.' } else { out.bytes[i] };
            match b {
                b'.' => {
                    if label_len == 0 || label_len > 63 {
                        return None;
                    }
                    let start = i - label_len;
                    if out.bytes[start] == b'-' || out.bytes[i - 1] == b'-' {
                        return None;
                    }
                    for &c in &out.bytes[start..i] {
                        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
                            return None;
                        }
                    }
                    label_len = 0;
                }
                b'0'..=b'9' => {
                    label_len += 1;
                }
                _ => {
                    label_len += 1;
                    all_digits_dots = false;
                }
            }
        }
        if out.bytes[0].is_ascii_digit() && all_digits_dots {
            return None;
        }
        Some(out)
    }
}

#[cfg(test)]
mod fixed_hostname_tests {
    use super::FixedHostname;

    #[test]
    fn normalizes_uppercase_and_trailing_dot() {
        let h = FixedHostname::normalize(b"SUB.Example.ORG.").expect("normalize");
        assert_eq!(h.as_bytes(), b"sub.example.org");
    }

    #[test]
    fn rejects_ip_literal_shape() {
        assert!(FixedHostname::normalize(b"1.2.3.4").is_none());
        assert!(FixedHostname::normalize(b"93.184.216.34").is_none());
    }

    #[test]
    fn rejects_malformed_labels() {
        assert!(FixedHostname::normalize(b"").is_none());
        assert!(FixedHostname::normalize(b"-bad.example.org").is_none());
        assert!(FixedHostname::normalize(b"bad-.example.org").is_none());
        assert!(FixedHostname::normalize(b"double..dot.example.org").is_none());
        assert!(FixedHostname::normalize(b"non_ascii_example.org").is_none());
    }

    #[test]
    fn accepts_253_byte_name_with_trailing_dot() {
        let mut name = Vec::with_capacity(254);
        for _ in 0..125 {
            name.extend_from_slice(b"a.");
        }
        name.extend_from_slice(b"abc.");
        assert_eq!(name.len(), 254, "valid 253-byte name plus trailing dot");
        let h = FixedHostname::normalize(&name).expect("253 canonical + dot must normalize");
        assert_eq!(h.as_bytes().len(), 253);
        assert!(FixedHostname::normalize(&name[..253]).is_some());
    }

    #[test]
    fn rejects_254_byte_name_without_dot_without_panic() {
        let name = [b'a'; 254];
        assert!(FixedHostname::normalize(&name).is_none());
    }

    #[test]
    fn rejects_255_byte_name_with_trailing_dot_without_panic() {
        let mut name = vec![b'a'; 254];
        name.push(b'.');
        assert!(FixedHostname::normalize(&name).is_none());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allowlist(Vec<Fqdn>);

impl Allowlist {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&Fqdn> {
        self.0.get(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Fqdn> {
        self.0.iter()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenAddr {
    ip: IpAddr,
    port: u16,
}

impl ListenAddr {
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    allowlist: Allowlist,
    listen: ListenAddr,
    startup_unresolved_allowance: u8,
}

impl Config {
    pub fn allowlist(&self) -> &Allowlist {
        &self.allowlist
    }

    pub fn listen(&self) -> &ListenAddr {
        &self.listen
    }

    pub fn startup_unresolved_allowance(&self) -> u8 {
        self.startup_unresolved_allowance
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Unreadable {
        path: String,
        source: String,
    },
    OversizedDocument {
        got: usize,
        limit: usize,
    },
    NotUtf8 {
        message: String,
    },
    ParseToml {
        message: String,
        span: Option<Range<usize>>,
    },
    MissingField(String),
    UnknownKey(String),
    UnknownTable(String),
    WrongType(String),
    AllowlistEmpty,
    AllowlistTooMany {
        got: usize,
    },
    DuplicateAllowlistName(String),
    InvalidFqdn {
        name: String,
        reason: String,
    },
    InvalidListen {
        value: String,
    },
    AllowanceOutOfRange {
        value: i64,
    },
}

impl ConfigError {
    pub fn exit_status(&self) -> i32 {
        78
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Unreadable { path, source } => {
                write!(f, "config unreadable: {}: {}", path, source)
            }
            ConfigError::OversizedDocument { got, limit } => {
                write!(
                    f,
                    "config exceeds {} bytes ({} bytes read); rejected without truncation",
                    limit, got
                )
            }
            ConfigError::NotUtf8 { message } => {
                write!(f, "config is not valid UTF-8: {}", message)
            }
            ConfigError::ParseToml { message, span } => match span {
                Some(span) => write!(
                    f,
                    "config parse error at bytes {}..{}: {}",
                    span.start, span.end, message
                ),
                None => write!(f, "config parse error: {}", message),
            },
            ConfigError::MissingField(field) => {
                write!(f, "config missing required field: {}", field)
            }
            ConfigError::UnknownKey(field) => write!(f, "config unknown key: {}", field),
            ConfigError::UnknownTable(table) => write!(f, "config unknown table: {}", table),
            ConfigError::WrongType(field) => write!(f, "config incorrect type: {}", field),
            ConfigError::AllowlistEmpty => write!(f, "config allowlist is empty (1..=32 required)"),
            ConfigError::AllowlistTooMany { got } => {
                write!(
                    f,
                    "config allowlist has {} entries (max {})",
                    got, ALLOWLIST_MAX
                )
            }
            ConfigError::DuplicateAllowlistName(name) => {
                write!(
                    f,
                    "config duplicate allowlist name after normalization: {}",
                    name
                )
            }
            ConfigError::InvalidFqdn { name, reason } => {
                write!(f, "config invalid FQDN {:?}: {}", name, reason)
            }
            ConfigError::InvalidListen { value } => {
                write!(
                    f,
                    "config listener {:?} invalid: expected numeric IPv4 or [bracketed IPv6] and port 1..=65535",
                    value
                )
            }
            ConfigError::AllowanceOutOfRange { value } => {
                write!(
                    f,
                    "config startup_unresolved_allowance {} out of range 0..=allowlist_len-1",
                    value
                )
            }
        }
    }
}

pub fn load_config_document(path: &str) -> Result<Config, ConfigError> {
    let file = File::open(path).map_err(|source| ConfigError::Unreadable {
        path: path.to_owned(),
        source: source.to_string(),
    })?;
    let mut buf = Vec::with_capacity(CONFIG_DOC_LIMIT + 1);
    file.take((CONFIG_DOC_LIMIT + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|source| ConfigError::Unreadable {
            path: path.to_owned(),
            source: source.to_string(),
        })?;
    if buf.len() > CONFIG_DOC_LIMIT {
        return Err(ConfigError::OversizedDocument {
            got: buf.len(),
            limit: CONFIG_DOC_LIMIT,
        });
    }
    let doc = std::str::from_utf8(&buf).map_err(|source| ConfigError::NotUtf8 {
        message: source.to_string(),
    })?;
    parse_config_document(doc)
}

pub fn parse_config_document(doc: &str) -> Result<Config, ConfigError> {
    if doc.len() > CONFIG_DOC_LIMIT {
        return Err(ConfigError::OversizedDocument {
            got: doc.len(),
            limit: CONFIG_DOC_LIMIT,
        });
    }
    let value: toml::Value = toml::from_str(doc).map_err(|err| ConfigError::ParseToml {
        message: err.message().to_owned(),
        span: err.span(),
    })?;
    let toml::Value::Table(table) = value else {
        return Err(ConfigError::ParseToml {
            message: "document root is not a table".to_owned(),
            span: None,
        });
    };
    from_table(table)
}

fn from_table(table: toml::Table) -> Result<Config, ConfigError> {
    let allowlist_names = require_string_list(&table, "allowlist")?;
    let listen = require_string(&table, "listen")?;
    let allowance = require_integer(&table, "startup_unresolved_allowance")?;
    for (key, value) in &table {
        if !matches!(
            key.as_str(),
            "allowlist" | "listen" | "startup_unresolved_allowance"
        ) {
            return Err(match value {
                toml::Value::Table(_) => ConfigError::UnknownTable(key.clone()),
                _ => ConfigError::UnknownKey(key.clone()),
            });
        }
    }
    let allowlist = build_allowlist(allowlist_names)?;
    let listen = parse_listen(&listen)?;
    if allowance < 0 || allowance as usize >= allowlist.len() {
        return Err(ConfigError::AllowanceOutOfRange { value: allowance });
    }
    Ok(Config {
        allowlist,
        listen,
        startup_unresolved_allowance: allowance as u8,
    })
}

fn require_string(table: &toml::Table, key: &str) -> Result<String, ConfigError> {
    match table.get(key) {
        None => Err(ConfigError::MissingField(key.into())),
        Some(toml::Value::String(value)) => Ok(value.clone()),
        Some(value) => Err(ConfigError::WrongType(format!(
            "{}: expected string, got {}",
            key,
            value_kind(value)
        ))),
    }
}

fn require_integer(table: &toml::Table, key: &str) -> Result<i64, ConfigError> {
    match table.get(key) {
        None => Err(ConfigError::MissingField(key.into())),
        Some(toml::Value::Integer(value)) => Ok(*value),
        Some(value) => Err(ConfigError::WrongType(format!(
            "{}: expected integer, got {}",
            key,
            value_kind(value)
        ))),
    }
}

fn require_string_list(table: &toml::Table, key: &str) -> Result<Vec<String>, ConfigError> {
    match table.get(key) {
        None => Err(ConfigError::MissingField(key.into())),
        Some(toml::Value::Array(items)) => {
            let mut values = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                match item {
                    toml::Value::String(value) => values.push(value.clone()),
                    _ => {
                        return Err(ConfigError::WrongType(format!(
                            "{}[{}]: expected string, got {}",
                            key,
                            index,
                            value_kind(item)
                        )));
                    }
                }
            }
            Ok(values)
        }
        Some(value) => Err(ConfigError::WrongType(format!(
            "{}: expected array of strings, got {}",
            key,
            value_kind(value)
        ))),
    }
}

fn value_kind(value: &toml::Value) -> &'static str {
    match value {
        toml::Value::String(_) => "string",
        toml::Value::Integer(_) => "integer",
        toml::Value::Float(_) => "float",
        toml::Value::Boolean(_) => "boolean",
        toml::Value::Datetime(_) => "datetime",
        toml::Value::Array(_) => "array",
        toml::Value::Table(_) => "table",
    }
}

fn build_allowlist(names: Vec<String>) -> Result<Allowlist, ConfigError> {
    if names.is_empty() {
        return Err(ConfigError::AllowlistEmpty);
    }
    if names.len() > ALLOWLIST_MAX {
        return Err(ConfigError::AllowlistTooMany { got: names.len() });
    }
    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        let fqdn =
            Fqdn::parse(&name).map_err(|reason| ConfigError::InvalidFqdn { name, reason })?;
        if !seen.insert(fqdn.as_str().to_owned()) {
            return Err(ConfigError::DuplicateAllowlistName(
                fqdn.as_str().to_owned(),
            ));
        }
        entries.push(fqdn);
    }
    Ok(Allowlist(entries))
}

fn parse_listen(listen: &str) -> Result<ListenAddr, ConfigError> {
    let invalid = || ConfigError::InvalidListen {
        value: listen.to_owned(),
    };
    let Some((addr_part, port_part)) = listen.rsplit_once(':') else {
        return Err(invalid());
    };
    let port: u16 = port_part.parse().map_err(|_| invalid())?;
    if port == 0 {
        return Err(invalid());
    }
    let ip = if let Some(rest) = addr_part.strip_prefix('[') {
        let Some(inner) = rest.strip_suffix(']') else {
            return Err(invalid());
        };
        let addr: Ipv6Addr = inner.parse().map_err(|_| invalid())?;
        IpAddr::V6(addr)
    } else {
        let addr: Ipv4Addr = addr_part.parse().map_err(|_| invalid())?;
        IpAddr::V4(addr)
    };
    Ok(ListenAddr { ip, port })
}
