use crate::log::RejectReason;

/// A typed refusal to serve a connection: the single source of truth mapping
/// forward to both the fixed HTTP body and the fixed `RejectReason` log
/// vocabulary. The refuse path never reverse-infers a reason from a byte
/// match, so a new refusal class cannot silently default to BadRequest.
#[derive(Clone, Copy)]
pub(super) enum Refusal {
    BadRequest,
    Forbidden,
    NoResolvedAddresses,
    DialFailed,
    SetupTimeout,
}

const BODY_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n";
const BODY_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n";
const BODY_502_NO_RESOLVED: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 22\r\n\r\nno resolved addresses\n";
const BODY_502_DIAL_FAILED: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 27\r\n\r\nupstream connection failed\n";
const BODY_504: &[u8] =
    b"HTTP/1.1 504 Gateway Timeout\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 23\r\n\r\nsetup deadline expired\n";

impl Refusal {
    pub(super) fn body(self) -> &'static [u8] {
        match self {
            Refusal::BadRequest => BODY_400,
            Refusal::Forbidden => BODY_403,
            Refusal::NoResolvedAddresses => BODY_502_NO_RESOLVED,
            Refusal::DialFailed => BODY_502_DIAL_FAILED,
            Refusal::SetupTimeout => BODY_504,
        }
    }

    pub(super) fn reason(self) -> RejectReason {
        match self {
            Refusal::BadRequest => RejectReason::BadRequest,
            Refusal::Forbidden => RejectReason::Forbidden,
            Refusal::NoResolvedAddresses | Refusal::DialFailed => RejectReason::DialFailed,
            Refusal::SetupTimeout => RejectReason::SetupTimeout,
        }
    }
}
