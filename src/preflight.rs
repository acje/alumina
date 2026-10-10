//! Linux startup privilege preflight: require every real/effective/saved/
//! filesystem UID to be non-root, empty effective, permitted and ambient
//! capability sets, and `no_new_privs`; any unmet prerequisite fails as
//! EX_CONFIG (78).
//!
//! Binding constraints (oracle `alumina-b1x` C10, T-privilege; `alumina.md:58,
//! :150, :235`). A single zero UID among the four is rejected: a root saved or
//! filesystem UID with a non-root effective UID is a privilege regain path and
//! is never accepted. The kernel facts are read from `/proc/self/status` (a
//! kernel-generated probe; `no_new_privs` is read, never set). The decision
//! table over extracted facts is unit-testable anywhere; kernel-grounded
//! positive/negative fixtures exercise the real probe on Linux.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelFacts {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub cap_eff: u64,
    pub cap_prm: u64,
    pub cap_amb: u64,
    pub no_new_privs: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PreflightError {
    NotLinux,
    StatusUnreadable { source: String },
    StatusMalformed { detail: String },
    Root,
    NonEmptyEffective,
    NonEmptyPermitted,
    NonEmptyAmbient,
    MissingNoNewPrivs,
}

impl PreflightError {
    pub fn exit_status(&self) -> i32 {
        78
    }
}

impl fmt::Display for PreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PreflightError::NotLinux => {
                write!(
                    f,
                    "privilege preflight requires a Linux kernel (/proc self-status unavailable)"
                )
            }
            PreflightError::StatusUnreadable { source } => {
                write!(f, "cannot read kernel self-status: {}", source)
            }
            PreflightError::StatusMalformed { detail } => {
                write!(f, "kernel self-status malformed: {}", detail)
            }
            PreflightError::Root => write!(
                f,
                "prerequisite failure: process has a root UID (real/effective/saved/filesystem)"
            ),
            PreflightError::NonEmptyEffective => {
                write!(
                    f,
                    "prerequisite failure: non-empty effective capability set"
                )
            }
            PreflightError::NonEmptyPermitted => {
                write!(
                    f,
                    "prerequisite failure: non-empty permitted capability set"
                )
            }
            PreflightError::NonEmptyAmbient => {
                write!(f, "prerequisite failure: non-empty ambient capability set")
            }
            PreflightError::MissingNoNewPrivs => {
                write!(f, "prerequisite failure: no_new_privs not set")
            }
        }
    }
}

pub fn check(facts: KernelFacts) -> Result<(), PreflightError> {
    if facts.ruid == 0 || facts.euid == 0 || facts.suid == 0 || facts.fsuid == 0 {
        return Err(PreflightError::Root);
    }
    if facts.cap_eff != 0 {
        return Err(PreflightError::NonEmptyEffective);
    }
    if facts.cap_prm != 0 {
        return Err(PreflightError::NonEmptyPermitted);
    }
    if facts.cap_amb != 0 {
        return Err(PreflightError::NonEmptyAmbient);
    }
    if !facts.no_new_privs {
        return Err(PreflightError::MissingNoNewPrivs);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn read_kernel_facts() -> Result<KernelFacts, PreflightError> {
    let text = std::fs::read_to_string("/proc/self/status").map_err(|source| {
        PreflightError::StatusUnreadable {
            source: source.to_string(),
        }
    })?;
    parse_proc_status(&text)
}

#[cfg(not(target_os = "linux"))]
pub fn read_kernel_facts() -> Result<KernelFacts, PreflightError> {
    Err(PreflightError::NotLinux)
}

pub fn parse_proc_status(text: &str) -> Result<KernelFacts, PreflightError> {
    let mut uids: Option<(u32, u32, u32, u32)> = None;
    let mut cap_eff: Option<u64> = None;
    let mut cap_prm: Option<u64> = None;
    let mut cap_amb: Option<u64> = None;
    let mut no_new_privs: Option<bool> = None;

    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else { continue };
        match key {
            "Uid:" => {
                let mut ids = parts;
                let r = ids.next().and_then(|v| v.parse().ok());
                let e = ids.next().and_then(|v| v.parse().ok());
                let s = ids.next().and_then(|v| v.parse().ok());
                let f = ids.next().and_then(|v| v.parse().ok());
                match (r, e, s, f) {
                    (Some(ruid), Some(euid), Some(suid), Some(fsuid)) => {
                        uids = Some((ruid, euid, suid, fsuid));
                    }
                    _ => uids = None,
                }
            }
            "CapEff:" => cap_eff = parts.next().and_then(|v| u64::from_str_radix(v, 16).ok()),
            "CapPrm:" => cap_prm = parts.next().and_then(|v| u64::from_str_radix(v, 16).ok()),
            "CapAmb:" => cap_amb = parts.next().and_then(|v| u64::from_str_radix(v, 16).ok()),
            "NoNewPrivs:" => {
                let raw = parts.next().and_then(|v| v.parse::<u8>().ok());
                no_new_privs = raw.map(|v| v != 0);
            }
            _ => {}
        }
    }

    let (ruid, euid, suid, fsuid) = uids.ok_or_else(|| PreflightError::StatusMalformed {
        detail: "missing or unparsable Uid real/effective/saved/filesystem ids".into(),
    })?;
    let cap_eff = cap_eff.ok_or_else(|| PreflightError::StatusMalformed {
        detail: "missing or unparsable CapEff".into(),
    })?;
    let cap_prm = cap_prm.ok_or_else(|| PreflightError::StatusMalformed {
        detail: "missing or unparsable CapPrm".into(),
    })?;
    let cap_amb = cap_amb.ok_or_else(|| PreflightError::StatusMalformed {
        detail: "missing or unparsable CapAmb".into(),
    })?;
    let no_new_privs = no_new_privs.ok_or_else(|| PreflightError::StatusMalformed {
        detail: "missing or unparsable NoNewPrivs".into(),
    })?;

    Ok(KernelFacts {
        ruid,
        euid,
        suid,
        fsuid,
        cap_eff,
        cap_prm,
        cap_amb,
        no_new_privs,
    })
}
