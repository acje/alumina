//! Typed tripwire/action control seam: legal configuration values and the
//! pure policy decision that projects a typed violation fact onto a
//! supplementary enforcement effect.
//!
//! Tarpit has no operational type here: a configuration that selects it is
//! rejected at parse with an explicit deferred-status diagnostic, so a
//! dormant feature cannot be represented as implemented
//! (docs/alumina-proxy.md tripwire amendment).
//!
//! Runtime enforcement and monitoring projection are wired into the
//! single-owner serving/runtime turns: serving enforces the latched policy
//! per admitted connection (`serving.rs`), refusal effects and tripwire
//! verdicts emit through `serving/reject.rs`, and the runtime loop drives
//! deadline-based monitoring projection (`runtime.rs`). The detection sites
//! that feed this seam are `serving/reject.rs::reject_hello` (AnyIllegal)
//! and the early-upstream-data branch of `serving.rs` (EarlyUpstreamData),
//! and mandatory baseline denial is retained independently of any
//! supplementary effect this seam produces.

pub mod action;
pub mod monitor;
pub mod policy;
pub mod state;
