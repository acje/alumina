//! Typed tripwire/action control seam: legal configuration values and the
//! pure policy decision that projects a typed violation fact onto a
//! supplementary enforcement effect.
//!
//! Tarpit has no operational type here: a configuration that selects it is
//! rejected at parse with an explicit deferred-status diagnostic, so a
//! dormant feature cannot be represented as implemented
//! (docs/alumina-proxy.md tripwire amendment).
//!
//! Runtime enforcement and monitoring projection are owner-local and are
//! integrated in later increments; the detection sites that will drive this
//! seam are `serving/reject.rs::reject_hello` (AnyIllegal) and the
//! early-upstream-data branch of `serving.rs` (EarlyUpstreamData), both of
//! which retain their mandatory baseline denial independently of any effect
//! this seam produces.

pub mod action;
pub mod policy;
pub mod state;
