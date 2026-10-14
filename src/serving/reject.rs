use std::time::Instant;

use crate::log::RejectReason;

use super::ServeError;
use super::{Refusal, Serving, Stage};

impl Serving {
    pub(super) fn refuse(&mut self, index: usize, refusal: Refusal) {
        let body = refusal.body();
        self.emit_reject(index, refusal.reason());
        let ws = &mut self.slots[index];
        ws.down_off = 0;
        ws.down[..body.len()].copy_from_slice(body);
        ws.down_len = body.len();
        ws.stage = Stage::Refusing(body);
        self.flush_down(index);
        if self.slots[index].down_len == 0 {
            self.close_slot(index);
        }
    }

    /// Emits one warn-reject record for the rejected slot: the client address
    /// when readable and the approved hostname when a fixed one was set.
    pub(super) fn emit_reject(&mut self, index: usize, reason: RejectReason) {
        let secs = self.storage.cache_secs(Instant::now());
        let client = self.slots[index]
            .client
            .as_ref()
            .and_then(|c| c.peer_addr().ok());
        let hostname = self.slots[index].approved.as_ref().map(|h| h.as_str());
        self.storage
            .logs_mut()
            .reject(secs, reason, client, hostname);
    }

    pub(super) fn reject_hello(&mut self, index: usize) -> Result<(), ServeError> {
        self.slots[index].gate.on_hello_rejected();
        self.emit_reject(index, RejectReason::TlsValidation);
        self.close_slot(index);
        Ok(())
    }

    pub(super) fn close_slot(&mut self, index: usize) {
        let now = Instant::now();
        let ws = &mut self.slots[index];
        ws.stage = Stage::Closing;
        let slot = ws.handle.take();
        let tunnel = ws.tunnel.take();
        ws.client.take();
        ws.upstream.take();
        ws.reset();
        if let Some(tunnel) = tunnel {
            self.storage.release_tunnel(tunnel);
        } else if let Some(slot) = slot {
            self.storage.release(slot);
        }
        self.note_occupancy(now);
    }
}
