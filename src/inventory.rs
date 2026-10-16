use std::fmt;
use std::mem::size_of;

use crate::client_hello::MAX_CLIENT_HELLO;
use crate::connect::CONNECT_LIMIT;
use crate::dns::ResponseWorkspace;
use crate::startup_dns::{QUERY_BUF_LEN, RECV_BUF_LEN};

pub const TUNNEL_SLOTS: usize = 512;
pub const BUFFERS_PER_SLOT: usize = 2;
pub const BUFFER_BYTES: usize = 128 * 1024;
pub const TRAFFIC_STORAGE_BYTES: usize = TUNNEL_SLOTS * BUFFERS_PER_SLOT * BUFFER_BYTES;
pub const CONFIG_DOC_BUFFER_BYTES: usize = 4096;

/// The retained per-slot serving metadata: the fixed CONNECT parser head and
/// the two 64 KiB ClientHello inspector buffers, allocated once per tunnel
/// slot for the process lifetime and reused across connections.
pub const SLOT_WORKSPACE_BYTES: usize = CONNECT_LIMIT + (MAX_CLIENT_HELLO * 2);

/// The total retained serving-workspace bytes across all 512 slots.
pub const SERVING_WORKSPACE_BYTES: usize = TUNNEL_SLOTS * SLOT_WORKSPACE_BYTES;

/// The retained DNS transport named buffers (lower bound): the fixed 512-byte
/// query buffer plus the fixed `DNS_MSG_LIMIT + 2` response buffer that the
/// startup DNS transport pre-allocates, and the reusable response parse
/// workspace (fixed owners table). These are the named buffers retained for
/// the process lifetime; the DNS response message bound is their constituent.
pub const DNS_NAMED_BUFFER_BYTES: usize =
    QUERY_BUF_LEN + RECV_BUF_LEN + size_of::<ResponseWorkspace>();

/// The reserved best-effort log queue (256 records x 8 KiB), not yet
/// initialized in the serving candidate.
pub const LOG_QUEUE_BYTES: usize = 256 * (8 * 1024);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageUnavailable;

impl fmt::Display for StorageUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "boot traffic storage unavailable: failed to allocate {} bytes",
            TRAFFIC_STORAGE_BYTES
        )
    }
}

/// The two retained directional buffers for one tunnel slot, allocated once at
/// boot and transferred by value into the serving slot they back.
#[derive(Debug)]
pub struct SlotTraffic {
    pub up: Box<[u8]>,
    pub down: Box<[u8]>,
}

impl SlotTraffic {
    /// Splits the retained pair into its two buffer halves for transfer.
    pub fn into_parts(self) -> (Box<[u8]>, Box<[u8]>) {
        (self.up, self.down)
    }
}

/// The boot-owned traffic store: one retained directional-buffer pair per
/// tunnel slot, fully initialized before the first DNS exchange. Allocation is
/// fallible and any failure surfaces as the typed OOM [`StorageUnavailable`];
/// the store is transferred in whole to the serving owner, so no duplicate
/// traffic blob exists and serving performs no buffer allocation.
#[derive(Debug)]
pub struct TrafficStorage {
    slots: Box<[SlotTraffic]>,
}

impl TrafficStorage {
    /// Allocates and zero-initializes the full 128 MiB traffic store.
    ///
    /// # Errors
    ///
    /// Returns [`StorageUnavailable`] when any retained buffer cannot be
    /// reserved; the partial store is dropped and boot fails with the typed
    /// OOM variant.
    pub fn allocate() -> Result<TrafficStorage, StorageUnavailable> {
        #[cfg(test)]
        if alloc_fault::armed() {
            return Err(StorageUnavailable);
        }
        let mut slots: Vec<SlotTraffic> = Vec::new();
        slots
            .try_reserve_exact(TUNNEL_SLOTS)
            .map_err(|_| StorageUnavailable)?;
        for _ in 0..TUNNEL_SLOTS {
            slots.push(SlotTraffic {
                up: buffer_bytes()?,
                down: buffer_bytes()?,
            });
        }
        Ok(TrafficStorage {
            slots: slots.into_boxed_slice(),
        })
    }

    /// The exact initialized traffic bytes: 512 slots x 2 directions x 128 KiB.
    pub fn len(&self) -> usize {
        self.slots.len() * BUFFERS_PER_SLOT * BUFFER_BYTES
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Read view of the retained per-slot pairs, for accounting and tests.
    pub fn slots(&self) -> &[SlotTraffic] {
        &self.slots
    }

    /// Consumes the store, yielding the per-slot pairs for transfer into the
    /// serving owner without a second allocation.
    pub fn into_slots(self) -> Box<[SlotTraffic]> {
        self.slots
    }
}

fn buffer_bytes() -> Result<Box<[u8]>, StorageUnavailable> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes
        .try_reserve_exact(BUFFER_BYTES)
        .map_err(|_| StorageUnavailable)?;
    bytes.resize(BUFFER_BYTES, 0);
    Ok(bytes.into_boxed_slice())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootInventory {
    traffic_storage_bytes: usize,
    serving_workspace_bytes: usize,
    dns_named_buffer_bytes: usize,
    transient_config_buffer_bytes: usize,
    reserved_log_queue_bytes: usize,
}

impl BootInventory {
    pub fn phase1() -> BootInventory {
        BootInventory {
            traffic_storage_bytes: TRAFFIC_STORAGE_BYTES,
            serving_workspace_bytes: SERVING_WORKSPACE_BYTES,
            dns_named_buffer_bytes: DNS_NAMED_BUFFER_BYTES,
            transient_config_buffer_bytes: CONFIG_DOC_BUFFER_BYTES,
            reserved_log_queue_bytes: LOG_QUEUE_BYTES,
        }
    }

    /// The fixed named buffers the process is planned to retain for its
    /// lifetime (lower bound over named constants and `size_of` of the
    /// retained DNS workspace). Constant-derived plan, not an observation:
    /// the traffic store initializes at boot, the serving workspaces at
    /// [`Preallocated::preallocate`](crate::runtime::Preallocated::preallocate),
    /// and the DNS buffers at the DNS transport's own construction.
    pub fn named_fixed_buffer_bytes(&self) -> usize {
        self.traffic_storage_bytes
            .saturating_add(self.serving_workspace_bytes)
            .saturating_add(self.dns_named_buffer_bytes)
    }

    pub fn traffic_storage_bytes(&self) -> usize {
        self.traffic_storage_bytes
    }

    pub fn serving_workspace_bytes(&self) -> usize {
        self.serving_workspace_bytes
    }

    pub fn dns_named_buffer_bytes(&self) -> usize {
        self.dns_named_buffer_bytes
    }

    pub fn transient_scratch_bytes(&self) -> usize {
        self.transient_config_buffer_bytes
    }

    pub fn reserved_future_bytes(&self) -> usize {
        self.reserved_log_queue_bytes
    }
}

#[cfg(test)]
pub(crate) fn arm_alloc_failure() {
    alloc_fault::set(true);
}

#[cfg(test)]
pub(crate) fn clear_alloc_failure() {
    alloc_fault::set(false);
}

#[cfg(test)]
mod alloc_fault {
    use std::cell::Cell;

    thread_local! {
        static FAIL: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) fn set(value: bool) {
        FAIL.with(|cell| cell.set(value));
    }

    pub(super) fn armed() -> bool {
        FAIL.with(|cell| cell.get())
    }
}
