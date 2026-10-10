use std::fmt;

pub const TUNNEL_SLOTS: usize = 128;
pub const BUFFERS_PER_SLOT: usize = 2;
pub const BUFFER_BYTES: usize = 512 * 1024;
pub const TRAFFIC_STORAGE_BYTES: usize = TUNNEL_SLOTS * BUFFERS_PER_SLOT * BUFFER_BYTES;
pub const CONFIG_DOC_BUFFER_BYTES: usize = 4096;

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

    /// The exact initialized traffic bytes: 128 slots x 2 directions x 512 KiB.
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
pub struct ReservedFuture {
    connect_parse_bytes: usize,
    tls_pre_auth_bytes: usize,
    dns_message_bytes: usize,
    log_queue_bytes: usize,
}

impl ReservedFuture {
    fn new() -> ReservedFuture {
        ReservedFuture {
            connect_parse_bytes: 8 * 1024,
            tls_pre_auth_bytes: 64 * 1024,
            dns_message_bytes: 16 * 1024,
            log_queue_bytes: 256 * (8 * 1024),
        }
    }

    pub fn total(&self) -> usize {
        self.connect_parse_bytes
            .saturating_add(self.tls_pre_auth_bytes)
            .saturating_add(self.dns_message_bytes)
            .saturating_add(self.log_queue_bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootInventory {
    traffic_storage_bytes: usize,
    transient_config_buffer_bytes: usize,
    reserved: ReservedFuture,
}

impl BootInventory {
    pub fn phase1() -> BootInventory {
        BootInventory {
            traffic_storage_bytes: TRAFFIC_STORAGE_BYTES,
            transient_config_buffer_bytes: CONFIG_DOC_BUFFER_BYTES,
            reserved: ReservedFuture::new(),
        }
    }

    pub fn retained_initialized_bytes(&self) -> usize {
        self.traffic_storage_bytes
    }

    pub fn transient_scratch_bytes(&self) -> usize {
        self.transient_config_buffer_bytes
    }

    pub fn reserved_future_bytes(&self) -> usize {
        self.reserved.total()
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
