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

#[derive(Debug)]
pub struct TrafficStorage {
    bytes: Box<[u8]>,
}

impl TrafficStorage {
    pub fn allocate() -> Result<TrafficStorage, StorageUnavailable> {
        #[cfg(test)]
        if alloc_fault::armed() {
            return Err(StorageUnavailable);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(TRAFFIC_STORAGE_BYTES)
            .map_err(|_| StorageUnavailable)?;
        bytes.resize(TRAFFIC_STORAGE_BYTES, 0);
        Ok(TrafficStorage {
            bytes: bytes.into_boxed_slice(),
        })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
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
