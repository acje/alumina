use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

pub const NAMED_PHASES: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    StartupDns,
    Serving,
    BackgroundRefresh,
    Logging,
    Shutdown,
}

impl Phase {
    pub const ALL: [Phase; NAMED_PHASES] = [
        Phase::StartupDns,
        Phase::Serving,
        Phase::BackgroundRefresh,
        Phase::Logging,
        Phase::Shutdown,
    ];

    fn index(self) -> usize {
        match self {
            Phase::StartupDns => 0,
            Phase::Serving => 1,
            Phase::BackgroundRefresh => 2,
            Phase::Logging => 3,
            Phase::Shutdown => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Alloc,
    Dealloc,
    Realloc,
}

impl Event {
    fn index(self) -> usize {
        match self {
            Event::Alloc => 0,
            Event::Dealloc => 1,
            Event::Realloc => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub allocs: u64,
    pub deallocs: u64,
    pub reallocs: u64,
}

impl Counts {
    pub fn all_zero(self) -> bool {
        self.allocs == 0 && self.deallocs == 0 && self.reallocs == 0
    }
}

type PhaseCounts = [[u64; 3]; NAMED_PHASES];

thread_local! {
    static CURRENT_PHASE: Cell<Option<Phase>> = const { Cell::new(None) };
    static MEASURED: Cell<PhaseCounts> = const { Cell::new([[0; 3]; NAMED_PHASES]) };
}

fn measure(event: Event) {
    let phase = CURRENT_PHASE.try_with(|cell| cell.get()).unwrap_or(None);
    let Some(phase) = phase else {
        return;
    };
    let p = phase.index();
    let e = event.index();
    let _ = MEASURED.try_with(|cell| {
        let mut counts = cell.get();
        counts[p][e] = counts[p][e].saturating_add(1);
        cell.set(counts);
    });
}

struct PhaseGuard {
    prev: Option<Phase>,
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        let _ = CURRENT_PHASE.try_with(|cell| cell.set(self.prev));
    }
}

pub fn run_phase<R>(phase: Phase, f: impl FnOnce() -> R) -> (R, Counts) {
    let before = MEASURED.with(|cell| cell.get());
    let _guard = PhaseGuard {
        prev: CURRENT_PHASE.with(|cell| cell.replace(Some(phase))),
    };
    let value = f();
    let after = MEASURED.with(|cell| cell.get());
    let p = phase.index();
    let counts = Counts {
        allocs: after[p][0] - before[p][0],
        deallocs: after[p][1] - before[p][1],
        reallocs: after[p][2] - before[p][2],
    };
    (value, counts)
}

pub fn active_phase() -> Option<Phase> {
    CURRENT_PHASE.with(|cell| cell.get())
}

pub struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        measure(Event::Alloc);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        measure(Event::Dealloc);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        measure(Event::Realloc);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[cfg(feature = "alloc-witness")]
#[global_allocator]
static WITNESS: Counting = Counting;
