use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    PartialRead,
    PartialWrite,
    WouldBlock,
    CombinedReadWrite,
    ReadinessWithoutData,
    Data,
    Eof,
    Reset,
    TimerExpiry,
    Clock,
}

pub const REQUIRED_CATEGORIES: [Category; 10] = [
    Category::PartialRead,
    Category::PartialWrite,
    Category::WouldBlock,
    Category::CombinedReadWrite,
    Category::ReadinessWithoutData,
    Category::Data,
    Category::Eof,
    Category::Reset,
    Category::TimerExpiry,
    Category::Clock,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    PartialRead { delivered: usize },
    PartialWrite { accepted: usize },
    WouldBlock,
    CombinedReadWrite,
    ReadinessWithoutData,
    Data { bytes: Vec<u8> },
    Eof,
    Reset,
    TimerExpiry { at: u64 },
    Clock { now: u64 },
}

impl Outcome {
    pub fn category(&self) -> Category {
        match self {
            Outcome::PartialRead { .. } => Category::PartialRead,
            Outcome::PartialWrite { .. } => Category::PartialWrite,
            Outcome::WouldBlock => Category::WouldBlock,
            Outcome::CombinedReadWrite => Category::CombinedReadWrite,
            Outcome::ReadinessWithoutData => Category::ReadinessWithoutData,
            Outcome::Data { .. } => Category::Data,
            Outcome::Eof => Category::Eof,
            Outcome::Reset => Category::Reset,
            Outcome::TimerExpiry { .. } => Category::TimerExpiry,
            Outcome::Clock { .. } => Category::Clock,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Script {
    id: String,
    points: BTreeMap<String, Vec<Outcome>>,
}

impl Script {
    pub fn new(id: impl Into<String>) -> Self {
        Script {
            id: id.into(),
            points: BTreeMap::new(),
        }
    }

    pub fn at(mut self, point: impl Into<String>, outcomes: Vec<Outcome>) -> Self {
        self.points.insert(point.into(), outcomes);
        self
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn points(&self) -> impl Iterator<Item = (&String, &Vec<Outcome>)> {
        self.points.iter()
    }
}

pub struct Replay {
    script: Script,
    points: BTreeMap<String, usize>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Replayed<'a> {
    pub point: &'a str,
    pub index: usize,
    pub outcome: Outcome,
}

impl Replay {
    pub fn new(script: Script) -> Self {
        Replay {
            script,
            points: BTreeMap::new(),
        }
    }

    pub fn script_id(&self) -> &str {
        self.script.id()
    }

    pub fn next<'a>(&mut self, point: &'a str) -> Option<Replayed<'a>> {
        let outcomes = self.script.points.get(point)?;
        let index = self.points.get(point).copied().unwrap_or(0);
        if index >= outcomes.len() {
            return None;
        }
        self.points.insert(point.to_owned(), index + 1);
        let outcome = outcomes[index].clone();
        Some(Replayed {
            point,
            index,
            outcome,
        })
    }

    pub fn into_script(self) -> Script {
        self.script
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clock {
    ticks: Vec<u64>,
    cursor: usize,
}

impl Clock {
    pub fn new(ticks: Vec<u64>) -> Self {
        Clock { ticks, cursor: 0 }
    }

    pub fn now(&mut self) -> Option<u64> {
        let tick = self.ticks.get(self.cursor).copied()?;
        self.cursor = self.cursor.saturating_add(1);
        Some(tick)
    }
}
