#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParserTarget {
    ConnectHeaders,
    ClientHello,
    DnsWire,
    LogRecord,
}

impl ParserTarget {
    pub const ALL: [ParserTarget; 4] = [
        ParserTarget::ConnectHeaders,
        ParserTarget::ClientHello,
        ParserTarget::DnsWire,
        ParserTarget::LogRecord,
    ];

    pub fn owning_slice(self) -> u8 {
        match self {
            ParserTarget::ConnectHeaders => 3,
            ParserTarget::ClientHello => 4,
            ParserTarget::DnsWire => 2,
            ParserTarget::LogRecord => 6,
        }
    }

    pub fn status(self) -> &'static str {
        "scaffold"
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed([u8; 32]);

impl Seed {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Seed(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InputHash(u64);

impl InputHash {
    pub fn hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(16);
        for byte in self.0.to_le_bytes() {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}

fn fnv1a64_raw(data: impl Iterator<Item = u8>) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

pub fn fnv1a64(data: impl Iterator<Item = u8>) -> InputHash {
    InputHash(fnv1a64_raw(data))
}

pub struct DeterministicGen {
    seed: Seed,
    state: u64,
}

impl DeterministicGen {
    pub fn new(seed: Seed) -> Self {
        let state = fnv1a64_raw(seed.as_bytes().iter().copied());
        DeterministicGen { seed, state }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn seed(&self) -> &Seed {
        &self.seed
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next_u64() >> 24) as u8).collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    DuplicateTarget(ParserTarget),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpusRecord {
    target: ParserTarget,
    seed: Seed,
    corpus_checked_in: bool,
    generated_inputs: u64,
    last_input_hash: Option<InputHash>,
}

pub struct CorpusOwnership {
    records: Vec<CorpusRecord>,
}

impl CorpusOwnership {
    pub fn new() -> Self {
        CorpusOwnership {
            records: Vec::new(),
        }
    }

    pub fn register(
        &mut self,
        target: ParserTarget,
        seed: Seed,
    ) -> Result<&mut CorpusRecord, RegisterError> {
        if self.records.iter().any(|record| record.target == target) {
            return Err(RegisterError::DuplicateTarget(target));
        }
        self.records.push(CorpusRecord {
            target,
            seed,
            corpus_checked_in: false,
            generated_inputs: 0,
            last_input_hash: None,
        });
        let index = self.records.len() - 1;
        Ok(&mut self.records[index])
    }

    pub fn records(&self) -> &[CorpusRecord] {
        &self.records
    }

    pub fn find(&self, target: ParserTarget) -> Option<&CorpusRecord> {
        self.records.iter().find(|record| record.target == target)
    }

    pub fn record_mut(&mut self, target: ParserTarget) -> Option<&mut CorpusRecord> {
        self.records
            .iter_mut()
            .find(|record| record.target == target)
    }

    pub fn contains(&self, target: ParserTarget) -> bool {
        self.records.iter().any(|record| record.target == target)
    }
}

impl Default for CorpusOwnership {
    fn default() -> Self {
        CorpusOwnership::new()
    }
}

impl CorpusRecord {
    pub fn target(&self) -> ParserTarget {
        self.target
    }

    pub fn seed(&self) -> &Seed {
        &self.seed
    }

    pub fn set_corpus_checked_in(&mut self, value: bool) {
        self.corpus_checked_in = value;
    }

    pub fn corpus_is_checked_in(&self) -> bool {
        self.corpus_checked_in
    }

    pub fn add_generated(&mut self, inputs: u64) {
        self.generated_inputs = self.generated_inputs.saturating_add(inputs);
    }

    pub fn generated_inputs(&self) -> u64 {
        self.generated_inputs
    }

    pub fn set_last_input_hash(&mut self, hash: InputHash) {
        self.last_input_hash = Some(hash);
    }

    pub fn last_input_hash(&self) -> Option<&InputHash> {
        self.last_input_hash.as_ref()
    }
}
