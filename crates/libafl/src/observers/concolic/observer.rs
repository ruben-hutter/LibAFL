use alloc::{borrow::Cow, vec::Vec};

use libafl_bolts::Named;
use serde::{Deserialize, Serialize};

use crate::observers::{
    Observer,
    concolic::{ConcolicMetadata, serialization_format::MessageFileReader},
};

/// A standard [`ConcolicObserver`] observer, observing constraints written into a memory buffer.
#[derive(Serialize, Deserialize, Debug)]
pub struct ConcolicObserver<'map> {
    #[serde(skip)]
    map: &'map [u8],
    name: Cow<'static, str>,
}

impl<I, S> Observer<I, S> for ConcolicObserver<'_> {}

impl ConcolicObserver<'_> {
    /// Create the concolic observer metadata for this run
    #[must_use]
    pub fn create_metadata_from_current_map(&self) -> ConcolicMetadata {
        // Debug: show raw shared memory state
        let first_bytes: Vec<u8> = self.map.iter().take(64).copied().collect();
        let non_zero_count = self.map.iter().filter(|&&b| b != 0).count();
        println!(
            "[ConcolicObserver] Shared memory: total_size={}, non_zero_bytes={}, first_64_bytes={:02x?}",
            self.map.len(),
            non_zero_count,
            first_bytes
        );

        let reader = MessageFileReader::from_length_prefixed_buffer(self.map)
            .expect("constructing the message reader from a memory buffer should not fail");

        let buffer = reader.get_buffer().to_vec();
        println!("  Length prefix decoded: {} bytes of trace data", buffer.len());

        // If the buffer is empty (length prefix was 0), the runtime didn't write
        // any symbolic data. Return empty metadata instead of trying to parse.
        if buffer.is_empty() {
            println!("  WARNING: Buffer is EMPTY - runtime wrote NO symbolic data!");
            println!("  This means SymQEMU/runtime didn't trace any symbolic expressions");
            println!("  Possible causes:");
            println!("     - Runtime not loaded (LD_LIBRARY_PATH missing libSymRuntime.so)");
            println!("     - Wrong backend (qsym instead of rust_backend)");
            println!("     - No symbolic input (input not marked as symbolic)");
            println!("     - Runtime failed to initialize shared memory");
            return ConcolicMetadata::default();
        }

        println!("  SUCCESS: Parsing {} bytes of concolic trace...", buffer.len());
        let metadata = ConcolicMetadata::from_buffer(buffer);
        let expr_count = metadata.iter_messages().count();
        // Histogram over expression kinds - shows at a glance whether a
        // trace contains path constraints (required for Z3) or only input
        // bytes.
        let mut kinds: alloc::collections::btree_map::BTreeMap<&'static str, usize> =
            alloc::collections::btree_map::BTreeMap::new();
        for (_id, msg) in metadata.iter_messages() {
            let name = match msg {
                crate::observers::concolic::SymExpr::InputByte { .. } => "InputByte",
                crate::observers::concolic::SymExpr::PathConstraint { .. } => "PathConstraint",
                crate::observers::concolic::SymExpr::Equal { .. } => "Equal",
                crate::observers::concolic::SymExpr::Integer { .. } => "Integer",
                _ => "other",
            };
            *kinds.entry(name).or_insert(0) += 1;
        }
        println!("  SUCCESS: Parsed {} symbolic expressions {:?}", expr_count, kinds);

        metadata
    }
}

impl Named for ConcolicObserver<'_> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<'map> ConcolicObserver<'map> {
    /// Creates a new [`ConcolicObserver`] with the given name and memory buffer.
    #[must_use]
    pub fn new(name: &'static str, map: &'map [u8]) -> Self {
        Self {
            map,
            name: Cow::from(name),
        }
    }
}
