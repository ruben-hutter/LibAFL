use alloc::borrow::Cow;

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
        let reader = MessageFileReader::from_length_prefixed_buffer(self.map)
            .expect("constructing the message reader from a memory buffer should not fail");
        let buffer = reader.get_buffer().to_vec();
        
        // If the buffer is empty (length prefix was 0), the runtime didn't write
        // any symbolic data. Return empty metadata instead of trying to parse.
        if buffer.is_empty() {
            return ConcolicMetadata::default();
        }
        
        ConcolicMetadata::from_buffer(buffer)
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
