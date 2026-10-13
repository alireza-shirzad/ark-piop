use std::{collections::BTreeMap, path::Path};

use crate::errors::SnarkResult;
use serde::{Deserialize, Serialize};
use tracing::instrument;

/// Nested size accounting for an artifact or one of its logical subcomponents.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SizeBreakdown {
    /// Serialized size of this component in bytes.
    pub size: usize,
    pub parts: BTreeMap<String, SizeBreakdown>,
}

impl SizeBreakdown {
    pub fn leaf(size: usize) -> Self {
        Self {
            size,
            parts: BTreeMap::new(),
        }
    }

    pub fn node(
        size: usize,
        parts: impl IntoIterator<Item = (impl Into<String>, SizeBreakdown)>,
    ) -> Self {
        Self {
            size,
            parts: parts
                .into_iter()
                .map(|(name, breakdown)| (name.into(), breakdown))
                .collect(),
        }
    }
}

/// A serializable object that can be loaded from and saved to disk.
pub trait Artifact: Sized {
    fn to_bytes(&self) -> SnarkResult<Vec<u8>>;

    fn from_bytes(bytes: &[u8]) -> SnarkResult<Self>;

    /// `Some` for artifacts with internal structure worth breaking down.
    fn size_breakdown(&self) -> Option<SizeBreakdown> {
        None
    }

    #[instrument(level = "debug")]
    fn load(path: &Path) -> SnarkResult<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    #[instrument(level = "debug", skip(self))]
    fn save(&self, path: &Path) -> SnarkResult<()> {
        let bytes = self.to_bytes()?;
        std::fs::write(path, bytes)?;
        Ok(())
    }
}
