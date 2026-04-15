use std::{collections::BTreeMap, path::Path};

use crate::errors::SnarkResult;
use serde::{Deserialize, Serialize};
use tracing::instrument;

/// Nested size accounting for an artifact or one of its logical subcomponents.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SizeBreakdown {
    /// Serialized size of this component in bytes.
    pub size: usize,
    /// Optional nested breakdown of child components.
    pub parts: BTreeMap<String, SizeBreakdown>,
}

impl SizeBreakdown {
    /// Construct a leaf component with no further breakdown.
    pub fn leaf(size: usize) -> Self {
        Self {
            size,
            parts: BTreeMap::new(),
        }
    }

    /// Construct a component with named child parts.
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

/// An artifact is a serializable boundary object that can be loaded from and saved to disk.
pub trait Artifact: Sized {
    /// Serialize the artifact into bytes.
    fn to_bytes(&self) -> SnarkResult<Vec<u8>>;

    /// Deserialize the artifact from bytes.
    fn from_bytes(bytes: &[u8]) -> SnarkResult<Self>;

    /// Return a nested size breakdown for artifacts that have meaningful internal structure.
    fn size_breakdown(&self) -> Option<SizeBreakdown> {
        None
    }

    /// Load the artifact from a file.
    #[instrument(level = "debug")]
    fn load(path: &Path) -> SnarkResult<Self> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Save the artifact to a file.
    #[instrument(level = "debug", skip(self))]
    fn save(&self, path: &Path) -> SnarkResult<()> {
        let bytes = self.to_bytes()?;
        std::fs::write(path, bytes)?;
        Ok(())
    }
}
