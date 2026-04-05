use std::path::Path;

use crate::errors::SnarkResult;
use tracing::instrument;

/// An artifact is a serializable boundary object that can be loaded from and saved to disk.
pub trait Artifact: Sized {
    /// Serialize the artifact into bytes.
    fn to_bytes(&self) -> SnarkResult<Vec<u8>>;

    /// Deserialize the artifact from bytes.
    fn from_bytes(bytes: &[u8]) -> SnarkResult<Self>;

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
