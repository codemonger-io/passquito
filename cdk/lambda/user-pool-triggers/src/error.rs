//! Common error.

use thiserror::{Error as ThisError};

/// Common error.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Inconvertible.
    #[error("inconvertible: `{0}`")]
    Inconvertible(&'static str),
}
