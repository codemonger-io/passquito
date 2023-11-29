//! Common error.

use thiserror::{Error as ThisError};

/// Common error.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Inconvertible.
    #[error("inconvertible: `{0}`")]
    Inconvertible(&'static str),
    /// Parameter not found.
    #[error("no such parameter: `{0}`")]
    ParameterNotFound(&'static str),
    /// Bad relying party origin.
    #[error("bad relying party origin: `{0}`")]
    BadRelyingPartyOrigin(String),
}
