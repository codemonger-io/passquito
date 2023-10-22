//! Errors.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

/// Possible errors.
#[derive(Debug, Error)]
pub enum WebauthnError {
    /// Unknown.
    #[error("unknown webauthn error")]
    Unknown,
    /// Corrupted session.
    #[error("Corrupt Session")]
    CorruptSession,
    /// No user.
    #[error("User Not Found")]
    UserNotFound,
    /// No credential for the user.
    #[error("User Has No Credentials")]
    UserHasNoCredentials,
    /// Bad request.
    #[error("Bad request")]
    BadRequest,
}

impl IntoResponse for WebauthnError {
    fn into_response(self) -> Response {
        macro_rules! internal_server_error {
            ($msg:expr) => {
                (StatusCode::INTERNAL_SERVER_ERROR, $msg)
            };
        }
        match self {
            WebauthnError::CorruptSession =>
                internal_server_error!("Corrupt Session"),
            WebauthnError::Unknown =>
                internal_server_error!("Unknown Error"),
            WebauthnError::UserHasNoCredentials =>
                internal_server_error!("User Has No Credentials"),
            WebauthnError::UserNotFound =>
                internal_server_error!("User Not Founde"),
            WebauthnError::BadRequest =>
                (StatusCode::BAD_REQUEST, "Bad Request"),
        }.into_response()
    }
}
