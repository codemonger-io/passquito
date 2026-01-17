//! Common error response.

use lambda_runtime::{Error, diagnostic::Diagnostic};

/// Common error response.
///
/// When a Lambda handler returns an Err result,
/// [`lambda_runtime`][https://docs.rs/lambda_runtime/latest/lambda_runtime/index.html]
/// generates an error message that depends on the Rust compiler version by
/// default.
///
/// By using this enum as an Err result, we can generate deterministic error
/// messages as it implements
/// [`lambda_runtime::Diagnostic`][https://docs.rs/lambda_runtime/latest/lambda_runtime/diagnostic/struct.Diagnostic.html].
///
/// #### Letting an error go
///
/// [`lambda_runtime::Error`][https://docs.rs/lambda_runtime/latest/lambda_runtime/type.Error.html]
/// can be converted into [`ErrorResponse::Unhandled`] with the `into` method.
///
/// ```
/// # use authentication::error_response::ErrorResponse;
/// let err: lambda_runtime::Error = "error".into();
/// let res: ErrorResponse = err.into();
/// ```
#[derive(Debug)]
pub enum ErrorResponse {
    /// 400 Bad Request.
    ///
    /// ### Diagnostic message
    ///
    /// Use the following pattern to catch this error in an integration
    /// response: `"[BadRequest] message"`
    BadRequest(String),
    /// 401 Unauthorized.
    ///
    /// ### Diagnostic message
    ///
    /// Use the following pattern to catch this error in an integration
    /// response: `"[Unauthorized] message"`
    Unauthorized(String),
    /// 503 Service Unavailable.
    ///
    /// ### Diagnostic message
    ///
    /// Use the following pattern to catch this error in an integration
    /// response: `"[ServiceUnavailable] message"`
    Unavailable(String),
    /// Configuration error which will end up with 500 Internal Server Error.
    ///
    /// ### Diagnostic message
    ///
    /// Use the following pattern to catch this error in an integration
    /// response: `"[BadConfiguration] message"`
    BadConfiguration(String),
    /// Others which will end up with 500 Internal Server Error.
    ///
    /// ### Diagnostic message
    ///
    /// Use the following pattern to catch this error in an integration
    /// response: `"[Unhandled] message"`
    Unhandled(Error),
}

impl ErrorResponse {
    /// Creates [`ErrorResponse::BadRequest`].
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    /// Creates [`ErrorResponse::Unauthorized`].
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Unauthorized(message.into())
    }

    /// Creates [`ErrorResponse::Unavailable`].
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable(message.into())
    }

    /// Creates [`ErrorResponse::BadConfiguration`].
    pub fn bad_configuration(message: impl Into<String>) -> Self {
        Self::BadConfiguration(message.into())
    }
}

impl<E> From<E> for ErrorResponse
where
    E: Into<Error>,
{
    fn from(e: E) -> Self {
        ErrorResponse::Unhandled(e.into())
    }
}

impl From<ErrorResponse> for Diagnostic {
    fn from(e: ErrorResponse) -> Self {
        match e {
            ErrorResponse::BadRequest(msg) => make_diagnostic("BadRequest", &msg),
            ErrorResponse::Unauthorized(msg) => make_diagnostic("Unauthorized", &msg),
            ErrorResponse::Unavailable(msg) => make_diagnostic("ServiceUnavailable", &msg),
            ErrorResponse::BadConfiguration(msg) => make_diagnostic("BadConfiguration", &msg),
            ErrorResponse::Unhandled(e) => make_diagnostic("Unhandled", &e.to_string()),
        }
    }
}

// Creates a `Diagnostic` of a given error type and message.
//
// The error message is prefixed with the error type so that selection patterns
// in integration response options can be specific.
fn make_diagnostic(error_type: &str, error_message: &str) -> Diagnostic {
    Diagnostic {
        error_type: error_type.to_string(),
        error_message: format!("[{error_type}] {error_message}"),
    }
}
