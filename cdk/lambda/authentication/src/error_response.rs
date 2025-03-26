//! Error response.

use lambda_http::{Body, Error, Response, http::StatusCode};
use lambda_runtime::diagnostic::Diagnostic;

/// Error response.
///
/// A Rust runtime buit with [`lambda_runtime`](https://docs.rs/lambda_runtime/latest/lambda_runtime/)
/// responds with a 500 error and exits if the service function returns an
/// error result.
/// If we want to return a different status code and keep the runtime running,
/// we have to let the service function return an OK result with a response
/// that has the disired status code.
///
/// This enum helps us to differentiate errors that we may want to respond with
/// a specific status code from those we let go and crash the runtime with a 500
/// status code.
///
/// #### Generating a response
///
/// `TryInto<Response<Body>>` is implemented for `ErrorResponse`.
///
/// ```
/// # use authentication::error_response::ErrorResponse;
/// use lambda_http::{Body, Response};
/// let res: Response<Body> = ErrorResponse::bad_request("Bad request").try_into().unwrap();
/// ```
///
/// #### Letting an error go
///
/// Errors can be converted into [`ErrorResponse::Unhandled`] with the `into`
/// method.
///
/// ```
/// # use authentication::error_response::ErrorResponse;
/// let err: lambda_http::Error = "error".into();
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

impl TryInto<Response<Body>> for ErrorResponse {
    type Error = Error;

    fn try_into(self) -> Result<Response<Body>, Self::Error> {
        match self {
            ErrorResponse::BadRequest(msg) => Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "text/plain")
                .body(msg.into())?),
            ErrorResponse::Unauthorized(msg) => Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("Content-Type", "text/plain")
                .body(msg.into())?),
            ErrorResponse::Unavailable(msg) => Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("Content-Type", "text/plain")
                .body(msg.into())?),
            ErrorResponse::BadConfiguration(msg) => Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "text/plain")
                .body(msg.into())?),
            ErrorResponse::Unhandled(e) => Err(e),
        }
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
