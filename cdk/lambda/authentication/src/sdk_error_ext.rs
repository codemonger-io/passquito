//! Provides an extension for [`SdkError`](https://docs.rs/aws-smithy-runtime-api/latest/aws_smithy_runtime_api/client/result/enum.SdkError.html).

use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_smithy_runtime_api::client::result::SdkError;
use aws_smithy_types::error::metadata::ProvideErrorMetadata as _;

/// Extension for [`SdkError`](https://docs.rs/aws-smithy-runtime-api/latest/aws_smithy_runtime_api/client/result/enum.SdkError.html)
/// which provides an additional test method.
///
/// This trait is intended to be implemented for `SdkError<E, R>` with a
/// specific `E` and arbitrary `R`.
pub trait SdkErrorExt {
    /// Returns if the error is retryable.
    fn is_retryable(&self) -> bool;
}

impl<R> SdkErrorExt for SdkError<PutItemError, R> {
    fn is_retryable(&self) -> bool {
        match self {
            SdkError::ServiceError(e) => match e.err() {
                PutItemError::ProvisionedThroughputExceededException(_) |
                PutItemError::RequestLimitExceeded(_) => true,
                e => match e.code() {
                    Some("ServiceUnavailable") | Some("ThrottlingException") => true,
                    _ => false,
                }
            }
            _ => false,
        }
    }
}
