use aws_lambda_events::event::cognito::CognitoEventUserPoolsDefineAuthChallenge;
use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use serde::Serialize;
use tracing::info;

use user_pool_triggers::event::{
    CognitoChallengeEvent,
    CognitoChallengeEventCase,
    CognitoEventUserPoolsCreateAuthChallengeExt,
    CognitoEventUserPoolsVerifyAuthChallengeExt,
};

/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
/// - https://github.com/aws-samples/serverless-rust-demo/
async fn function_handler(
    event: LambdaEvent<CognitoChallengeEvent>,
) -> Result<CognitoChallengeEvent, Error> {
    let (payload, _) = event.into_parts();
    let result = match payload.determine() {
        Ok(CognitoChallengeEventCase::Define(payload)) =>
            define_auth_challenge(payload).await?.into(),
        Ok(CognitoChallengeEventCase::Create(payload)) =>
            create_auth_challenge(payload).await?.into(),
        Ok(CognitoChallengeEventCase::Verify(payload)) =>
            verify_auth_challenge(payload).await?.into(),
        Err(_) => {
            return Err("invalid Cognito challenge event".into());
        }
    };
    Ok(result)
}

// Handles "Define auth challenge" events.
async fn define_auth_challenge(
    payload: CognitoEventUserPoolsDefineAuthChallenge,
) -> Result<CognitoEventUserPoolsDefineAuthChallenge, Error> {
    info!("define_auth_challenge");
    Ok(payload)
}

// Handles "Create auth challenge" events.
async fn create_auth_challenge(
    payload: CognitoEventUserPoolsCreateAuthChallengeExt,
) -> Result<CognitoEventUserPoolsCreateAuthChallengeExt, Error> {
    info!("create_auth_challenge");
    Ok(payload)
}

// Handles "Verify auth challenge" events.
async fn verify_auth_challenge(
    payload: CognitoEventUserPoolsVerifyAuthChallengeExt,
) -> Result<CognitoEventUserPoolsVerifyAuthChallengeExt, Error> {
    info!("verify_auth_challenge");
    Ok(payload)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .init();

    run(service_fn(function_handler)).await
}
