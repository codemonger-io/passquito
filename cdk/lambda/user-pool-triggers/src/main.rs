use aws_lambda_events::event::cognito::CognitoEventUserPoolsDefineAuthChallenge;
use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use serde::{Deserialize, Serialize};
use tracing::info;

use user_pool_triggers::event::{
    CognitoChallengeEvent,
    CognitoChallengeEventCase,
    CognitoEventUserPoolsCreateAuthChallengeExt,
    CognitoEventUserPoolsDefineAuthChallengeOps,
    CognitoEventUserPoolsVerifyAuthChallengeExt,
};

const CHALLENGE_PARAMETER_NAME: &str = "passkeyTestChallenge";

/// Challenge response.
/// 
/// TODO: replace with the one from [`webauthn-rs-proto`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequestChallengeResponse {
    /// Dummy field.
    pub dummy: String,
}

/// Public key credential.
///
/// TODO: replace with the one from [`webauthn-rs-proto`]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKeyCredential {
    /// Dummy field.
    pub dummy: String,
}

/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
/// - https://github.com/aws-samples/serverless-rust-demo/
async fn function_handler(
    event: LambdaEvent<CognitoChallengeEvent>,
) -> Result<CognitoChallengeEvent, Error> {
    let (event, _) = event.into_parts();
    let result = match event.determine() {
        Ok(CognitoChallengeEventCase::Define(event)) =>
            define_auth_challenge(event).await?.into(),
        Ok(CognitoChallengeEventCase::Create(event)) =>
            create_auth_challenge(event).await?.into(),
        Ok(CognitoChallengeEventCase::Verify(event)) =>
            verify_auth_challenge(event).await?.into(),
        Err(e) => {
            return Err(format!("invalid Cognito challenge event: {}", e).into());
        }
    };
    Ok(result)
}

// Handles "Define auth challenge" events.
async fn define_auth_challenge(
    mut event: CognitoEventUserPoolsDefineAuthChallenge,
) -> Result<CognitoEventUserPoolsDefineAuthChallenge, Error> {
    info!("define_auth_challenge");
    if event.sessions().is_empty() {
        info!("starting custom authentication");
        event.start_custom_challenge();
    } else if event.sessions().last().unwrap().as_ref()
        .filter(|s| s.challenge_result)
        .is_some()
    {
        info!("finishing custom authentication");
        event.allow();
    } else {
        info!("rejecting custom authentication");
        event.deny();
    }
    Ok(event)
}

// Handles "Create auth challenge" events.
async fn create_auth_challenge(
    mut event: CognitoEventUserPoolsCreateAuthChallengeExt,
) -> Result<CognitoEventUserPoolsCreateAuthChallengeExt, Error> {
    info!("create_auth_challenge");
    if event.sessions().is_empty() {
        event.set_challenge_metadata("PASSKEY_TEST_CHALLENGE");
        let rcr = RequestChallengeResponse {
            dummy: "dummy".into(),
        };
        event.set_public_challenge_parameter(CHALLENGE_PARAMETER_NAME, &rcr)?;
        event.set_private_challenge_parameter(CHALLENGE_PARAMETER_NAME, &rcr)?;
        Ok(event)
    } else {
        Err("no further challenges".into())
    }
}

// Handles "Verify auth challenge" events.
async fn verify_auth_challenge(
    mut event: CognitoEventUserPoolsVerifyAuthChallengeExt,
) -> Result<CognitoEventUserPoolsVerifyAuthChallengeExt, Error> {
    info!("verify_auth_challenge");
    let credential: PublicKeyCredential = event.get_challenge_answer()?;
    let challenge: RequestChallengeResponse = event
        .get_private_challenge_parameter(CHALLENGE_PARAMETER_NAME)?
        .ok_or("missing private challenge parameter")?;
    if credential.dummy == challenge.dummy {
        event.accept();
    } else {
        event.reject();
    }
    Ok(event)
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
