//! Cognito Lambda trigger for the custom challenges with passkeys.
//!
//! You have to configure the following environment variables:
//! - `SESSION_TABLE_NAME`: name of the DynamoDB table that manages sessions
//! - `CREDENTIAL_TABLE_NAME`: name of the DynamoDB table that manages
//!   credentials

use aws_lambda_events::event::cognito::CognitoEventUserPoolsDefineAuthChallenge;
use aws_sdk_dynamodb::{
    primitives::DateTime,
    types::{AttributeValue, ReturnValue},
};
use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{error, info};
use webauthn_rs::{
    Webauthn,
    WebauthnBuilder,
    prelude::{
        DiscoverableAuthentication,
        DiscoverableKey,
        Passkey,
        Url,
    },
};
use webauthn_rs_proto::{
    CollectedClientData,
    auth::PublicKeyCredential,
};

use authentication::event::{
    CognitoChallengeEvent,
    CognitoChallengeEventCase,
    CognitoEventUserPoolsCreateAuthChallengeExt,
    CognitoEventUserPoolsDefineAuthChallengeOps,
    CognitoEventUserPoolsVerifyAuthChallengeExt,
};

const CHALLENGE_PARAMETER_NAME: &str = "passkeyTestChallenge";

// State shared among Lambda invocations.
struct SharedState {
    webauthn: Webauthn,
    dynamodb: aws_sdk_dynamodb::Client,
    session_table_name: String,
    credential_table_name: String,
}

impl SharedState {
    async fn new() -> Result<Self, Error> {
        let rp_id = "localhost";
        let rp_origin = Url::parse("http://localhost:5173")?;
        let webauthn = WebauthnBuilder::new(rp_id, &rp_origin)?
            .rp_name("Passkey Test")
            .build()?;
        let config = aws_config::load_from_env().await;
        Ok(Self {
            webauthn,
            dynamodb: aws_sdk_dynamodb::Client::new(&config),
            session_table_name: env::var("SESSION_TABLE_NAME")
                .or(Err("SESSION_TABLE_NAME env must be set"))?,
            credential_table_name: env::var("CREDENTIAL_TABLE_NAME")
                .or(Err("CREDENTIAL_TABLE_NAME env must be set"))?,
        })
    }
}

/// Challenge response.
/// 
/// TODO: replace with the one from [`webauthn-rs-proto`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequestChallengeResponse {
    /// Dummy field.
    pub dummy: String,
}

/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
/// - https://github.com/aws-samples/serverless-rust-demo/
async fn function_handler(
    shared_state: Arc<SharedState>,
    event: LambdaEvent<CognitoChallengeEvent>,
) -> Result<CognitoChallengeEvent, Error> {
    let (event, _) = event.into_parts();
    let result = match event.determine() {
        Ok(CognitoChallengeEventCase::Define(event)) =>
            define_auth_challenge(shared_state, event).await?.into(),
        Ok(CognitoChallengeEventCase::Create(event)) =>
            create_auth_challenge(shared_state, event).await?.into(),
        Ok(CognitoChallengeEventCase::Verify(event)) =>
            verify_auth_challenge(shared_state, event).await?.into(),
        Err(e) => {
            return Err(format!("invalid Cognito challenge event: {}", e).into());
        }
    };
    Ok(result)
}

// Handles "Define auth challenge" events.
async fn define_auth_challenge(
    _shared_state: Arc<SharedState>,
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
    _shared_state: Arc<SharedState>,
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
    shared_state: Arc<SharedState>,
    mut event: CognitoEventUserPoolsVerifyAuthChallengeExt,
) -> Result<CognitoEventUserPoolsVerifyAuthChallengeExt, Error> {
    info!("verify_auth_challenge");

    let username = event.cognito_event_user_pools_header.user_name.as_ref()
        .ok_or("missing username")?;
    let credential: PublicKeyCredential = match event.get_challenge_answer() {
        Ok(credential) => credential,
        Err(e) => {
            error!("bad challenge answer: {:?}", event.get_raw_challenge_answer());
            return Err(e.into());
        }
    };
    // TODO: support non-discoverable credentials
    let _challenge: RequestChallengeResponse = event
        .get_private_challenge_parameter(CHALLENGE_PARAMETER_NAME)?
        .ok_or("missing private challenge parameter")?;

    // extracts the user handle from `credential`
    // it must match the username in the event
    let user_handle = credential.response.user_handle.as_ref()
        .ok_or("missing user handle")?
        .to_string();
    if username != &user_handle {
        error!("user mismatch: {} vs {}", username, user_handle);
        return Err("user mismatch".into());
    }

    // extracts the challenge from `credential`
    // https://github.com/kanidm/webauthn-rs/blob/0ff6b525d428b5155243a37e1672c1e3205d41e8/webauthn-rs-core/src/core.rs#L702-L705
    // https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorResponse/clientDataJSON#type
    let client_data: CollectedClientData = serde_json::from_slice(
        credential.response.client_data_json.as_ref(),
    )?;
    if client_data.type_ != "webauthn.get" {
        error!("invalid client data type: {}", client_data.type_);
        return Err("invalild client data type".into());
    }
    let client_challenge = client_data.challenge;

    // obtains the session corresponding to the challenge
    let session = shared_state.dynamodb
        .delete_item()
        .table_name(shared_state.session_table_name.clone())
        .key(
            "pk",
            AttributeValue::S(format!("discoverable#{}", client_challenge)),
        )
        .return_values(ReturnValue::AllOld)
        .send()
        .await?
        .attributes
        .ok_or("expired or wrong session")?;
    // session may have expired
    let ttl: i64 = session.get("ttl")
        .ok_or("missing ttl")?
        .as_n()
        .or(Err("invalid ttl"))?
        .parse()?;
    if ttl < DateTime::from(SystemTime::now()).secs() {
        return Err("session expired".into());
    }
    let auth_state = session.get("state")
        .ok_or("missing authentication state")?
        .as_s()
        .or(Err("invalid authentication state"))?;
    let auth_state: DiscoverableAuthentication =
        serde_json::from_str(&auth_state)?;

    // obtains the credentials (passkeys) associated with the user
    let credentials = shared_state.dynamodb
        .query()
        .table_name(shared_state.credential_table_name.clone())
        .key_condition_expression("pk = :pk")
        .expression_attribute_values(
            ":pk",
            AttributeValue::S(format!("user#{}", username)),
        )
        .send()
        .await?
        .items
        .ok_or("no credentials")?;
    let credentials: Vec<&String> = credentials.iter()
        .map(|c| c.get("credential")
            .ok_or("missing credential")?
            .as_s()
            .or(Err("invalid credential")))
        .collect::<Result<Vec<_>, _>>()?;
    let mut passkeys: Vec<Passkey> = credentials.into_iter()
        .map(|c| serde_json::from_str::<Passkey>(c))
        .collect::<Result<Vec<_>, _>>()?;

    // verifies the challenge
    let discoverable_keys: Vec<DiscoverableKey> = passkeys.iter()
        .map(|c| c.into())
        .collect();
    match shared_state.webauthn.finish_discoverable_authentication(
        &credential,
        auth_state,
        &discoverable_keys,
    ) {
        Ok(auth_result) => {
            // updates the stored credential if necessary
            for passkey in passkeys.iter_mut() {
                let credential_id = passkey.cred_id().to_string();
                info!("checking credential updates: {}", credential_id);
                if passkey.update_credential(&auth_result).is_some_and(|b| b) {
                    info!("updating credential: {}", credential_id);
                    shared_state.dynamodb
                        .update_item()
                        .table_name(shared_state.credential_table_name.clone())
                        .key(
                            "pk",
                            AttributeValue::S(format!("user#{}", username)),
                        )
                        .key(
                            "sk",
                            AttributeValue::S(
                                format!("credential#{}", credential_id),
                            ),
                        )
                        .update_expression("SET credential = :credential")
                        .expression_attribute_values(
                            ":credential",
                            AttributeValue::S(serde_json::to_string(passkey)?),
                        )
                        .condition_expression("attributes_exists(pk)")
                        .return_values(ReturnValue::None)
                        .send()
                        .await?;
                }
            }
            event.accept();
        }
        Err(e) => {
            error!("authentication failed: {}", e);
            event.reject();
        }
    };
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

    let shared_state = Arc::new(SharedState::new().await?);
    run(service_fn(|req| async {
        function_handler(shared_state.clone(), req).await
    })).await
}
