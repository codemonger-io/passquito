//! Registration.
//!
//! You have to configure the following environment variables:
//! - `BASE_PATH`: base path to provide the service; e.g., `/auth/cedentials/registration/`
//! - `SESSION_TABLE_NAME`: name of the DynamoDB table to store sessions
//! - `USER_POOL_ID`: ID of the Cognito user pool
//! - `CREDENTIAL_TABLE_NAME`: name of the DynamoDB table to store credentials
//!
//! ## Endpoints
//!
//! Provides the following endpoints under the base path.
//!
//! ### `POST ${BASE_PATH}start`
//!
//! Starts registration of a new user.
//! The request body must be [`NewUserInfo`] as `application/json`.
//! The response body is [`StartRegistrationSession`] as `application/json`.
//!
//! ### `POST ${BASE_PATH}finish`
//!
//! Verifies the new user and finishes registration.
//! The request body must be [`FinishRegistrationSession`] as `application/json`.
//! The response body is an empty text.

use aws_sdk_cognitoidentityprovider::types::{
    AttributeType as UserAttributeType,
    MessageActionType,
};
use aws_sdk_dynamodb::{
    primitives::{DateTime, DateTimeFormat},
    types::{AttributeValue, ReturnValue},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as base64url};
use lambda_http::{
    Body,
    Error,
    Request,
    RequestExt,
    RequestPayloadExt,
    Response,
    http::StatusCode,
    run,
    service_fn,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::time::SystemTime;
use tracing::{error, info};
use webauthn_rs::{
    WebauthnBuilder,
    prelude::{
        CreationChallengeResponse,
        CredentialID,
        PasskeyRegistration,
        Url,
        Uuid,
    },
};
use webauthn_rs_proto::RegisterPublicKeyCredential;

/// Information on a new user.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewUserInfo {
    /// Username.
    pub username: String,

    /// Display name.
    pub display_name: String,
}

/// Beginning of a session to register a new user.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartRegistrationSession {
    /// Session ID.
    pub session_id: String,

    /// Credential creation options.
    pub credential_creation_options: CreationChallengeResponse,
}

/// End of a session to register a new user.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishRegistrationSession {
    /// Session ID.
    pub session_id: String,

    /// Public key credential.
    pub public_key_credential: RegisterPublicKeyCredential,
}

async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    let base_path = env::var("BASE_PATH")
        .or(Err("BASE_PATH env must be configured"))?;
    let base_path = base_path.trim_end_matches('/');
    let job_path = event.raw_http_path().strip_prefix(base_path)
        .ok_or(format!("path must start with \"{}\"", base_path))?;
    match job_path {
        "/start" => {
            let user_info: NewUserInfo = event
                .payload()?
                .ok_or("missing new user info")?;
            start_registration(user_info).await
        }
        "/finish" => {
            let session: FinishRegistrationSession = event
                .payload()?
                .ok_or("missing registration session")?;
            finish_registration(session).await
        }
        _ => Err(format!("unsupported job path: {}", job_path).into()),
    }
}

async fn start_registration(user_info: NewUserInfo) -> Result<Response<Body>, Error> {
    info!("start_registration: {:?}", user_info);
    // TODO: reuse Webauthn
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:5173")?;
    let builder = WebauthnBuilder::new(rp_id, &rp_origin)?;
    let builder = builder.rp_name("Passkey Test");
    let webauthn = builder.build()?;

    // TODO: resolve the existing user

    // associates this ID with the new Cognito user later
    let user_unique_id = Uuid::new_v4();

    // TODO: list existing credentials to exclude
    let exclude_credentials: Option<Vec<CredentialID>> = None;

    let res = match webauthn.start_passkey_registration(
        user_unique_id,
        &user_info.username,
        &user_info.display_name,
        exclude_credentials,
    ) {
        Ok((ccr, reg_state)) => {
            // caches `reg_state`
            // TODO: reuse DynamoDB client
            let table_name = env::var("SESSION_TABLE_NAME")?;
            let config = aws_config::load_from_env().await;
            let client = aws_sdk_dynamodb::Client::new(&config);
            let user_unique_id = base64url.encode(user_unique_id.into_bytes());
            let session_id = base64url.encode(Uuid::new_v4().as_ref());
            let ttl = DateTime::from(SystemTime::now()).secs() + 60;
            info!("putting registration session: {}", session_id);
            client.put_item()
                .table_name(table_name)
                .item("pk", AttributeValue::S(format!("registration#{}", session_id)))
                .item("ttl", AttributeValue::N(format!("{}", ttl)))
                .item("userId", AttributeValue::S(user_unique_id))
                .item("userInfo", AttributeValue::M(HashMap::from([
                    ("username".into(), AttributeValue::S(user_info.username.into())),
                    ("displayName".into(), AttributeValue::S(user_info.display_name.into())),
                ])))
                .item("state", AttributeValue::S(serde_json::to_string(&reg_state)?))
                .send()
                .await?;
            serde_json::to_string(&StartRegistrationSession {
                session_id,
                credential_creation_options: ccr,
            })?
        }
        Err(e) => {
            error!("failed to start registration: {}", e);
            return Err("failed to start registration".into());
        }
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(res.into())?)
}

async fn finish_registration(session: FinishRegistrationSession) -> Result<Response<Body>, Error> {
    info!("finish_registration: {}", session.session_id);
    // TODO: reuse Webauthn
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:5173")?;
    let builder = WebauthnBuilder::new(rp_id, &rp_origin)?;
    let builder = builder.rp_name("Passkey Test");
    let webauthn = builder.build()?;

    // pops the session
    let table_name = env::var("SESSION_TABLE_NAME")?;
    let config = aws_config::load_from_env().await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let item = dynamodb.delete_item()
        .table_name(table_name)
        .key("pk", AttributeValue::S(format!("registration#{}", session.session_id)))
        .return_values(ReturnValue::AllOld)
        .send()
        .await?
        .attributes
        .ok_or("expired or wrong registration session")?;

    // the session may have expired
    let ttl: i64 = item.get("ttl")
        .ok_or("missing ttl")?
        .as_n()
        .or(Err("invalid ttl"))?
        .parse()?;
    if ttl < DateTime::from(SystemTime::now()).secs() {
        return Err("registration session expired".into());
    }

    // extracts the registration state
    let reg_state: PasskeyRegistration = serde_json::from_str(
        item.get("state")
            .ok_or("missing registration state")?
            .as_s()
            .or(Err("invalid state"))?,
    )?;

    // verifies the request
    match webauthn.finish_passkey_registration(
        &session.public_key_credential,
        &reg_state,
    ) {
        Ok(key) => {
            info!("verified key: {:?}", key);
            // extracts the user information
            let user_unique_id = item.get("userId")
                .ok_or("missing userId")?
                .as_s()
                .or(Err("invalid userId"))?;
            let user_info = item.get("userInfo")
                .ok_or("missing userInfo")?
                .as_m()
                .or(Err("invalid userInfo"))?;
            let username = user_info.get("username")
                .ok_or("missing username")?
                .as_s()
                .or(Err("invalid username"))?;
            let display_name = user_info.get("displayName")
                .ok_or("missing displayName")?
                .as_s()
                .or(Err("invalid displayName"))?;
            // generates a random password that is never used
            let mut password = [0u8; 24];
            getrandom::getrandom(&mut password)?;
            let password = base64url.encode(&password);
            // creates the Cognito user if not exists
            let user_pool_id = env::var("USER_POOL_ID")
                .or(Err("USER_POOL_ID env must be set"))?;
            let cognito = aws_sdk_cognitoidentityprovider::Client::new(&config);
            let cognito_user = cognito.admin_create_user()
                .user_pool_id(user_pool_id.clone())
                .username(user_unique_id.clone())
                .user_attributes(UserAttributeType::builder()
                    .name("preferred_username")
                    .value(username.clone())
                    .build())
                .user_attributes(UserAttributeType::builder()
                    .name("name")
                    .value(display_name.clone())
                    .build())
                .message_action(MessageActionType::Suppress)
                .temporary_password(password.clone())
                .send()
                .await?
                .user
                .ok_or("failed to create a new user")?;
            let sub = cognito_user.attributes
                .ok_or("missing Cognito user attributes")?
                .into_iter()
                .find(|a| a.name.as_ref()
                    .zip(a.value.as_ref())
                    .filter(|(n, _)| *n == "sub")
                    .is_some())
                .and_then(|a| a.value)
                .ok_or("missing Cognito user sub attribute")?;
            info!("created Cognito user: {}", sub);
            // force-confirms the password
            cognito.admin_set_user_password()
                .user_pool_id(user_pool_id)
                .username(user_unique_id.clone())
                .password(password)
                .permanent(true)
                .send()
                .await?;
            // stores `key` in the credential table
            // TODO: delete the user upon failure
            let credential_table_name = env::var("CREDENTIAL_TABLE_NAME")?;
            let credential_id = format!("{}", key.cred_id());
            let created_at = DateTime::from(SystemTime::now())
                .fmt(DateTimeFormat::DateTime)?;
            info!("storing credential: {}", credential_id);
            dynamodb.put_item()
                .table_name(credential_table_name)
                .item("pk", AttributeValue::S(format!("user#{}", user_unique_id)))
                .item("sk", AttributeValue::S(format!("credential#{}", credential_id)))
                .item("credentialId", AttributeValue::S(credential_id))
                .item("credential", AttributeValue::S(serde_json::to_string(&key)?))
                .item("cognitoSub", AttributeValue::S(sub))
                .item("createdAt", AttributeValue::S(created_at.clone()))
                .item("updatedAt", AttributeValue::S(created_at))
                .send()
                .await?;
        }
        Err(e) => {
            error!("failed to finish registration: {}", e);
            return Err("failed to finish registration".into());
        }
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        .body(().into())?)
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