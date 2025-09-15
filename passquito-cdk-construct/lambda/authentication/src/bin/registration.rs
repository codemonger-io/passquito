//! Registration.
//!
//! This application is intended to run as an AWS Lambda function.
//!
//! You have to configure the following environment variables:
//! - `SESSION_TABLE_NAME`: name of the DynamoDB table to store sessions
//! - `USER_POOL_ID`: ID of the Cognito user pool
//! - `CREDENTIAL_TABLE_NAME`: name of the DynamoDB table to store credentials
//! - `RP_ORIGIN_PARAMETER_PATH`: path to the parameter that stores the origin
//!   (URL) of the relying party in the Parameter Store on AWS Systems Manager
//!
//! You may configure the following environment variable:
//! - `REGISTRATION_TIMEOUT_IN_MILLIS`: timeout of the registration
//!   session in milliseconds (default: 30000 ms = 5 minutes).
//!   The default value is [recommended in the WebAuthn specification](https://www.w3.org/TR/webauthn-3/#sctn-timeout-recommended-range).
//!
//! ## Actions
//!
//! Provides the following actions depending on the request payload.
//!
//! ### Start registration of a new user
//!
//! Starts a registration session for a new user.
//!
//! To start registration of a new user, the request body must be in the form
//! of the following JSON which is a serialized form of
//! [`RegistrationAction::Start`]:
//!
//! ```json
//! {
//!   "start": {
//!     "username": "test",
//!     "displayName": "Test User"
//!   }
//! }
//! ```
//!
//! The response body is [`StartRegistrationSession`] in the JSON format.
//!
//! ### Start registration of a new credential for a verified user
//!
//! Starts a registration session of a new credential for a verified user.
//!
//! To start registration of a new credential of a verified user, the request
//! body must be in the form of the following JSON which is a serialized form
//! of [`RegistrationAction::StartVerified`]:
//!
//! ```json
//! {
//!   "startVerified": {
//!     "username": "test",
//!     "displayName": "Test User,
//!     "cognitoSub": "sub-issued-by-cognito",
//!     "userId": "unique-user-id"
//!   }
//! }
//! ```
//!
//! The response body is [`StartRegistrationSession`] in the JSON format.
//!
//! This action is intended to be used by a user who has been verified in a
//! cross-device manner to register a new device (credential).
//!
//! ### Finish registration
//!
//! Verifies the public key credential of a new user and finishes the
//! registration.
//!
//! To finish the registration of a new user, the request body must be in the
//! form of the following JSON which is a serialized form of
//! [`RegistrationAction::Finish`]:
//!
//! ```json
//! {
//!   "finish": {
//!     "sesssionId": "0123456789abcdef",
//!     "publicKeyCredential": {
//!       // see RegisterPublicKeyCredential
//!     }
//!   }
//! }
//! ```
//!
//! The response body is [`RegisteredUserInfo`] in the JSON format.

use aws_sdk_cognitoidentityprovider::types::{
    AttributeType as UserAttributeType,
    MessageActionType,
    UserStatusType,
};
use aws_sdk_dynamodb::{
    primitives::{DateTime, DateTimeFormat},
    types::{AttributeValue, ReturnValue},
};
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE_NO_PAD as base64url},
};
use lambda_runtime::{Error, LambdaEvent, run, service_fn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{error, info, warn};
use webauthn_rs::{
    Webauthn,
    WebauthnBuilder,
    prelude::{
        CreationChallengeResponse,
        CredentialID,
        Passkey,
        PasskeyRegistration,
        Uuid,
        WebauthnError,
    },
};
use webauthn_rs_proto::{RegisterPublicKeyCredential, ResidentKeyRequirement};

use authentication::error_response::ErrorResponse;
use authentication::parameters::load_relying_party_origin;
use authentication::sdk_error_ext::SdkErrorExt as _;

const DEFAULT_REGISTRATION_TIMEOUT_IN_MILLIS: &str = "300000";

// Shared state.
#[cfg_attr(test, derive(derive_builder::Builder))]
#[cfg_attr(test, builder(setter(into), pattern = "owned"))]
struct SharedState<Webauthn> {
    webauthn: Webauthn,
    cognito: aws_sdk_cognitoidentityprovider::Client,
    dynamodb: aws_sdk_dynamodb::Client,
    #[cfg_attr(test, builder(default = "\"ap-northeast-1_123456789\".to_string()"))]
    user_pool_id: String,
    #[cfg_attr(test, builder(default = "\"sessions\".to_string()"))]
    session_table_name: String,
    #[cfg_attr(test, builder(default = "\"credentials\".to_string()"))]
    credential_table_name: String,
    #[cfg_attr(test, builder(default = "DEFAULT_REGISTRATION_TIMEOUT_IN_MILLIS.parse().map(Duration::from_millis).unwrap()"))]
    registration_timeout: Duration,
}

impl SharedState<Webauthn> {
    async fn new() -> Result<Self, Error> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let (rp_id, rp_origin) =
            load_relying_party_origin(aws_sdk_ssm::Client::new(&config)).await?;
        let registration_timeout = env::var("REGISTRATION_TIMEOUT_IN_MILLIS")
            .unwrap_or_else(|_| DEFAULT_REGISTRATION_TIMEOUT_IN_MILLIS.to_string())
            .parse()
            .map(Duration::from_millis)
            .map_err(|_| "REGISTRATION_TIMEOUT_IN_MILLIS env must be an integer or omitted")?;
        let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)?
            .rp_name("Passkey Test")
            .timeout(registration_timeout.clone())
            .build()?;
        Ok(Self {
            webauthn,
            cognito: aws_sdk_cognitoidentityprovider::Client::new(&config),
            dynamodb: aws_sdk_dynamodb::Client::new(&config),
            user_pool_id: env::var("USER_POOL_ID")
                .or(Err("USER_POOL_ID env must be set"))?,
            session_table_name: env::var("SESSION_TABLE_NAME")
                .or(Err("SESSION_TABLE_NAME env must be set"))?,
            credential_table_name: env::var("CREDENTIAL_TABLE_NAME")
                .or(Err("CREDENTIAL_TABLE_NAME env must be set"))?,
            registration_timeout,
        })
    }
}

/// Registration action.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RegistrationAction {
    /// Start registration of a new user.
    Start(NewUserInfo),
    /// Start registration of a new credential of a verified user.
    StartVerified(VerifiedUserInfo),
    /// Finish registration.
    Finish(FinishRegistrationSession),
}

/// Information on a new user.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewUserInfo {
    /// Username of the new user.
    ///
    /// The username is not necessarily unique.
    /// It is provided for the user to locate the passkey in user's device.
    ///
    /// The username is stored as the preferred username in the Cognito user
    /// pool.
    pub username: String,

    /// Display name of the new user.
    ///
    /// The display name is not necessarily unique.
    /// It is provided for the user to locate the passkey in user's device.
    /// (As far as I tested, macOS did not show the display name.)
    pub display_name: String,
}

/// Information on a verified user.
///
/// Extension of [`NewUserInfo`].
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedUserInfo {
    /// User information.
    #[serde(flatten)]
    pub user_info: NewUserInfo,

    /// Cognito-issued sub of the user.
    pub cognito_sub: String,

    /// Unique user ID issued by Passquito.
    pub user_id: String,
}

impl std::ops::Deref for VerifiedUserInfo {
    type Target = NewUserInfo;

    fn deref(&self) -> &Self::Target {
        &self.user_info
    }
}

/// Beginning of a session to register a new user.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
#[serde(rename_all = "camelCase")]
pub struct StartRegistrationSession {
    /// Session ID.
    ///
    /// Pass this session ID when you finish the registration.
    pub session_id: String,

    /// Credential creation options.
    pub credential_creation_options: CreationChallengeResponse,
}

/// End of a session to register a new user.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishRegistrationSession {
    /// Session ID.
    ///
    /// The session ID issued when you started the registration.
    pub session_id: String,

    /// Public key credential.
    pub public_key_credential: RegisterPublicKeyCredential,
}

/// Registered user.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredUserInfo {
    /// Unique user ID issued by Passquito.
    pub user_id: String,
}

async fn function_handler<Webauthn>(
    shared_state: Arc<SharedState<Webauthn>>,
    event: LambdaEvent<serde_json::Value>,
) -> Result<serde_json::Value, ErrorResponse>
where
    Webauthn: WebauthnStartRegistration + WebauthnFinishRegistration,
{
    // parses the payload as RegistrationAction
    let (action, _) = event.into_parts();
    let action: RegistrationAction = serde_json::from_value(action)
        .map_err(|e| {
            error!("failed to parse payload: {e}");
            ErrorResponse::bad_request("invalid payload")
        })?;
    match action {
        RegistrationAction::Start(user_info) => {
            let res = start_registration(shared_state, user_info).await;
            res.and_then(|res| serde_json::to_value(res).map_err(Into::into))
        }
        RegistrationAction::StartVerified(user_info) => {
            let res = start_registration_for_verified_user(shared_state, user_info).await;
            res.and_then(|res| serde_json::to_value(res).map_err(Into::into))
        }
        RegistrationAction::Finish(session) => {
            let res = finish_registration(shared_state, session).await;
            res.and_then(|res| serde_json::to_value(res).map_err(Into::into))
        }
    }.map_err(|e| match e {
        // prevents the internal error details from being exposed to the client
        ErrorResponse::Unhandled(e) => {
            error!("{e:?}");
            "internal server error".into()
        }
        _ => e,
    })
}

async fn start_registration<Webauthn>(
    shared_state: Arc<SharedState<Webauthn>>,
    user_info: NewUserInfo,
) -> Result<StartRegistrationSession, ErrorResponse>
where
    Webauthn: WebauthnStartRegistration,
{
    info!("start_registration: {:?}", user_info);

    let user_unique_id = Uuid::new_v4();

    let (mut ccr, reg_state) = shared_state.webauthn.start_passkey_registration(
        user_unique_id,
        &user_info.username,
        &user_info.display_name,
        None,
    )?;

    // caches `reg_state`
    let user_unique_id = base64url.encode(user_unique_id.into_bytes());
    let session_id = base64url.encode(Uuid::new_v4().as_bytes());
    let ttl = DateTime::from(SystemTime::now() + shared_state.registration_timeout).secs();
    info!("putting registration session: {}", session_id);
    shared_state.dynamodb
        .put_item()
        .table_name(shared_state.session_table_name.clone())
        .item(
            "pk",
            AttributeValue::S(format!("registration#{}", session_id)),
        )
        .item("ttl", AttributeValue::N(format!("{}", ttl)))
        .item("userId", AttributeValue::S(user_unique_id))
        .item("userInfo", AttributeValue::M(HashMap::from([
            (
                "username".into(),
                AttributeValue::S(user_info.username.into()),
            ),
            (
                "displayName".into(),
                AttributeValue::S(user_info.display_name.into()),
            ),
        ])))
        .item(
            "state",
            AttributeValue::S(serde_json::to_string(&reg_state)?),
        )
        .send()
        .await
        .map_err(|e| if e.is_retryable() {
            error!("{e:?}");
            ErrorResponse::unavailable("too many requests")
        } else {
            e.into()
        })?;
    // requires a resident key
    if let Some(selection) = ccr.public_key.authenticator_selection.as_mut() {
        selection.resident_key = Some(ResidentKeyRequirement::Required);
        selection.require_resident_key = true;
    }
    Ok(StartRegistrationSession {
        session_id,
        credential_creation_options: ccr,
    })
}

async fn start_registration_for_verified_user<Webauthn>(
    shared_state: Arc<SharedState<Webauthn>>,
    user_info: VerifiedUserInfo,
) -> Result<StartRegistrationSession, ErrorResponse>
where
    Webauthn: WebauthnStartRegistration,
{
    info!("start_registration_for_verified_user: {:?}", user_info);

    // finds all the credentials associated with the user ID and
    // the exact Cognito sub
    let res = shared_state.dynamodb
        .query()
        .table_name(shared_state.credential_table_name.clone())
        .key_condition_expression("pk = :pk")
        .filter_expression("cognitoSub = :cognitoSub")
        .expression_attribute_values(
            ":pk",
            AttributeValue::S(format!("user#{}", user_info.user_id)),
        )
        .expression_attribute_values(
            ":cognitoSub",
            AttributeValue::S(user_info.cognito_sub.clone()),
        )
        .send()
        .await
        .map_err(|e| if e.is_retryable() {
            error!("{e:?}");
            ErrorResponse::unavailable("too many requests")
        } else {
            e.into()
        })?;
    if res.last_evaluated_key.is_some() {
        // TODO: list all the credentials across pages anyway?
        //       or cap the number of credentials?
        warn!("too many credentials associated with the user: {}", user_info.user_id);
    }
    let existing_credentials = res
        .items
        .ok_or_else(|| ErrorResponse::bad_request("no credentials associated with user"))?;
    if existing_credentials.is_empty() {
        return Err(ErrorResponse::bad_request("no credentials associated with user"));
    }

    // makes sure that the user exists in the Cognito user pool
    // also checks the following:
    // - the Cognito username matches the user ID
    // - the user is enabled
    // - the user status is confirmed
    let cognito_user = shared_state.cognito
        .list_users()
        .user_pool_id(shared_state.user_pool_id.clone())
        .filter(format!("sub = \"{}\"", user_info.cognito_sub)) // TODO: what if the sub contains a double quote?
        .limit(1)
        .send()
        .await
        .map_err(|e| if e.is_retryable() {
            error!("{e:?}");
            ErrorResponse::unavailable("too many requests")
        } else {
            e.into()
        })?
        .users
        .ok_or_else(|| "missing user in the Cognito user pool")?
        .pop()
        .ok_or_else(|| "missing user in the Cognito user pool")?;
    if !cognito_user.username.is_some_and(|username| username == user_info.user_id) {
        return Err("Cognito username does not match user ID".into());
    }
    if !cognito_user.enabled {
        return Err(ErrorResponse::unauthorized("Cognito user is disabled"));
    }
    if cognito_user.user_status.is_some_and(|status| status == UserStatusType::Unconfirmed) {
        return Err("uncofirmed Cognito user".into());
    }

    // decodes the user_id as a UUID
    let user_uuid = base64url.decode(&user_info.user_id)
        .map_err(|_| "malformed user ID")
        .and_then(|user_id| Uuid::from_slice(&user_id)
            .map_err(|_| "user ID must be a UUID"))?;

    let exclude_credentials: Vec<CredentialID> = existing_credentials.into_iter()
        .map(|c| {
            let id = c.get("credentialId")
                .ok_or("missing credentialId in the database")?
                .as_s()
                .or(Err("malformed credentialId in the database"))?
                .as_str();
            // as far as I know, we have to use serde::Deserialize
            // to build HumanBinaryData from a base64-encoded string
            serde_json::from_value(serde_json::Value::String(id.into()))
                .or(Err("malformed credentialId in the database"))
        })
        .collect::<Result<_, _>>()?;

    let (mut ccr, reg_state) = shared_state.webauthn.start_passkey_registration(
        user_uuid,
        &user_info.username,
        &user_info.display_name,
        Some(exclude_credentials),
    )?;

    // caches `reg_state`
    let session_id = base64url.encode(Uuid::new_v4().as_bytes());
    let ttl = DateTime::from(SystemTime::now() + shared_state.registration_timeout).secs();
    info!("putting registration session: {}", session_id);
    shared_state.dynamodb
        .put_item()
        .table_name(shared_state.session_table_name.clone())
        .item(
            "pk",
            AttributeValue::S(format!("registration#{}", session_id)),
        )
        .item("ttl", AttributeValue::N(format!("{}", ttl)))
        .item("userId", AttributeValue::S(user_info.user_id.clone()))
        .item("userInfo", AttributeValue::M(HashMap::from([
            (
                "username".into(),
                AttributeValue::S(user_info.user_info.username),
            ),
            (
                "displayName".into(),
                AttributeValue::S(user_info.user_info.display_name),
            ),
        ])))
        .item(
            "state",
            AttributeValue::S(serde_json::to_string(&reg_state)?),
        )
        .send()
        .await
        .map_err(|e| if e.is_retryable() {
            error!("{e:?}");
            ErrorResponse::unavailable("too many requests")
        } else {
            e.into()
        })?;
    // requires a resident key
    if let Some(selection) = ccr.public_key.authenticator_selection.as_mut() {
        selection.resident_key = Some(ResidentKeyRequirement::Required);
        selection.require_resident_key = true;
    }
    Ok(StartRegistrationSession {
        session_id,
        credential_creation_options: ccr,
    })
}

async fn finish_registration<Webauthn>(
    shared_state: Arc<SharedState<Webauthn>>,
    session: FinishRegistrationSession,
) -> Result<RegisteredUserInfo, ErrorResponse>
where
    Webauthn: WebauthnFinishRegistration,
{
    info!("finish_registration: {}", session.session_id);

    // TODO: this function MUST not fail, because it may become out of sync
    //       with the passkey in the user's device. but how?
    // - include an optional user ID in `FinishRegistrationSession` so that we
    //   can trace which user tried to register a new credential.
    // - back up the credential in an S3 bucket with a lifecycle policy so that
    //   it is deleted after a certain period of time.
    // - or, just log the user ID in CloudWatch Logs. if we know the user ID,
    //   the administrator can manually initiate the registration process again.
    //   (the problem is that the user ID is not obvious for the user.)

    // pops the session
    let item = shared_state.dynamodb
        .delete_item()
        .table_name(shared_state.session_table_name.clone())
        .key(
            "pk",
            AttributeValue::S(format!("registration#{}", session.session_id)),
        )
        .return_values(ReturnValue::AllOld)
        .send()
        .await?
        .attributes
        .ok_or_else(|| ErrorResponse::unauthorized("missing session"))?;

    // the session may have expired
    let ttl: i64 = item.get("ttl")
        .ok_or("missing ttl")?
        .as_n()
        .or(Err("invalid ttl"))?
        .parse()?;
    if ttl < DateTime::from(SystemTime::now()).secs() {
        return Err(ErrorResponse::unauthorized("expired session"));
    }

    // extracts the registration state
    let reg_state: PasskeyRegistration = serde_json::from_str(
        item.get("state")
            .ok_or("missing registration state")?
            .as_s()
            .or(Err("invalid state"))?,
    )?;

    // verifies the request
    let key = shared_state.webauthn.finish_passkey_registration(
        &session.public_key_credential,
        &reg_state,
    )?;
    info!("verified key: {:?}", key);

    // extracts the user information
    let user_unique_id = item.get("userId")
        .ok_or("missing userId in session")?
        .as_s()
        .or(Err("malformed userId in session"))?;
    let user_info = item.get("userInfo")
        .ok_or("missing userInfo in session")?
        .as_m()
        .or(Err("malformed userInfo in session"))?;
    let preferred_username = user_info.get("username")
        .ok_or("missing username in session")?
        .as_s()
        .or(Err("malformed username in session"))?;
    let display_name = user_info.get("displayName")
        .ok_or("missing displayName in session")?
        .as_s()
        .or(Err("malformed displayName in session"))?;
    // generates a random password that is never used
    let mut password = [0u8; 24];
    getrandom::fill(&mut password)?;
    let password = base64url.encode(&password);
    // finds the Cognito user, or creates a new Cognito user
    let cognito_user = match shared_state.cognito
        .list_users()
        .user_pool_id(shared_state.user_pool_id.clone())
        .filter(format!("username = \"{user_unique_id}\""))
        .limit(1)
        .send()
        .await?
        .users
        .and_then(|mut users| users.pop())
    {
        Some(user) => user,
        None => {
            let user = shared_state.cognito
                .admin_create_user()
                .user_pool_id(shared_state.user_pool_id.clone())
                .username(user_unique_id.clone())
                .user_attributes(UserAttributeType::builder()
                    .name("preferred_username")
                    .value(preferred_username.clone())
                    .build()
                    .unwrap())
                .user_attributes(UserAttributeType::builder()
                    .name("name")
                    .value(display_name.clone())
                    .build()
                    .unwrap())
                .message_action(MessageActionType::Suppress)
                .temporary_password(password.clone())
                .send()
                .await?
                .user
                .ok_or("failed to create a new user")?;
            info!("created a new Cognito user: {:?}", user);
            // force confirms the password
            shared_state.cognito
                .admin_set_user_password()
                .user_pool_id(shared_state.user_pool_id.clone())
                .username(user_unique_id.clone())
                .password(password)
                .permanent(true)
                .send()
                .await?;
            user
        }
    };
    let sub = cognito_user.attributes
        .ok_or("missing Cognito user attributes")?
        .into_iter()
        .find_map(|a| a.value
            .map(|v| (a.name, v))
            .filter(|(name, _)| *name == "sub")
            .map(|(_, value)| value))
        .ok_or("missing Cognito user sub attribute")?;
    info!("Cognito sub: {}", sub);
    // stores `key` in the credential table
    let credential_id = base64url.encode(key.cred_id());
    let created_at = DateTime::from(SystemTime::now())
        .fmt(DateTimeFormat::DateTime)?;
    info!("storing credential: {}", credential_id);
    let res = shared_state.dynamodb
        .put_item()
        .table_name(shared_state.credential_table_name.clone())
        .item(
            "pk",
            AttributeValue::S(format!("user#{}", user_unique_id)),
        )
        .item(
            "sk",
            AttributeValue::S(format!("credential#{}", credential_id)),
        )
        .item("credentialId", AttributeValue::S(credential_id))
        .item(
            "credential",
            AttributeValue::S(serde_json::to_string(&key)?),
        )
        .item("cognitoSub", AttributeValue::S(sub))
        .item("createdAt", AttributeValue::S(created_at.clone()))
        .item("updatedAt", AttributeValue::S(created_at))
        .send()
        .await
        .map_err(|e| if e.is_retryable() {
            ErrorResponse::unavailable("too many requests")
        } else {
            e.into()
        });
    if let Err(e) = res {
        error!("failed to store credential: {e:?}");
        shared_state.cognito
            .admin_delete_user()
            .user_pool_id(shared_state.user_pool_id.clone())
            .username(user_unique_id)
            .send()
            .await?;
        // TODO: what if deleting the user fails?
        return Err(e);
    }
    Ok(RegisteredUserInfo {
        user_id: user_unique_id.to_string(),
    })
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

/// Phase of webauthn for starting registration.
trait WebauthnStartRegistration {
    /// Initiates the registration of a new passkey.
    fn start_passkey_registration(
        &self,
        user_unique_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), WebauthnError>;
}

/// Phase of webauthn for finishing registration.
trait WebauthnFinishRegistration {
    /// Completes the registration of the passkey.
    fn finish_passkey_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, WebauthnError>;
}

impl WebauthnStartRegistration for Webauthn {
    #[inline]
    fn start_passkey_registration(
        &self,
        user_unique_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration), WebauthnError> {
        self.start_passkey_registration(
            user_unique_id,
            user_name,
            user_display_name,
            exclude_credentials,
        )
    }
}

impl WebauthnFinishRegistration for Webauthn {
    #[inline]
    fn finish_passkey_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey, WebauthnError> {
        self.finish_passkey_registration(reg, state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use aws_smithy_mocks::{mock, MockResponseInterceptor, Rule, RuleMode};

    use self::mocks::webauthn::{
        ConstantWebauthn,
        ConstantWebauthnStartRegistration,
        ConstantWebauthnFinishRegistration,
    };

    #[tokio::test]
    async fn function_handler_start_registration() {
        let cognito = MockResponseInterceptor::new();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::put_item_ok());

        let shared_state: SharedState<ConstantWebauthn> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthn::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION,
                self::mocks::webauthn::OK_PASSKEY,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let event = LambdaEvent::new(
            serde_json::json!({
                "start": {
                    "username": "test",
                    "displayName": "Test User",
                },
            }),
            lambda_runtime::Context::default(),
        );
        assert!(function_handler(shared_state, event).await.is_ok());
    }

    #[tokio::test]
    async fn function_handler_start_registration_for_verified_user() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_one());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_one_credential())
            .with_rule(&self::mocks::dynamodb::put_item_ok());

        let shared_state: SharedState<ConstantWebauthn> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthn::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let event = LambdaEvent::new(
            serde_json::json!({
                "startVerified": {
                    "username": "test",
                    "displayName": "Test User",
                    "cognitoSub": "dummy-sub-123",
                    "userId": "8TZ_kg_dp_pr0t7SDvGJiw",
                },
            }),
            lambda_runtime::Context::default(),
        );
        assert!(function_handler(shared_state, event).await.is_ok());
    }

    #[tokio::test]
    async fn function_handler_finish_registration() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_empty())
            .with_rule(&self::mocks::cognito::admin_create_user_ok())
            .with_rule(&self::mocks::cognito::admin_set_user_password_ok());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_session())
            .with_rule(&self::mocks::dynamodb::put_item_ok());

        let shared_state: SharedState<ConstantWebauthn> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthn::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION,
                self::mocks::webauthn::OK_PASSKEY,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let payload = format!(
            r#"{{
                "finish": {{
                    "sessionId": "dummy-session-id",
                    "publicKeyCredential": {}
                }}
            }}"#,
            self::mocks::webauthn::OK_REGISTER_PUBLIC_KEY_CREDENTIAL,
        );
        let event = LambdaEvent::new(
            serde_json::from_str(&payload).unwrap(),
            lambda_runtime::Context::default(),
        );
        let res = function_handler(shared_state, event).await.unwrap();
        assert_eq!(
            res,
            serde_json::json!({
                "userId": "8TZ_kg_dp_pr0t7SDvGJiw",
            })
        );
    }

    #[tokio::test]
    async fn function_handler_with_invalid_payload() {
        let cognito = MockResponseInterceptor::new();
        let dynamodb = MockResponseInterceptor::new();

        let shared_state: SharedState<ConstantWebauthn> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthn::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION,
                self::mocks::webauthn::OK_PASSKEY,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        // "start" action: invalid JSON payload
        let event = LambdaEvent::new(
            serde_json::json!({
                "start": {}
            }),
            lambda_runtime::Context::default(),
        );
        let res = function_handler(shared_state.clone(), event).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::BadRequest(_)));

        // "finish" action: invalid JSON payload
        let event = LambdaEvent::new(
            serde_json::json!({
                "finish": {}
            }),
            lambda_runtime::Context::default(),
        );
        let res = function_handler(shared_state.clone(), event).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::BadRequest(_)));

        // "unsupported" action
        let event = LambdaEvent::new(
            serde_json::json!({
                "unsupported": {}
            }),
            lambda_runtime::Context::default(),
        );
        let res = function_handler(shared_state.clone(), event).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::BadRequest(_)));
    }

    #[tokio::test]
    async fn function_handler_with_unhandled_error() {
        let cognito = MockResponseInterceptor::new();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::put_item_resource_not_found_exception())
            .with_rule(&self::mocks::dynamodb::query_resource_not_found_exception())
            .with_rule(&self::mocks::dynamodb::delete_item_resource_not_found_exception());

        let shared_state: SharedState<ConstantWebauthn> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthn::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION,
                self::mocks::webauthn::OK_PASSKEY,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        // start
        let event = LambdaEvent::new(
            serde_json::json!({
                "start": {
                    "username": "test",
                    "displayName": "Test User",
                },
            }),
            lambda_runtime::Context::default(),
        );
        let res = function_handler(shared_state.clone(), event).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unhandled(e) if e.to_string() == "internal server error"));

        // start for verified user
        let event = LambdaEvent::new(
            serde_json::json!({
                "startVerified": {
                    "username": "test",
                    "displayName": "Test User",
                    "cognitoSub": "dummy-sub-123",
                    "userId": "8TZ_kg_dp_pr0t7SDvGJiw",
                },
            }),
            lambda_runtime::Context::default(),
        );
        let res = function_handler(shared_state.clone(), event).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unhandled(e) if e.to_string() == "internal server error"));

        // finish
        let payload = format!(
            r#"{{
                "finish": {{
                    "sessionId": "dummy-session-id",
                    "publicKeyCredential": {}
                }}
            }}"#,
            self::mocks::webauthn::OK_REGISTER_PUBLIC_KEY_CREDENTIAL,
        );
        let event = LambdaEvent::new(
            serde_json::from_str(&payload).unwrap(),
            lambda_runtime::Context::default(),
        );
        let res = function_handler(shared_state.clone(), event).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unhandled(e) if e.to_string() == "internal server error"));
    }

    #[tokio::test]
    async fn start_registration_of_new_user() {
        let cognito = MockResponseInterceptor::new();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::put_item_ok());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        assert!(
            start_registration(
                shared_state,
                NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
            ).await.is_ok(),
        );
    }

    #[tokio::test]
    async fn start_registration_with_dynamodb_put_item_provisitioned_throughput_exceeded() {
        let cognito = MockResponseInterceptor::new();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::put_item_provisioned_throughput_exceeded());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration(
            shared_state,
            NewUserInfo {
                username: "test".into(),
                display_name: "Test User".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_with_dynamodb_put_item_request_limit_exceeded() {
        let cognito = MockResponseInterceptor::new();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::put_item_request_limit_exceeded());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration(
            shared_state,
            NewUserInfo {
                username: "test".into(),
                display_name: "Test User".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_with_dynamodb_put_item_service_unavailable() {
        let cognito = MockResponseInterceptor::new();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::put_item_service_unavailable());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration(
            shared_state,
            NewUserInfo {
                username: "test".into(),
                display_name: "Test User".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_with_dynamodb_put_item_throttling_exception() {
        let cognito = MockResponseInterceptor::new();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::put_item_throttling_exception());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration(
            shared_state,
            NewUserInfo {
                username: "test".into(),
                display_name: "Test User".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_existing_credential() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_one());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_one_credential())
            .with_rule(&self::mocks::dynamodb::put_item_ok());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        assert!(
            start_registration_for_verified_user(
                shared_state,
                VerifiedUserInfo {
                    user_info: NewUserInfo {
                        username: "test".into(),
                        display_name: "Test User".into(),
                    },
                    cognito_sub: "dummy-sub-123".into(),
                    user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
                },
            ).await.is_ok(),
        );
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_non_existing_credential() {
        let cognito = MockResponseInterceptor::new();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_empty_credentials());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::BadRequest(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_cognito_username_user_id_mismatch() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_one());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_one_credential());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "q8UUA6NeySf0A6JBBpM4EA".into(), // another user ID
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unhandled(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_disabled_cognito_user() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_disabled_one());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_one_credential());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unauthorized(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_unconfirmed_cognito_user() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_unconfirmed_one());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_one_credential());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unhandled(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_dynamodb_query_throughput_exceeded() {
        let cognito = MockResponseInterceptor::new();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_throughput_exceeded());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_dynamodb_query_request_limit_exceeded() {
        let cognito = MockResponseInterceptor::new();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_request_limit_exceeded());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_dynamodb_query_service_unavailable() {
        let cognito = MockResponseInterceptor::new();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_service_unavailable());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_dynamodb_query_throttling() {
        let cognito = MockResponseInterceptor::new();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_throttling_exception());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_cognito_list_users_too_many_requests() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_too_many_requests());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_one_credential());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_cognito_list_users_service_unavailable() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_service_unavailable());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_one_credential());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_cognito_list_users_throttling() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_throttling_exception());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_one_credential());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_dynamodb_put_item_provisioned_throughput_exceeded() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_one());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_one_credential())
            .with_rule(&self::mocks::dynamodb::put_item_provisioned_throughput_exceeded());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_dynamodb_put_item_request_limit_exceeded() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_one());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_one_credential())
            .with_rule(&self::mocks::dynamodb::put_item_request_limit_exceeded());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_dynamodb_put_item_service_unavailable() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_one());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_one_credential())
            .with_rule(&self::mocks::dynamodb::put_item_service_unavailable());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn start_registration_for_verified_user_with_dynamodb_put_item_throttling() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_one());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_one_credential())
            .with_rule(&self::mocks::dynamodb::put_item_throttling_exception());

        let shared_state: SharedState<ConstantWebauthnStartRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnStartRegistration::new(
                self::mocks::webauthn::OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS,
                self::mocks::webauthn::OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let err = start_registration_for_verified_user(
            shared_state,
            VerifiedUserInfo {
                user_info: NewUserInfo {
                    username: "test".into(),
                    display_name: "Test User".into(),
                },
                cognito_sub: "dummy-sub-123".into(),
                user_id: "8TZ_kg_dp_pr0t7SDvGJiw".into(),
            },
        ).await.err().unwrap();
        assert!(matches!(err, ErrorResponse::Unavailable(_)));
    }

    #[tokio::test]
    async fn finish_registration_of_legitimate_new_user() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_empty())
            .with_rule(&self::mocks::cognito::admin_create_user_ok())
            .with_rule(&self::mocks::cognito::admin_set_user_password_ok());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_session())
            .with_rule(&self::mocks::dynamodb::put_item_ok());

        let shared_state: SharedState<ConstantWebauthnFinishRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnFinishRegistration::new(
                self::mocks::webauthn::OK_PASSKEY,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = finish_registration(
            shared_state,
            FinishRegistrationSession {
                session_id: "dummy-session-id".to_string(),
                public_key_credential: serde_json::from_str(
                    self::mocks::webauthn::OK_REGISTER_PUBLIC_KEY_CREDENTIAL,
                ).unwrap(),
            },
        ).await.unwrap();
        assert_eq!(res.user_id, "8TZ_kg_dp_pr0t7SDvGJiw");
    }

    #[tokio::test]
    async fn finish_registration_of_existing_user() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_one());
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_session())
            .with_rule(&self::mocks::dynamodb::put_item_ok());

        let shared_state: SharedState<ConstantWebauthnFinishRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnFinishRegistration::new(
                self::mocks::webauthn::OK_PASSKEY,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = finish_registration(
            shared_state,
            FinishRegistrationSession {
                session_id: "dummy-session-id".to_string(),
                public_key_credential: serde_json::from_str(
                    self::mocks::webauthn::OK_REGISTER_PUBLIC_KEY_CREDENTIAL,
                ).unwrap(),
            },
        ).await.unwrap();
        assert_eq!(res.user_id, "8TZ_kg_dp_pr0t7SDvGJiw");
    }

    #[tokio::test]
    async fn finish_registration_with_missing_session() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny);
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_missing_session());

        let shared_state: SharedState<ConstantWebauthnFinishRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnFinishRegistration::new(
                self::mocks::webauthn::OK_PASSKEY,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = finish_registration(
            shared_state,
            FinishRegistrationSession {
                session_id: "dummy-session-id".to_string(),
                public_key_credential: serde_json::from_str(
                    self::mocks::webauthn::OK_REGISTER_PUBLIC_KEY_CREDENTIAL,
                ).unwrap(),
            },
        ).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unauthorized(_)));
    }

    #[tokio::test]
    async fn finish_registration_with_expired_session() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny);
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_expired_session());

        let shared_state: SharedState<ConstantWebauthnFinishRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnFinishRegistration::new(
                self::mocks::webauthn::OK_PASSKEY,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = finish_registration(
            shared_state,
            FinishRegistrationSession {
                session_id: "dummy-session-id".to_string(),
                public_key_credential: serde_json::from_str(
                    self::mocks::webauthn::OK_REGISTER_PUBLIC_KEY_CREDENTIAL,
                ).unwrap(),
            },
        ).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unauthorized(_)));
    }

    #[tokio::test]
    async fn finish_registration_with_credential_table_put_item_throughput_exceeded() {
        let admin_delete_user = self::mocks::cognito::admin_delete_user_ok();
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_empty())
            .with_rule(&self::mocks::cognito::admin_create_user_ok())
            .with_rule(&self::mocks::cognito::admin_set_user_password_ok())
            .with_rule(&admin_delete_user);
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_session())
            .with_rule(&self::mocks::dynamodb::put_item_provisioned_throughput_exceeded());

        let shared_state: SharedState<ConstantWebauthnFinishRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnFinishRegistration::new(
                self::mocks::webauthn::OK_PASSKEY,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = finish_registration(
            shared_state,
            FinishRegistrationSession {
                session_id: "dummy-session-id".to_string(),
                public_key_credential: serde_json::from_str(
                    self::mocks::webauthn::OK_REGISTER_PUBLIC_KEY_CREDENTIAL,
                ).unwrap(),
            },
        ).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unavailable(_)));
        assert_eq!(admin_delete_user.num_calls(), 1);
    }

    #[tokio::test]
    async fn finish_registration_with_credential_table_put_item_request_limit_exceeded() {
        let admin_delete_user = self::mocks::cognito::admin_delete_user_ok();
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_empty())
            .with_rule(&self::mocks::cognito::admin_create_user_ok())
            .with_rule(&self::mocks::cognito::admin_set_user_password_ok())
            .with_rule(&admin_delete_user);
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_session())
            .with_rule(&self::mocks::dynamodb::put_item_request_limit_exceeded());

        let shared_state: SharedState<ConstantWebauthnFinishRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnFinishRegistration::new(
                self::mocks::webauthn::OK_PASSKEY,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = finish_registration(
            shared_state,
            FinishRegistrationSession {
                session_id: "dummy-session-id".to_string(),
                public_key_credential: serde_json::from_str(
                    self::mocks::webauthn::OK_REGISTER_PUBLIC_KEY_CREDENTIAL,
                ).unwrap(),
            },
        ).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unavailable(_)));
        assert_eq!(admin_delete_user.num_calls(), 1);
    }

    #[tokio::test]
    async fn finish_registration_with_credential_table_put_item_service_unavailable() {
        let admin_delete_user = self::mocks::cognito::admin_delete_user_ok();
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_empty())
            .with_rule(&self::mocks::cognito::admin_create_user_ok())
            .with_rule(&self::mocks::cognito::admin_set_user_password_ok())
            .with_rule(&admin_delete_user);
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_session())
            .with_rule(&self::mocks::dynamodb::put_item_service_unavailable());

        let shared_state: SharedState<ConstantWebauthnFinishRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnFinishRegistration::new(
                self::mocks::webauthn::OK_PASSKEY,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = finish_registration(
            shared_state,
            FinishRegistrationSession {
                session_id: "dummy-session-id".to_string(),
                public_key_credential: serde_json::from_str(
                    self::mocks::webauthn::OK_REGISTER_PUBLIC_KEY_CREDENTIAL,
                ).unwrap(),
            },
        ).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unavailable(_)));
        assert_eq!(admin_delete_user.num_calls(), 1);
    }

    #[tokio::test]
    async fn finish_registration_with_credential_table_put_item_throttling_exception() {
        let admin_delete_user = self::mocks::cognito::admin_delete_user_ok();
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_empty())
            .with_rule(&self::mocks::cognito::admin_create_user_ok())
            .with_rule(&self::mocks::cognito::admin_set_user_password_ok())
            .with_rule(&admin_delete_user);
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_session())
            .with_rule(&self::mocks::dynamodb::put_item_throttling_exception());

        let shared_state: SharedState<ConstantWebauthnFinishRegistration> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnFinishRegistration::new(
                self::mocks::webauthn::OK_PASSKEY,
            ))
            .cognito(self::mocks::cognito::new_client(cognito))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = finish_registration(
            shared_state,
            FinishRegistrationSession {
                session_id: "dummy-session-id".to_string(),
                public_key_credential: serde_json::from_str(
                    self::mocks::webauthn::OK_REGISTER_PUBLIC_KEY_CREDENTIAL,
                ).unwrap(),
            },
        ).await.err().unwrap();
        assert!(matches!(res, ErrorResponse::Unavailable(_)));
        assert_eq!(admin_delete_user.num_calls(), 1);
    }

    mod mocks {
        use super::*;

        pub(crate) mod webauthn {
            use super::*;

            pub(crate) struct ConstantWebauthn {
                start: ConstantWebauthnStartRegistration,
                finish: ConstantWebauthnFinishRegistration,
            }

            impl ConstantWebauthn {
                pub(crate) fn new(
                    creation_challenge_response: impl Into<String>,
                    passkey_registration: impl Into<String>,
                    passkey: impl Into<String>,
                ) -> Self {
                    Self {
                        start: ConstantWebauthnStartRegistration::new(
                            creation_challenge_response,
                            passkey_registration,
                        ),
                        finish: ConstantWebauthnFinishRegistration::new(passkey),
                    }
                }
            }

            impl WebauthnStartRegistration for ConstantWebauthn {
                fn start_passkey_registration(
                    &self,
                    user_unique_id: Uuid,
                    user_name: &str,
                    user_display_name: &str,
                    excluded_credentials: Option<Vec<CredentialID>>,
                ) -> Result<(CreationChallengeResponse, PasskeyRegistration), WebauthnError> {
                    self.start.start_passkey_registration(
                        user_unique_id,
                        user_name,
                        user_display_name,
                        excluded_credentials,
                    )
                }
            }

            impl WebauthnFinishRegistration for ConstantWebauthn {
                fn finish_passkey_registration(
                    &self,
                    reg: &RegisterPublicKeyCredential,
                    state: &PasskeyRegistration,
                ) -> Result<Passkey, WebauthnError> {
                    self.finish.finish_passkey_registration(reg, state)
                }
            }

            pub(crate) struct ConstantWebauthnStartRegistration {
                creation_challenge_response: String,
                passkey_registration: String,
            }

            impl ConstantWebauthnStartRegistration {
                pub(crate) fn new(
                    creation_challenge_response: impl Into<String>,
                    passkey_registration: impl Into<String>,
                ) -> Self {
                    Self {
                        creation_challenge_response: creation_challenge_response.into(),
                        passkey_registration: passkey_registration.into(),
                    }
                }
            }

            impl WebauthnStartRegistration for ConstantWebauthnStartRegistration {
                fn start_passkey_registration(
                    &self,
                    _: Uuid,
                    _: &str,
                    _: &str,
                    _: Option<Vec<CredentialID>>,
                ) -> Result<(CreationChallengeResponse, PasskeyRegistration), WebauthnError> {
                    Ok((
                        serde_json::from_str(&self.creation_challenge_response).unwrap(),
                        serde_json::from_str(&self.passkey_registration).unwrap(),
                    ))
                }
            }

            pub(crate) struct ConstantWebauthnFinishRegistration {
                passkey: String,
            }

            impl ConstantWebauthnFinishRegistration {
                pub(crate) fn new(passkey: impl Into<String>) -> Self {
                    Self {
                        passkey: passkey.into(),
                    }
                }
            }

            impl WebauthnFinishRegistration for ConstantWebauthnFinishRegistration {
                fn finish_passkey_registration(
                    &self,
                    _: &RegisterPublicKeyCredential,
                    _: &PasskeyRegistration,
                ) -> Result<Passkey, WebauthnError> {
                    Ok(serde_json::from_str(&self.passkey).unwrap())
                }
            }

            pub(crate) const OK_CREATION_CHALLENGE_RESPONSE: &str = r#"{
                "publicKey": {
                    "rp": {
                        "id": "localhost",
                        "name": "Passkey Test"
                    },
                    "user": {
                        "id": "8TZ_kg_dp_pr0t7SDvGJiw",
                        "name": "test",
                        "displayName": "Test User"
                    },
                    "challenge": "fS_B1MxJouaI0QpuYtrsl6kheAAqtQlUgyAfaxOYdXE",
                    "pubKeyCredParams": [
                        {
                            "type": "public-key",
                            "alg": -7
                        },
                        {
                            "type": "public-key",
                            "alg": -8
                        }
                    ]
                }
            }"#;

            pub(crate) const OK_CREATION_CHALLENGE_RESPONSE_WITH_EXCLUDE_CREDENTIALS: &str = r#"{
                "publicKey": {
                    "rp": {
                        "id": "localhost",
                        "name": "Passkey Test"
                    },
                    "user": {
                        "id": "8TZ_kg_dp_pr0t7SDvGJiw",
                        "name": "test",
                        "displayName": "Test User"
                    },
                    "challenge": "fS_B1MxJouaI0QpuYtrsl6kheAAqtQlUgyAfaxOYdXE",
                    "pubKeyCredParams": [
                        {
                            "type": "public-key",
                            "alg": -7
                        },
                        {
                            "type": "public-key",
                            "alg": -8
                        }
                    ],
                    "exclude_credentials": [
                        {
                            "type": "public-key",
                            "id": "VD-k4AUT6FLUNmROa7OAiA"
                        }
                    ]
                }
            }"#;

            pub(crate) const OK_PASSKEY_REGISTRATION: &str = r#"{
                "rs": {
                    "policy": "required",
                    "exclude_credentials": [],
                    "challenge": "fS_B1MxJouaI0QpuYtrsl6kheAAqtQlUgyAfaxOYdXE",
                    "credential_algorithms": ["ECDSA_SHA256", "EDDSA"],
                    "require_resident_key": true,
                    "authenticator_attachment": null,
                    "extensions": {},
                    "allow_synchronised_authenticators": false
                }
            }"#;

            pub(crate) const OK_PASSKEY_REGISTRATION_WITH_EXCLUDE_CREDENTIALS: &str = r#"{
                "rs": {
                    "policy": "required",
                    "exclude_credentials": ["VD-k4AUT6FLUNmROa7OAiA"],
                    "challenge": "fS_B1MxJouaI0QpuYtrsl6kheAAqtQlUgyAfaxOYdXE",
                    "credential_algorithms": ["ECDSA_SHA256", "EDDSA"],
                    "require_resident_key": true,
                    "authenticator_attachment": null,
                    "extensions": {},
                    "allow_synchronised_authenticators": false
                }
            }"#;

            pub(crate) const OK_REGISTER_PUBLIC_KEY_CREDENTIAL: &str = r#"{
                "id": "zVgCuXz99SsFmTTo",
                "rawId": "zVgCuXz99SsFmTTo",
                "response": {
                    "attestationObject": "",
                    "clientDataJSON": ""
                },
                "type": "public-key",
                "extensions": {}
            }"#;

            pub(crate) const OK_PASSKEY: &str = r#"{
                "cred": {
                    "cred_id": "VD-k4AUT6FLUNmROa7OAiA",
                    "cred": {
                        "type_": "ES256",
                        "key": {
                            "EC_EC2": {
                                "curve": "SECP256R1",
                                "x": "",
                                "y": ""
                            }
                        }
                    },
                    "counter": 1,
                    "transports": null,
                    "user_verified": true,
                    "backup_eligible": true,
                    "backup_state": false,
                    "registration_policy": "required",
                    "extensions": {},
                    "attestation": {
                        "data": "None",
                        "metadata": "None"
                    },
                    "attestation_format": "none"
                }
            }"#;
        }

        pub(crate) mod cognito {
            use super::*;

            use aws_sdk_cognitoidentityprovider::{
                config::Region,
                operation::{
                    admin_create_user::AdminCreateUserOutput,
                    admin_delete_user::AdminDeleteUserOutput,
                    admin_set_user_password::AdminSetUserPasswordOutput,
                    list_users::ListUsersOutput,
                },
                types::{AttributeType, UserStatusType, UserType},
                Client,
                Config,
            };
            use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
            use aws_smithy_runtime_api::http::StatusCode as SmithyStatusCode;
            use aws_smithy_types::body::SdkBody;

            const TOO_MANY_REQUESTS_EXCEPTION: &str = r#"{"__type": "TooManyRequestsException", "message": "Too many requests."}"#;

            const SERVICE_UNAVAILABLE: &str = r#"{"__type": "ServiceUnavailable", "message": "Service unavailable."}"#;

            const THROTTLING_EXCEPTION: &str = r#"{"__type": "ThrottlingException", "message": "Throttled."}"#;

            pub(crate) fn new_client(mocks: MockResponseInterceptor) -> Client {
                let mock_http_client = aws_smithy_mocks::create_mock_http_client();
                Client::from_conf(
                    Config::builder()
                        .with_test_defaults()
                        .region(Region::new("ap-northeast-1"))
                        .http_client(mock_http_client)
                        .interceptor(mocks)
                        .build(),
                )
            }

            pub(crate) fn list_users_empty() -> Rule {
                mock!(Client::list_users)
                    .then_output(|| ListUsersOutput::builder().build())
            }

            pub(crate) fn list_users_one() -> Rule {
                mock!(Client::list_users)
                    .then_output(|| ListUsersOutput::builder()
                        .users(UserType::builder()
                            .enabled(true)
                            .username("8TZ_kg_dp_pr0t7SDvGJiw")
                            .attributes(AttributeType::builder()
                                .name("sub")
                                .value("dummy-sub-123")
                                .build()
                                .unwrap())
                            .attributes(AttributeType::builder()
                                .name("preferred_username")
                                .value("test")
                                .build()
                                .unwrap())
                            .build())
                        .build())
            }

            pub(crate) fn list_users_disabled_one() -> Rule {
                mock!(Client::list_users)
                    .then_output(|| ListUsersOutput::builder()
                        .users(UserType::builder()
                            .enabled(false)
                            .username("8TZ_kg_dp_pr0t7SDvGJiw")
                            .attributes(AttributeType::builder()
                                .name("sub")
                                .value("dummy-sub-123")
                                .build()
                                .unwrap())
                            .attributes(AttributeType::builder()
                                .name("preferred_username")
                                .value("test")
                                .build()
                                .unwrap())
                            .build())
                        .build())
            }

            pub(crate) fn list_users_unconfirmed_one() -> Rule {
                mock!(Client::list_users)
                    .then_output(|| ListUsersOutput::builder()
                        .users(UserType::builder()
                            .enabled(true)
                            .username("8TZ_kg_dp_pr0t7SDvGJiw")
                            .attributes(AttributeType::builder()
                                .name("sub")
                                .value("dummy-sub-123")
                                .build()
                                .unwrap())
                            .attributes(AttributeType::builder()
                                .name("preferred_username")
                                .value("test")
                                .build()
                                .unwrap())
                            .user_status(UserStatusType::Unconfirmed)
                            .build())
                        .build())
            }

            pub(crate) fn list_users_too_many_requests() -> Rule {
                mock!(Client::list_users)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(TOO_MANY_REQUESTS_EXCEPTION),
                        )
                    })
            }

            pub(crate) fn list_users_service_unavailable() -> Rule {
                mock!(Client::list_users)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(503).unwrap(),
                            SdkBody::from(SERVICE_UNAVAILABLE),
                        )
                    })
            }

            pub(crate) fn list_users_throttling_exception() -> Rule {
                mock!(Client::list_users)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(THROTTLING_EXCEPTION),
                        )
                    })
            }

            pub(crate) fn admin_create_user_ok() -> Rule {
                mock!(Client::admin_create_user)
                    .then_output(|| AdminCreateUserOutput::builder()
                        .user(UserType::builder()
                            .attributes(AttributeType::builder()
                                .name("sub")
                                .value("dummy-sub-123")
                                .build()
                                .unwrap())
                            .build())
                        .build())
            }

            pub(crate) fn admin_set_user_password_ok() -> Rule {
                mock!(Client::admin_set_user_password)
                    .then_output(|| AdminSetUserPasswordOutput::builder().build())
            }

            pub(crate) fn admin_delete_user_ok() -> Rule {
                mock!(Client::admin_delete_user)
                    .then_output(|| AdminDeleteUserOutput::builder().build())
            }
        }

        pub(crate) mod dynamodb {
            use super::*;

            use aws_sdk_dynamodb::{
                config::Region,
                operation::{
                    delete_item::DeleteItemOutput,
                    put_item::PutItemOutput,
                    query::QueryOutput,
                },
                Client,
                Config,
            };
            use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
            use aws_smithy_runtime_api::http::StatusCode as SmithyStatusCode;
            use aws_smithy_types::body::SdkBody;

            const PROVISIONED_THROUGHPUT_EXCEEDED_EXCEPTION: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ProvisionedThroughputExceededException", "message": "Exceeded provisioned throughput."}"#;

            const REQUEST_LIMIT_EXCEEDED: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#RequestLimitExceeded", "message": "Exceeded request limit."}"#;

            const SERVICE_UNAVAILABLE: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ServiceUnavailable", "message": "Service unavailable."}"#;

            const THROTTLING_EXCEPTION: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ThrottlingException", "message": "Throttled."}"#;

            const RESOURCE_NOT_FOUND_EXCEPTION: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ResourceNotFoundException", "message": "No such table."}"#;

            pub(crate) fn new_client(mocks: MockResponseInterceptor) -> Client {
                let mock_http_client = aws_smithy_mocks::create_mock_http_client();
                Client::from_conf(
                    Config::builder()
                        .with_test_defaults()
                        .region(Region::new("ap-northeast-1"))
                        .http_client(mock_http_client)
                        .interceptor(mocks)
                        .build(),
                )
            }

            pub(crate) fn put_item_ok() -> Rule {
                mock!(Client::put_item)
                    .then_output(|| PutItemOutput::builder().build())
            }

            pub(crate) fn put_item_provisioned_throughput_exceeded() -> Rule {
                mock!(Client::put_item)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(PROVISIONED_THROUGHPUT_EXCEEDED_EXCEPTION),
                        )
                    })
            }

            pub(crate) fn put_item_request_limit_exceeded() -> Rule {
                mock!(Client::put_item)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(REQUEST_LIMIT_EXCEEDED),
                        )
                    })
            }

            pub(crate) fn put_item_service_unavailable() -> Rule {
                mock!(Client::put_item)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(503).unwrap(),
                            SdkBody::from(SERVICE_UNAVAILABLE),
                        )
                    })
            }

            pub(crate) fn put_item_throttling_exception() -> Rule {
                mock!(Client::put_item)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(THROTTLING_EXCEPTION),
                        )
                    })
            }

            pub(crate) fn put_item_resource_not_found_exception() -> Rule {
                mock!(Client::put_item)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(RESOURCE_NOT_FOUND_EXCEPTION),
                        )
                    })
            }

            pub(crate) fn delete_item_session() -> Rule {
                mock!(Client::delete_item)
                    .then_output(|| {
                        let ttl = DateTime::from(SystemTime::now()).secs() + 300;
                        DeleteItemOutput::builder()
                            .attributes("ttl", AttributeValue::N(format!("{}", ttl)))
                            .attributes("state", AttributeValue::S(super::webauthn::OK_PASSKEY_REGISTRATION.to_string()))
                            .attributes("userId", AttributeValue::S("8TZ_kg_dp_pr0t7SDvGJiw".to_string()))
                            .attributes("userInfo", AttributeValue::M(HashMap::from([
                                ("username".to_string(), AttributeValue::S("test".to_string())),
                                ("displayName".to_string(), AttributeValue::S("Test User".to_string())),
                            ])))
                            .build()
                    })
            }

            pub(crate) fn delete_item_missing_session() -> Rule {
                mock!(Client::delete_item)
                    .then_output(|| DeleteItemOutput::builder().build())
            }

            pub(crate) fn delete_item_expired_session() -> Rule {
                mock!(Client::delete_item)
                    .then_output(|| {
                        let ttl = DateTime::from(SystemTime::now()).secs() - 300;
                        DeleteItemOutput::builder()
                            .attributes("ttl", AttributeValue::N(format!("{}", ttl)))
                            .build()
                    })
            }

            pub(crate) fn delete_item_resource_not_found_exception() -> Rule {
                mock!(Client::delete_item)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(RESOURCE_NOT_FOUND_EXCEPTION),
                        )
                    })
            }

            pub(crate) fn query_one_credential() -> Rule {
                mock!(Client::query)
                    .then_output(|| {
                        QueryOutput::builder()
                            .items(HashMap::from([
                                ("pk".to_string(), AttributeValue::S("user#8TZ_kg_dp_pr0t7SDvGJiw".to_string())),
                                ("sk".to_string(), AttributeValue::S("credential#VD-k4AUT6FLUNmROa7OAiA".to_string())),
                                ("credentialId".to_string(), AttributeValue::S("VD-k4AUT6FLUNmROa7OAiA".to_string())),
                                ("credential".to_string(), AttributeValue::S(webauthn::OK_PASSKEY.to_string())),
                                ("cognitoSub".to_string(), AttributeValue::S("dummy-sub-123".to_string())),
                                ("createdAt".to_string(), AttributeValue::S("2025-03-16T16:35:00.000000Z".to_string())),
                                ("updatedAt".to_string(), AttributeValue::S("2025-03-16T16:35:00.000000Z".to_string())),
                            ]))
                            .build()
                    })
            }

            pub(crate) fn query_empty_credentials() -> Rule {
                mock!(Client::query)
                    .then_output(|| QueryOutput::builder().build())
            }

            pub(crate) fn query_throughput_exceeded() -> Rule {
                mock!(Client::query)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(PROVISIONED_THROUGHPUT_EXCEEDED_EXCEPTION),
                        )
                    })
            }

            pub(crate) fn query_request_limit_exceeded() -> Rule {
                mock!(Client::query)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(REQUEST_LIMIT_EXCEEDED),
                        )
                    })
            }

            pub(crate) fn query_service_unavailable() -> Rule {
                mock!(Client::query)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(503).unwrap(),
                            SdkBody::from(SERVICE_UNAVAILABLE),
                        )
                    })
            }

            pub(crate) fn query_throttling_exception() -> Rule {
                mock!(Client::query)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(THROTTLING_EXCEPTION),
                        )
                    })
            }

            pub(crate) fn query_resource_not_found_exception() -> Rule {
                mock!(Client::query)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(RESOURCE_NOT_FOUND_EXCEPTION),
                        )
                    })
            }
        }
    }
}
