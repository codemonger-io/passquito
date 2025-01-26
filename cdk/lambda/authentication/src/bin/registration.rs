//! Registration.
//!
//! This application is intended to run as an AWS Lambda function.
//!
//! You have to configure the following environment variables:
//! - `BASE_PATH`: base path to provide the service, which must end with a
//!   trailing slash (/); e.g., `/auth/credentials/registration/`
//! - `SESSION_TABLE_NAME`: name of the DynamoDB table to store sessions
//! - `USER_POOL_ID`: ID of the Cognito user pool
//! - `CREDENTIAL_TABLE_NAME`: name of the DynamoDB table to store credentials
//! - `RP_ORIGIN_PARAMETER_PATH`: path to the parameter that stores the origin
//!   (URL) of the relying party in the Parameter Store on AWS Systems Manager
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
//! The request body must be [`FinishRegistrationSession`] as
//! `application/json`.
//! The response body is an empty text.

use aws_sdk_cognitoidentityprovider::types::{
    AttributeType as UserAttributeType,
    MessageActionType,
};
use aws_sdk_dynamodb::{
    primitives::{DateTime, DateTimeFormat},
    types::{AttributeValue, ReturnValue},
};
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE_NO_PAD as base64url},
};
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
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{error, info};
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
use webauthn_rs_proto::RegisterPublicKeyCredential;

use authentication::error_response::ErrorResponse;
use authentication::parameters::load_relying_party_origin;
use authentication::sdk_error_ext::SdkErrorExt;

// Shared state.
#[cfg_attr(test, derive(derive_builder::Builder))]
#[cfg_attr(test, builder(setter(into), pattern = "owned"))]
struct SharedState<Webauthn> {
    webauthn: Webauthn,
    cognito: aws_sdk_cognitoidentityprovider::Client,
    dynamodb: aws_sdk_dynamodb::Client,
    #[cfg_attr(test, builder(default = "\"/auth/credentials/registration\".to_string()"))]
    base_path: String,
    #[cfg_attr(test, builder(default = "\"ap-northeast-1_123456789\".to_string()"))]
    user_pool_id: String,
    #[cfg_attr(test, builder(default = "\"sessions\".to_string()"))]
    session_table_name: String,
    #[cfg_attr(test, builder(default = "\"credentials\".to_string()"))]
    credential_table_name: String,
}

impl SharedState<Webauthn> {
    async fn new() -> Result<Self, Error> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let (rp_id, rp_origin) =
            load_relying_party_origin(aws_sdk_ssm::Client::new(&config)).await?;
        let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)?
            .rp_name("Passkey Test")
            .build()?;
        let base_path = env::var("BASE_PATH")
            .or(Err("BASE_PATH env must be set"))?;
        Ok(Self {
            webauthn,
            cognito: aws_sdk_cognitoidentityprovider::Client::new(&config),
            dynamodb: aws_sdk_dynamodb::Client::new(&config),
            base_path: base_path.trim_end_matches('/').into(),
            user_pool_id: env::var("USER_POOL_ID")
                .or(Err("USER_POOL_ID env must be set"))?,
            session_table_name: env::var("SESSION_TABLE_NAME")
                .or(Err("SESSION_TABLE_NAME env must be set"))?,
            credential_table_name: env::var("CREDENTIAL_TABLE_NAME")
                .or(Err("CREDENTIAL_TABLE_NAME env must be set"))?,
        })
    }
}

/// Information on a new user.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewUserInfo {
    /// Username.
    ///
    /// When you register a new user, specify a preferred username which may
    /// identify a person.
    /// The username is not necessarily unique.
    /// It is provided for the user to locate the passkey in user's device.
    ///
    /// When you register a new credential for an existing user, specify the
    /// unique ID of the user, which was generated when the user signed up.
    pub username: String,

    /// Display name.
    ///
    /// The display name is not necessarily unique.
    /// It is provided for the user to locate the passkey in user's device.
    /// (As far as I tested, macOS did not show the display name.)
    pub display_name: String,
}

/// Beginning of a session to register a new user.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
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

async fn function_handler<Webauthn>(
    shared_state: Arc<SharedState<Webauthn>>,
    event: Request,
) -> Result<Response<Body>, Error>
where
    Webauthn: WebauthnStartRegistration + WebauthnFinishRegistration,
{
    // common parsing pattern of the payload
    macro_rules! parse_payload {
        ($event:expr, $type:ty) => {
            $event
                .payload::<$type>()
                .map_err(|e| {
                    error!("failed to parse payload: {e}");
                    ErrorResponse::bad_request("invalid payload")
                })
                .and_then(|payload| {
                    payload.ok_or_else(|| {
                        ErrorResponse::bad_request("invalid payload")
                    })
                })
        };
    }

    let job_path = event.raw_http_path()
        .strip_prefix(&shared_state.base_path)
        .ok_or_else(|| {
            error!("path must start with \"{}\"", shared_state.base_path);
            ErrorResponse::bad_request("bad request")
        });
    let res = match job_path {
        Ok(p) if p == "/start" => {
            match parse_payload!(event, NewUserInfo) {
                Ok(user_info) => start_registration(shared_state, user_info).await,
                Err(e) => Err(e),
            }
        }
        Ok(p) if p == "/finish" => {
            match parse_payload!(event, FinishRegistrationSession) {
                Ok(session) => finish_registration(shared_state, session).await,
                Err(e) => Err(e),
            }
        }
        Ok(p) => {
            error!("unsupported job path: {}", p);
            Err(ErrorResponse::bad_request("bad request"))
        }
        Err(e) => Err(e),
    };
    match res {
        Ok(res) => Ok(res),
        Err(res) => res.try_into(),
    }
}

async fn start_registration<Webauthn>(
    shared_state: Arc<SharedState<Webauthn>>,
    user_info: NewUserInfo,
) -> Result<Response<Body>, ErrorResponse>
where
    Webauthn: WebauthnStartRegistration,
{
    info!("start_registration: {:?}", user_info);

    // resolves the existing user
    let existing_user = shared_state.cognito
        .list_users()
        .user_pool_id(shared_state.user_pool_id.clone())
        .attributes_to_get("username")
        .filter(format!("username = \"{}\"", user_info.username))
        .limit(1)
        .send()
        .await?
        .users
        .unwrap_or_default()
        .pop();

    // obtains the user ID or generates a new one for a new user
    let user_unique_id = existing_user.as_ref()
        .map(|u| u.username.as_ref()
            .ok_or("missing username in user pool"))
        .transpose()?
        .map(|username| base64url.decode(username)
            .or(Err("malformed username in user pool"))
            .and_then(|id| Uuid::from_slice(&id)
                .or(Err("malformed username in user pool"))))
        .transpose()?
        .unwrap_or_else(Uuid::new_v4);

    // lists existing credentials for the user to be excluded
    let exclude_credentials: Option<Vec<CredentialID>> =
        match existing_user.as_ref()
    {
        Some(user) => {
            let username = user.username.as_ref().unwrap();
            info!("listing credentials for {}", username);
            let credentials = shared_state.dynamodb
                .query()
                .table_name(shared_state.credential_table_name.clone())
                .key_condition_expression("pk = :pk")
                .expression_attribute_values(":pk", AttributeValue::S(
                    format!("user#{}", username),
                ))
                .send()
                .await?
                .items
                .unwrap_or_default();
            Some(
                credentials.into_iter()
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
                    .collect::<Result<_, _>>()?,
            )
        }
        None => None,
    };

    let res = match shared_state.webauthn.start_passkey_registration(
        user_unique_id,
        &user_info.username,
        &user_info.display_name,
        exclude_credentials,
    ) {
        Ok((mut ccr, reg_state)) => {
            // caches `reg_state`
            let user_unique_id = base64url.encode(user_unique_id.into_bytes());
            let session_id = base64url.encode(Uuid::new_v4().as_bytes());
            let ttl = DateTime::from(SystemTime::now()).secs() + 60;
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
                .await?;
            // requires a resident key
            if let Some(selection) = ccr.public_key.authenticator_selection.as_mut() {
                selection.require_resident_key = true;
            }
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
        // TODO: no need for this after giving up the proxy integration
        .header("Access-Control-Allow-Origin", "*")
        .body(res.into())?)
}

async fn finish_registration<Webauthn>(
    shared_state: Arc<SharedState<Webauthn>>,
    session: FinishRegistrationSession,
) -> Result<Response<Body>, ErrorResponse>
where
    Webauthn: WebauthnFinishRegistration,
{
    info!("finish_registration: {}", session.session_id);

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
    match shared_state.webauthn.finish_passkey_registration(
        &session.public_key_credential,
        &reg_state,
    ) {
        Ok(key) => {
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
            let username = user_info.get("username")
                .ok_or("missing username in session")?
                .as_s()
                .or(Err("malformed username in session"))?;
            let display_name = user_info.get("displayName")
                .ok_or("missing displayName in session")?
                .as_s()
                .or(Err("malformed displayName in session"))?;
            // generates a random password that is never used
            let mut password = [0u8; 24];
            getrandom::getrandom(&mut password)?;
            let password = base64url.encode(&password);
            // creates the Cognito user if not exists
            // TODO: what if the user exists?
            let cognito_user = shared_state.cognito
                .admin_create_user()
                .user_pool_id(shared_state.user_pool_id.clone())
                .username(user_unique_id.clone())
                .user_attributes(UserAttributeType::builder()
                    .name("preferred_username")
                    .value(username.clone())
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
            let sub = cognito_user.attributes
                .ok_or("missing Cognito user attributes")?
                .into_iter()
                .find_map(|a| a.value
                    .map(|v| (a.name, v))
                    .filter(|(name, _)| *name == "sub")
                    .map(|(_, value)| value))
                .ok_or("missing Cognito user sub attribute")?;
            info!("created Cognito user: {}", sub);
            // force-confirms the password
            shared_state.cognito
                .admin_set_user_password()
                .user_pool_id(shared_state.user_pool_id.clone())
                .username(user_unique_id.clone())
                .password(password)
                .permanent(true)
                .send()
                .await?;
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
        }
        Err(e) => {
            error!("failed to finish registration: {}", e);
            return Err("failed to finish registration".into());
        }
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain")
        // TODO: no need for this after giving up the proxy integration
        .header("Access-Control-Allow-Origin", "*")
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

    use aws_smithy_mocks_experimental::{mock, MockResponseInterceptor, Rule, RuleMode};
    use lambda_http::http;

    use self::mocks::webauthn::{
        ConstantWebauthn,
        ConstantWebauthnStartRegistration,
        ConstantWebauthnFinishRegistration,
    };

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

        // "/start" action
        // - no payload
        let mut request = Request::default()
            .with_raw_http_path("/auth/credentials/registration/start");
        *request.method_mut() = http::Method::POST;
        request.headers_mut().insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
        let res = function_handler(shared_state.clone(), request).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        // - invalid JSON payload
        let mut request = Request::default()
            .with_raw_http_path("/auth/credentials/registration/start");
        *request.method_mut() = http::Method::POST;
        *request.body_mut() = r#"{"invalidField":null}"#.into();
        request.headers_mut().insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
        let res = function_handler(shared_state.clone(), request).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        // - bad Content-Type
        let mut request = Request::default()
            .with_raw_http_path("/auth/credentials/registration/start");
        *request.method_mut() = http::Method::POST;
        *request.body_mut() = r#"{"username":"test","displayName":"Test User"}"#.into();
        request.headers_mut().insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        let res = function_handler(shared_state.clone(), request).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // "/finish" action
        // - no payload
        let mut request = Request::default()
            .with_raw_http_path("/auth/credentials/registration/finish");
        *request.method_mut() = http::Method::POST;
        request.headers_mut().insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
        let res = function_handler(shared_state.clone(), request).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        // - invalid JSON payload
        let mut request = Request::default()
            .with_raw_http_path("/auth/credentials/registration/finish");
        *request.method_mut() = http::Method::POST;
        *request.body_mut() = r#"{"invalidField":null}"#.into();
        request.headers_mut().insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
        let res = function_handler(shared_state.clone(), request).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        // - bad Content-Type
        let mut request = Request::default()
            .with_raw_http_path("/auth/credentials/registration/finish");
        *request.method_mut() = http::Method::POST;
        *request.body_mut() = r#"{
            "sessionId": "dummy-session-id",
            "publicKeyCredential": {
                "id": "zVgCuXz99SsFmTTo",
                "rawId": "zVgCuXz99SsFmTTo",
                "response": {
                    "attestationObject": "",
                    "clientDataJSON": ""
                },
                "type": "public-key",
                "extensions": {}
            }
        }"#.into();
        request.headers_mut().insert(http::header::CONTENT_TYPE, "text/plain".parse().unwrap());
        let res = function_handler(shared_state.clone(), request).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn function_handler_with_invalid_path() {
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

        // not starting with the prefix
        let mut request = Request::default()
            .with_raw_http_path("/passkey/registration/start");
        *request.method_mut() = http::Method::POST;
        *request.body_mut() = r#"{"username":"test","displayName":"Test User"}"#.into();
        request.headers_mut().insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
        let res = function_handler(shared_state.clone(), request).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // unsupported action
        let mut request = Request::default()
            .with_raw_http_path("/auth/credentials/registration/cancel");
        *request.method_mut() = http::Method::POST;
        *request.body_mut() = r#"{"username":"test","displayName":"Test User"}"#.into();
        request.headers_mut().insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
        let res = function_handler(shared_state.clone(), request).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn start_registration_of_new_user() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::cognito::list_users_empty());
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

        let res = start_registration(
            shared_state,
            NewUserInfo {
                username: "test".into(),
                display_name: "Test User".into(),
            },
        ).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(serde_json::from_slice::<StartRegistrationSession>(res.body()).is_ok());
    }

    #[tokio::test]
    async fn finish_registration_of_legitimate_user() {
        let cognito = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
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
        assert_eq!(res.status(), StatusCode::OK);
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
            .with_rule(&self::mocks::cognito::admin_create_user_ok())
            .with_rule(&self::mocks::cognito::admin_set_user_password_ok())
            .with_rule(&admin_delete_user);
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_session())
            .with_rule(&self::mocks::dynamodb::put_item_throughput_exceeded());

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
                types::{AttributeType, UserType},
                Client,
                Config,
            };

            pub(crate) fn new_client(mocks: MockResponseInterceptor) -> Client {
                Client::from_conf(
                    Config::builder()
                        .with_test_defaults()
                        .region(Region::new("ap-northeast-1"))
                        .interceptor(mocks)
                        .build(),
                )
            }

            pub(crate) fn list_users_empty() -> Rule {
                mock!(Client::list_users)
                    .then_output(|| ListUsersOutput::builder().build())
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
                operation::delete_item::DeleteItemOutput,
                operation::put_item::PutItemOutput,
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

            pub(crate) fn new_client(mocks: MockResponseInterceptor) -> Client {
                Client::from_conf(
                    Config::builder()
                        .with_test_defaults()
                        .region(Region::new("ap-northeast-1"))
                        .interceptor(mocks)
                        .build(),
                )
            }

            pub(crate) fn put_item_ok() -> Rule {
                mock!(Client::put_item)
                    .then_output(|| PutItemOutput::builder().build())
            }

            pub(crate) fn put_item_throughput_exceeded() -> Rule {
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

            pub(crate) fn delete_item_session() -> Rule {
                mock!(Client::delete_item)
                    .then_output(|| {
                        let ttl = DateTime::from(SystemTime::now()).secs() + 60;
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
                        let ttl = DateTime::from(SystemTime::now()).secs() - 60;
                        DeleteItemOutput::builder()
                            .attributes("ttl", AttributeValue::N(format!("{}", ttl)))
                            .build()
                    })
            }
        }
    }
}
