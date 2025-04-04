//! Cognito Lambda trigger for the custom challenges with passkeys.
//!
//! You have to configure the following environment variables:
//! - `SESSION_TABLE_NAME`: name of the DynamoDB table that manages sessions
//! - `CREDENTIAL_TABLE_NAME`: name of the DynamoDB table that manages
//!   credentials
//! - `RP_ORIGIN_PARAMETER_PATH`: path to the parameter that stores the origin
//!   (URL) of the relying party in Parameter Store on AWS Systems Manager
//!
//! You may configure the following environment variable:
//! - `AUTHENTICATION_TIMEOUT_IN_MILLIS`: timeout for authentication in
//!   milliseconds. 300,000 ms (5 minutes) by default, which is the [lower bound
//!   recommended in the WebAuthn specification](https://www.w3.org/TR/webauthn-3/#sctn-timeout-recommended-range).

use aws_lambda_events::event::cognito::{
    CognitoEventUserPoolsCreateAuthChallenge,
    CognitoEventUserPoolsDefineAuthChallenge,
    CognitoEventUserPoolsVerifyAuthChallenge,
};
use aws_sdk_dynamodb::{
    primitives::{DateTime, DateTimeFormat},
    types::{AttributeValue, ReturnValue},
};
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE_NO_PAD as base64url},
};
use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use ring::digest;
use std::env;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{error, info};
use webauthn_rs::{
    Webauthn,
    WebauthnBuilder,
    prelude::{
        AuthenticationResult,
        DiscoverableAuthentication,
        DiscoverableKey,
        Passkey,
        PasskeyAuthentication,
        RequestChallengeResponse,
        WebauthnError,
    },
};
use webauthn_rs_proto::{
    CollectedClientData,
    auth::{PublicKeyCredential, PublicKeyCredentialRequestOptions},
    options::{AllowCredentials, UserVerificationPolicy},
};

use authentication::event::{
    CognitoChallengeEvent,
    CognitoChallengeEventCase,
    CognitoEventUserPoolsCreateAuthChallengeOps,
    CognitoEventUserPoolsDefineAuthChallengeOps,
    CognitoEventUserPoolsVerifyAuthChallengeOps,
};
use authentication::parameters::load_relying_party_origin;

// TODO: move to the library module
const CHALLENGE_PARAMETER_NAME: &str = "passkeyTestChallenge";

const DEFAULT_AUTHENTICATION_TIMEOUT_IN_MILLIS: &str = "300000";

// State shared among Lambda invocations.
#[cfg_attr(test, derive(derive_builder::Builder))]
#[cfg_attr(test, builder(setter(into), pattern = "owned"))]
struct SharedState<Webauthn> {
    webauthn: Webauthn,
    #[cfg_attr(test, builder(default = "\"localhost\".to_string()"))]
    rp_id: String, // no interface to get the relying party ID from `Webauthn`
    dynamodb: aws_sdk_dynamodb::Client,
    #[cfg_attr(test, builder(default = "\"sessions\".to_string()"))]
    session_table_name: String,
    #[cfg_attr(test, builder(default = "\"credentials\".to_string()"))]
    credential_table_name: String,
    #[cfg_attr(test, builder(default = "DEFAULT_AUTHENTICATION_TIMEOUT_IN_MILLIS.parse().map(Duration::from_millis).unwrap()"))]
    authentication_timeout: Duration,
}

impl SharedState<Webauthn> {
    async fn new() -> Result<Self, Error> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let (rp_id, rp_origin) =
            load_relying_party_origin(aws_sdk_ssm::Client::new(&config)).await?;
        let authentication_timeout = env::var("AUTHENTICATION_TIMEOUT_IN_MILLIS")
            .unwrap_or_else(|_| DEFAULT_AUTHENTICATION_TIMEOUT_IN_MILLIS.to_string())
            .parse()
            .map(Duration::from_millis)
            .map_err(|_| "AUTHENTICATION_TIMEOUT_IN_MILLIS must be an integer or omitted")?;
        let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)?
            .rp_name("Passkey Test")
            .timeout(authentication_timeout.clone())
            .build()?;
        Ok(Self {
            webauthn,
            rp_id: rp_id.to_string(),
            dynamodb: aws_sdk_dynamodb::Client::new(&config),
            session_table_name: env::var("SESSION_TABLE_NAME")
                .or(Err("SESSION_TABLE_NAME env must be set"))?,
            credential_table_name: env::var("CREDENTIAL_TABLE_NAME")
                .or(Err("CREDENTIAL_TABLE_NAME env must be set"))?,
            authentication_timeout,
        })
    }
}

async fn function_handler<Webauthn>(
    shared_state: Arc<SharedState<Webauthn>>,
    event: LambdaEvent<CognitoChallengeEvent>,
) -> Result<CognitoChallengeEvent, Error>
where
    Webauthn: WebauthnCreateAuthChallenge + WebauthnVerifyAuthChallenge,
{
    let (event, _) = event.into_parts();
    match event.determine() {
        Ok(CognitoChallengeEventCase::Define(event)) =>
            define_auth_challenge(shared_state, event).await.map(Into::into),
        Ok(CognitoChallengeEventCase::Create(event)) =>
            create_auth_challenge(shared_state, event).await.map(Into::into),
        Ok(CognitoChallengeEventCase::Verify(event)) =>
            verify_auth_challenge(shared_state, event).await.map(Into::into),
        Err(e) => {
            Err(format!("invalid Cognito challenge event: {}", e).into())
        }
    }.map_err(|e| {
        // never exposes the error message to the client, because it might
        // contain sensitive information. logs it and returns a generic error
        // message instead.
        error!("{e:?}");
        "Internal Server Error".into()
    })
}

// Handles "Define auth challenge" events.
async fn define_auth_challenge<Webauthn>(
    _shared_state: Arc<SharedState<Webauthn>>,
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
async fn create_auth_challenge<Webauthn>(
    shared_state: Arc<SharedState<Webauthn>>,
    mut event: CognitoEventUserPoolsCreateAuthChallenge,
) -> Result<CognitoEventUserPoolsCreateAuthChallenge, Error>
where
    Webauthn: WebauthnCreateAuthChallenge,
{
    info!("create_auth_challenge: {:?}", event);
    if event.sessions().is_empty() {
        let username = event.cognito_event_user_pools_header.user_name
            .as_ref()
            .ok_or("missing username in Cognito trigger")?;
        if event.user_exists() {
            // lists credentials of the user
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
                .unwrap_or_default();
            let credentials: Vec<&String> = credentials.iter()
                .map(|c| c.get("credential")
                    .ok_or("missing credential in the database")?
                    .as_s()
                    .or(Err("malformed credential in the database")))
                .collect::<Result<Vec<_>, _>>()?;
            let passkeys: Vec<Passkey> = credentials.into_iter()
                .map(|c| serde_json::from_str(c)
                    .or(Err("malformed credential in the database")))
                .collect::<Result<Vec<_>, _>>()?;
            // what if there is no credential?
            // the subsequent `start_passkey_authentication` fails

            // starts authentication
            match shared_state.webauthn
                .start_passkey_authentication(&passkeys)
            {
                Ok((rcr, auth_state)) => {
                    event.set_challenge_metadata("PASSKEY_TEST_CHALLENGE");
                    event.set_public_challenge_parameter(
                        CHALLENGE_PARAMETER_NAME,
                        &rcr,
                    )?;
                    event.set_private_challenge_parameter(
                        CHALLENGE_PARAMETER_NAME,
                        &auth_state,
                    )?;
                }
                Err(e) => {
                    error!("failed to start authentication: {}", e);
                    // handles this as an "Internal Server Error"
                    // TODO: does this benefit the attacker?
                    return Err(format!("failed to start authentication: {}", e).into());
                }
            }
        } else {
            info!("non existing user");
            // not to allow an attacker to know if the user does not exist,
            // we generate a challene with a fake credential ID. the fake
            // credential ID must be deterministic reagarding the username,
            // because the attacker might notice if the credential ID for the
            // same username varied over time.
            //
            // generates 160 bits (20 bytes) fake credential ID from username
            // TODO: secret salt
            let mut hash = ring::digest::Context::new(&digest::SHA256);
            hash.update(b"TODO: replace this with a secret salt!!!");
            hash.update(username.as_bytes());
            let hash = hash.finish();
            let mut credential_id: Vec<u8> = Vec::with_capacity(20);
            credential_id.extend_from_slice(&hash.as_ref()[0..20]);
            let mut challenge = vec![0u8; 32];
            getrandom::getrandom(&mut challenge)?;
            let rcr = RequestChallengeResponse {
                public_key: PublicKeyCredentialRequestOptions {
                    rp_id: shared_state.rp_id.clone(),
                    challenge: challenge.into(),
                    allow_credentials: vec![AllowCredentials {
                        type_: "public-key".into(),
                        id: credential_id.into(),
                        transports: None,
                    }],
                    user_verification: UserVerificationPolicy::Preferred,
                    timeout: Some(shared_state.authentication_timeout.as_millis().try_into()?),
                    hints: None, // TODO: client-device?
                    extensions: None,
                },
                mediation: None,
            };
            event.set_challenge_metadata("PASSKEY_TEST_CHALLENGE");
            event.set_public_challenge_parameter(
                CHALLENGE_PARAMETER_NAME,
                &rcr,
            )?;
            event.set_private_challenge_parameter(
                CHALLENGE_PARAMETER_NAME,
                "",
            )?;
        }
        Ok(event)
    } else {
        Err("no further challenges".into())
    }
}

// Handles "Verify auth challenge" events.
async fn verify_auth_challenge<Webauthn>(
    shared_state: Arc<SharedState<Webauthn>>,
    mut event: CognitoEventUserPoolsVerifyAuthChallenge,
) -> Result<CognitoEventUserPoolsVerifyAuthChallenge, Error>
where
    Webauthn: WebauthnVerifyAuthChallenge,
{
    info!("verify_auth_challenge: {:?}", event);

    let user_handle = event.cognito_event_user_pools_header.user_name.as_ref()
        .ok_or("missing username in request")?;
    let credential: PublicKeyCredential = match event.get_challenge_answer() {
        Ok(credential) => credential,
        Err(_) => {
            // rejects the request instead of returning an error, because this
            // is a client error
            error!(
                "malformed challenge answer: {:?}",
                event.get_raw_challenge_answer(),
            );
            event.reject();
            return Ok(event);
        }
    };

    // extracts the user handle from `credential`
    // it must match `user_name` (user unique ID) in the event
    let cred_user_handle = credential.response.user_handle.as_ref()
        .map(|h| base64url.encode(h))
        .ok_or("missing user handle in credential")?;
    if user_handle != &cred_user_handle {
        // rejects the request instead of returning an error, because this
        // should be a client error (really?)
        error!("user handle mismatch: {} vs {}", user_handle, cred_user_handle);
        event.reject();
        return Ok(event);
    }

    // extracts the challenge from `credential`
    // https://github.com/kanidm/webauthn-rs/blob/0ff6b525d428b5155243a37e1672c1e3205d41e8/webauthn-rs-core/src/core.rs#L702-L705
    // https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorResponse/clientDataJSON#type
    //
    // rejects the request if the client data JSON is bad; i.e.,
    // - cannot be deserialized as `CollectedClientData`
    // - has a type other than "webauthn.get"
    //
    // never returns an error, because the above inputs are client errors
    let client_challenge = serde_json::from_slice(credential.response.client_data_json.as_ref())
        .map_err(|e| format!("malformed client data: {}", e))
        .and_then(|client_data: CollectedClientData| {
            if client_data.type_ == "webauthn.get" {
                Ok(client_data)
            } else {
                Err(format!("invalid client data type: {}", client_data.type_))
            }
        })
        .map(|client_data| client_data.challenge);
    let client_challenge = match client_challenge {
        Ok(client_challenge) => client_challenge,
        Err(e) => {
            error!("{}", e);
            event.reject();
            return Ok(event);
        }
    };

    // obtains the session corresponding to the challenge
    // TODO: we want to save DynamoDB access by first checking if the challenge
    //       was made by InitiateAuth, but we are not allowed to access the
    //       challenge data in PasskeyAuthentication. maybe we can extract it
    //       by serializing PasskeyAuthentication as serde_json::Value
    let session = shared_state.dynamodb
        .delete_item()
        .table_name(shared_state.session_table_name.clone())
        .key(
            "pk",
            AttributeValue::S(format!("discoverable#{}", base64url.encode(client_challenge))),
        )
        .return_values(ReturnValue::AllOld)
        .send()
        .await?
        .attributes;
    if let Some(session) = session {
        info!("client-side discoverable credential");
        // session may have expired
        let ttl: i64 = session.get("ttl")
            .ok_or("missing ttl")?
            .as_n()
            .or(Err("malformed ttl"))?
            .parse()?;
        if ttl < DateTime::from(SystemTime::now()).secs() {
            // rejects the request instead of returning an error, because an
            // expired session should be a client error
            error!("session expired");
            event.reject();
            return Ok(event);
        }
        let auth_state = session.get("state")
            .ok_or("missing authentication state")?
            .as_s()
            .or(Err("malformed authentication state"))?;
        let auth_state: DiscoverableAuthentication =
            serde_json::from_str(&auth_state)?;

        // obtains the credentials (passkeys) associated with the user
        let credentials = shared_state.dynamodb
            .query()
            .table_name(shared_state.credential_table_name.clone())
            .key_condition_expression("pk = :pk")
            .expression_attribute_values(
                ":pk",
                AttributeValue::S(format!("user#{}", user_handle)),
            )
            .send()
            .await?
            .items
            .ok_or("no credentials")?;
        let credentials: Vec<&String> = credentials.iter()
            .map(|c| c.get("credential")
                .ok_or("missing credential")?
                .as_s()
                .or(Err("malformed credential")))
            .collect::<Result<Vec<_>, _>>()?;
        let mut passkeys: Vec<Passkey> = credentials.into_iter()
            .map(|c| serde_json::from_str::<Passkey>(c)
                .or(Err("malformed credential")))
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
            Ok(auth_result) if auth_result.user_verified() => {
                // updates the stored credential if necessary
                for passkey in passkeys.iter_mut() {
                    let credential_id = base64url.encode(passkey.cred_id());
                    info!("checking credential updates: {}", credential_id);
                    let updated_at = DateTime::from(SystemTime::now())
                        .fmt(DateTimeFormat::DateTime)?;
                    if passkey.update_credential(&auth_result)
                        .is_some_and(|b| b)
                    {
                        info!("updating credential: {}", credential_id);
                        // As per https://www.w3.org/TR/webauthn-3/#sctn-sign-counter,
                        // we must make sure that the counter is greater than
                        // the stored one unless it is zero. this check has
                        // already been done in
                        // `finish_discoverable_authentication`:
                        // https://github.com/kanidm/webauthn-rs/blob/8c2d2bdff441f5eea885371cff81e73c97f490a8/webauthn-rs-core/src/core.rs#L1158-L1177
                        let res = shared_state.dynamodb
                            .update_item()
                            .table_name(
                                shared_state.credential_table_name.clone(),
                            )
                            .key("pk", AttributeValue::S(
                                format!("user#{}", user_handle),
                            ))
                            .key(
                                "sk",
                                AttributeValue::S(
                                    format!("credential#{}", credential_id),
                                ),
                            )
                            .update_expression("SET credential = :credential, updatedAt = :updatedAt")
                            .expression_attribute_values(
                                ":credential",
                                AttributeValue::S(
                                    serde_json::to_string(passkey)?,
                                ),
                            )
                            .expression_attribute_values(
                                ":updatedAt",
                                AttributeValue::S(updated_at),
                            )
                            .condition_expression("attributes_exists(pk)")
                            .return_values(ReturnValue::None)
                            .send()
                            .await;
                        // tolerates the failure to update
                        // TODO: this might allow an attacker slight chance to
                        //       use a cloned authenticator
                        if let Err(e) = res {
                            error!("failed to update credential: {}", e);
                        }
                    }
                }
                event.accept();
            }
            Ok(_) => {
                error!("token verified but user not verified");
                event.reject();
            }
            Err(e) => {
                error!("authentication failed: {}", e);
                event.reject();
            }
        };
    } else {
        info!("Cognito initiated challenge");
        // Q. Should we make sure that `credential` is actually in our
        //    credential store?
        // A. I do not think so. Because `auth_state` should retain the
        //    list of credentials we offered to the challenger from the create
        //    auth challenge trigger.

        // challenge offered by InitiateAuth
        let auth_state: PasskeyAuthentication = event
            .get_private_challenge_parameter(CHALLENGE_PARAMETER_NAME)?
            .ok_or("missing private challenge parameter")?;
        match shared_state.webauthn.finish_passkey_authentication(
            &credential,
            &auth_state,
        ) {
            Ok(auth_result) if auth_result.user_verified() => {
                // updates the stored credential if necessary
                let credential_item = shared_state.dynamodb
                    .get_item()
                    .table_name(shared_state.credential_table_name.clone())
                    .key(
                        "pk",
                        AttributeValue::S(format!("user#{}", user_handle)),
                    )
                    .key("sk", AttributeValue::S(
                        format!("credential#{}", base64url.encode(auth_result.cred_id())),
                    ))
                    .send()
                    .await?
                    .item
                    .ok_or("missing credential in the database")?;
                let passkey = credential_item.get("credential")
                    .ok_or("malformed credential in the database")?
                    .as_s()
                    .or(Err("malformed credential in the database"))?;
                let mut passkey: Passkey = serde_json::from_str(passkey)
                    .or(Err("malformed credential in the database"))?;
                if passkey.update_credential(&auth_result).is_some_and(|b| b) {
                    info!("updating credential: {:?}", auth_result.cred_id());
                    // As per https://www.w3.org/TR/webauthn-3/#sctn-sign-counter,
                    // we must make sure that the counter is greater than
                    // the stored one unless it is zero. this check has already
                    // been done in `finish_passkey_authentication`:
                    // https://github.com/kanidm/webauthn-rs/blob/8c2d2bdff441f5eea885371cff81e73c97f490a8/webauthn-rs-core/src/core.rs#L1158-L1177
                    let updated_at = DateTime::from(SystemTime::now())
                        .fmt(DateTimeFormat::DateTime)?;
                    let res = shared_state.dynamodb
                        .update_item()
                        .table_name(
                            shared_state.credential_table_name.clone(),
                        )
                        .key(
                            "pk",
                            AttributeValue::S(format!("user#{}", user_handle)),
                        )
                        .key(
                            "sk",
                            AttributeValue::S(
                                format!("credential#{}", base64url.encode(auth_result.cred_id())),
                            ),
                        )
                        .update_expression("SET credential = :credential, updatedAt = :updateAt")
                        .expression_attribute_values(
                            ":credential",
                            AttributeValue::S(
                                serde_json::to_string(&passkey)?,
                            ),
                        )
                        .expression_attribute_values(
                            ":updatedAt",
                            AttributeValue::S(updated_at),
                        )
                        .condition_expression("attributes_exists(pk)")
                        .return_values(ReturnValue::None)
                        .send()
                        .await;
                    // tolerates the failure to update
                    // TODO: this might allow an attacker slight chance to
                    //       use a cloned authenticator
                    if let Err(e) = res {
                        error!("failed to update credential: {}", e);
                    }
                }
                event.accept();
            }
            Ok(_) => {
                error!("token verified but user not verified");
                event.reject();
            }
            Err(e) => {
                error!("authentication failed: {}", e);
                event.reject();
            }
        };
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

    let shared_state = Arc::new(SharedState::new().await?);
    run(service_fn(|req| async {
        function_handler(shared_state.clone(), req).await
    })).await
}

/// Phase of webauthn for creating a custom auth challenge.
trait WebauthnCreateAuthChallenge {
    fn start_passkey_authentication(
        self: &Self,
        creds: &[Passkey],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), WebauthnError>;
}

/// Phase of webauthn for verifying a custom auth challenge.
trait WebauthnVerifyAuthChallenge {
    fn finish_discoverable_authentication(
        self: &Self,
        reg: &PublicKeyCredential,
        state: DiscoverableAuthentication,
        creds: &[DiscoverableKey],
    ) -> Result<AuthenticationResult, WebauthnError>;

    fn finish_passkey_authentication(
        self: &Self,
        reg: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult, WebauthnError>;
}

impl WebauthnCreateAuthChallenge for Webauthn {
    #[inline]
    fn start_passkey_authentication(
        self: &Self,
        creds: &[Passkey],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), WebauthnError> {
        self.start_passkey_authentication(creds)
    }
}

impl WebauthnVerifyAuthChallenge for Webauthn {
    #[inline]
    fn finish_discoverable_authentication(
        self: &Self,
        reg: &PublicKeyCredential,
        state: DiscoverableAuthentication,
        creds: &[DiscoverableKey],
    ) -> Result<AuthenticationResult, WebauthnError> {
        self.finish_discoverable_authentication(reg, state, creds)
    }

    #[inline]
    fn finish_passkey_authentication(
        self: &Self,
        reg: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult, WebauthnError> {
        self.finish_passkey_authentication(reg, state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use aws_lambda_events::event::cognito::CognitoEventUserPoolsChallengeResult;
    use aws_smithy_mocks_experimental::{mock, MockResponseInterceptor, Rule, RuleMode};
    use std::collections::HashMap;

    use self::mocks::webauthn::{
        ConstantWebauthnCreateAuthChallenge,
        ConstantWebauthnVerifyAuthChallenge,
        NoCredentialWebauthnCreateAuthChallenge,
        RejectingWebauthn,
        RejectingWebauthnVerifyAuthChallenge,
    };

    #[tokio::test]
    async fn function_handler_hiding_error_details() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_table_not_found())
            .with_rule(&self::mocks::dynamodb::delete_item_table_not_found());

        let shared_state: SharedState<RejectingWebauthn> = SharedStateBuilder::default()
            .webauthn(RejectingWebauthn)
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        // create_auth_challenge
        let mut event = CognitoEventUserPoolsCreateAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_name = Some("CUSTOM_CHALLENGE".to_string()); // see CognitoChallengeEvent::determine
        let res = function_handler(
            shared_state.clone(),
            LambdaEvent::new(event.try_into().unwrap(), lambda_runtime::Context::default()),
        ).await.err().unwrap();
        assert_eq!(res.to_string(), "Internal Server Error");

        // verify_auth_challenge
        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL,
        ));
        let res = function_handler(
            shared_state,
            LambdaEvent::new(event.try_into().unwrap(), lambda_runtime::Context::default()),
        ).await.err().unwrap();
        assert_eq!(res.to_string(), "Internal Server Error");
    }

    #[tokio::test]
    async fn define_auth_challenge_start_custom_challenge() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny);

        let shared_state: SharedState<()> = SharedStateBuilder::default()
            .webauthn(())
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let res = define_auth_challenge(
            shared_state,
            CognitoEventUserPoolsDefineAuthChallenge::default(),
        ).await.unwrap();
        assert!(!res.response.issue_tokens);
        assert!(!res.response.fail_authentication);
        assert_eq!(res.response.challenge_name, Some("CUSTOM_CHALLENGE".to_string()));
    }

    #[tokio::test]
    async fn define_auth_challenge_allow_custom_challenge() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny);

        let shared_state: SharedState<()> = SharedStateBuilder::default()
            .webauthn(())
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsDefineAuthChallenge::default();
        event.request.session.push(
            Some(CognitoEventUserPoolsChallengeResult {
                challenge_name: Some("CUSTOM_CHALLENGE".to_string()),
                challenge_result: true,
                challenge_metadata: None,
            }),
        );
        let res = define_auth_challenge(shared_state, event).await.unwrap();
        assert!(res.response.issue_tokens);
        assert!(!res.response.fail_authentication);
        assert!(res.response.challenge_name.is_none());
    }

    #[tokio::test]
    async fn define_auth_challenge_deny_custom_challenge() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny);

        let shared_state: SharedState<()> = SharedStateBuilder::default()
            .webauthn(())
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsDefineAuthChallenge::default();
        event.request.session.push(
            Some(CognitoEventUserPoolsChallengeResult {
                challenge_name: Some("CUSTOM_CHALLENGE".to_string()),
                challenge_result: false,
                challenge_metadata: None,
            }),
        );
        let res = define_auth_challenge(shared_state, event).await.unwrap();
        assert!(!res.response.issue_tokens);
        assert!(res.response.fail_authentication);
        assert!(res.response.challenge_name.is_none());
    }

    #[tokio::test]
    async fn create_auth_challenge_for_existing_user() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_a_credential());

        let shared_state: SharedState<ConstantWebauthnCreateAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnCreateAuthChallenge::new(
                self::mocks::webauthn::OK_REQUEST_CHALLENGE_RESPONSE,
                self::mocks::webauthn::OK_PASSKEY_AUTHENTICATION,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsCreateAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        let res = create_auth_challenge(shared_state, event).await.unwrap();
        assert_eq!(res.response.challenge_metadata, Some("PASSKEY_TEST_CHALLENGE".to_string()));
        let rcr: RequestChallengeResponse = serde_json::from_str(self::mocks::webauthn::OK_REQUEST_CHALLENGE_RESPONSE).unwrap();
        assert_eq!(
            res.response.public_challenge_parameters,
            HashMap::from([
                (
                    CHALLENGE_PARAMETER_NAME.to_string(),
                    serde_json::to_string(&rcr).unwrap(),
                ),
            ]),
        );
        let auth_state: PasskeyAuthentication = serde_json::from_str(self::mocks::webauthn::OK_PASSKEY_AUTHENTICATION).unwrap();
        assert_eq!(
            res.response.private_challenge_parameters,
            HashMap::from([
                (
                    CHALLENGE_PARAMETER_NAME.to_string(),
                    serde_json::to_string(&auth_state).unwrap(),
                ),
            ]),
        );
    }

    #[tokio::test]
    async fn create_auth_challenge_for_non_existing_user() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny);

        let shared_state: SharedState<NoCredentialWebauthnCreateAuthChallenge> = SharedStateBuilder::default()
            .webauthn(NoCredentialWebauthnCreateAuthChallenge) // never used
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsCreateAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("nonexistinguser".to_string());
        event.request.user_not_found = true;

        let res = create_auth_challenge(shared_state.clone(), event.clone()).await.unwrap();
        assert_eq!(res.response.challenge_metadata, Some("PASSKEY_TEST_CHALLENGE".to_string()));
        let rcr = res.response.public_challenge_parameters.get(CHALLENGE_PARAMETER_NAME).unwrap();
        let rcr: RequestChallengeResponse = serde_json::from_str(rcr).unwrap();
        // saves the credential ID to test if it does not change over time
        let credential_id_1 = &rcr.public_key.allow_credentials[0].id;

        // second attempt
        let res = create_auth_challenge(shared_state, event).await.unwrap();
        let rcr = res.response.public_challenge_parameters.get(CHALLENGE_PARAMETER_NAME).unwrap();
        let rcr: RequestChallengeResponse = serde_json::from_str(rcr).unwrap();
        let credential_id_2 = &rcr.public_key.allow_credentials[0].id;
        assert_eq!(credential_id_1, credential_id_2);
    }

    #[tokio::test]
    async fn create_auth_challenge_for_user_wo_credential() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::query_no_credential());

        let shared_state: SharedState<NoCredentialWebauthnCreateAuthChallenge> = SharedStateBuilder::default()
            .webauthn(NoCredentialWebauthnCreateAuthChallenge)
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsCreateAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueidwocredential".to_string());
        assert!(create_auth_challenge(shared_state, event).await.is_err());
    }

    #[tokio::test]
    async fn verify_auth_challenge_of_discoverable_credential() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_discovery_session())
            .with_rule(&self::mocks::dynamodb::query_a_credential());

        let shared_state: SharedState<ConstantWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnVerifyAuthChallenge::new(
                self::mocks::webauthn::OK_AUTHENTICATION_RESULT,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL,
        ));
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        assert!(res.response.answer_correct);
    }

    #[tokio::test]
    async fn verify_auth_challenge_of_discoverable_credential_with_update() {
        let update_item_ok = self::mocks::dynamodb::update_item_ok();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_discovery_session())
            .with_rule(&self::mocks::dynamodb::query_a_credential())
            .with_rule(&update_item_ok);

        let shared_state: SharedState<ConstantWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnVerifyAuthChallenge::new(
                self::mocks::webauthn::OK_AUTHENTICATION_RESULT_UPDATED,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL,
        ));
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        assert!(res.response.answer_correct);
        assert_eq!(update_item_ok.num_calls(), 1);
    }

    #[tokio::test]
    async fn verify_auth_challenge_of_cognito_initiated_credential() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_no_credential())
            .with_rule(&self::mocks::dynamodb::get_item_a_credential());

        let shared_state: SharedState<ConstantWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnVerifyAuthChallenge::new(
                self::mocks::webauthn::OK_AUTHENTICATION_RESULT,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL,
        ));
        event.request.private_challenge_parameters = HashMap::from([
            (
                CHALLENGE_PARAMETER_NAME.to_string(),
                self::mocks::webauthn::OK_PASSKEY_AUTHENTICATION.to_string(),
            ),
        ]);
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        assert!(res.response.answer_correct);
    }

    #[tokio::test]
    async fn verify_auth_challenge_of_cognito_initiated_credential_with_update() {
        let update_item_ok = self::mocks::dynamodb::update_item_ok();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_no_credential())
            .with_rule(&self::mocks::dynamodb::get_item_a_credential())
            .with_rule(&update_item_ok);

        let shared_state: SharedState<ConstantWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnVerifyAuthChallenge::new(
                self::mocks::webauthn::OK_AUTHENTICATION_RESULT_UPDATED,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL,
        ));
        event.request.private_challenge_parameters = HashMap::from([
            (
                CHALLENGE_PARAMETER_NAME.to_string(),
                self::mocks::webauthn::OK_PASSKEY_AUTHENTICATION.to_string(),
            ),
        ]);
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        assert!(res.response.answer_correct);
        assert_eq!(update_item_ok.num_calls(), 1);
    }

    #[tokio::test]
    async fn verify_auth_challenge_of_discoverable_credential_with_verification_error() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_discovery_session())
            .with_rule(&self::mocks::dynamodb::query_a_credential());

        let shared_state: SharedState<RejectingWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(RejectingWebauthnVerifyAuthChallenge)
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL,
        ));
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        assert!(!res.response.answer_correct);
    }

    #[tokio::test]
    async fn verify_auth_challenge_of_cognito_initiated_credential_with_verification_error() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_no_credential())
            .with_rule(&self::mocks::dynamodb::get_item_a_credential());

        let shared_state: SharedState<RejectingWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(RejectingWebauthnVerifyAuthChallenge)
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL,
        ));
        event.request.private_challenge_parameters = HashMap::from([
            (
                CHALLENGE_PARAMETER_NAME.to_string(),
                self::mocks::webauthn::OK_PASSKEY_AUTHENTICATION.to_string(),
            ),
        ]);
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        assert!(!res.response.answer_correct);
    }

    #[tokio::test]
    async fn verify_auth_challenge_of_discoverable_credential_user_not_verified() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_discovery_session())
            .with_rule(&self::mocks::dynamodb::query_a_credential());

        let shared_state: SharedState<ConstantWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnVerifyAuthChallenge::new(
                self::mocks::webauthn::AUTHENTICATION_RESULT_USER_NOT_VERIFIED,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL,
        ));
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        assert!(!res.response.answer_correct);
    }

    #[tokio::test]
    async fn verify_auth_challenge_of_cognito_initiated_credential_user_not_verified() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_no_credential())
            .with_rule(&self::mocks::dynamodb::get_item_a_credential());

        let shared_state: SharedState<ConstantWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnVerifyAuthChallenge::new(
                self::mocks::webauthn::AUTHENTICATION_RESULT_USER_NOT_VERIFIED,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL,
        ));
        event.request.private_challenge_parameters = HashMap::from([
            (
                CHALLENGE_PARAMETER_NAME.to_string(),
                self::mocks::webauthn::OK_PASSKEY_AUTHENTICATION.to_string(),
            ),
        ]);
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        assert!(!res.response.answer_correct);
    }

    #[tokio::test]
    async fn verify_auth_challenge_with_malformed_challenge_answer() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny);

        let shared_state: SharedState<ConstantWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnVerifyAuthChallenge::new(
                self::mocks::webauthn::OK_AUTHENTICATION_RESULT,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from("{}"));
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        assert!(!res.response.answer_correct);
    }

    #[tokio::test]
    async fn verify_auth_challenge_with_user_handle_mismatch() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny);

        let shared_state: SharedState<ConstantWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnVerifyAuthChallenge::new(
                self::mocks::webauthn::OK_AUTHENTICATION_RESULT,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("anotheruseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL,
        ));
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        assert!(!res.response.answer_correct);
    }

    #[tokio::test]
    async fn verify_auth_challenge_with_malformed_client_data() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny);

        let shared_state: SharedState<ConstantWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnVerifyAuthChallenge::new(
                self::mocks::webauthn::OK_AUTHENTICATION_RESULT,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::PUBLIC_KEY_CREDENTIAL_MALFORMED_CLIENT_DATA,
        ));
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        assert!(!res.response.answer_correct);
    }

    #[tokio::test]
    async fn verify_auth_challenge_with_bad_client_data_type() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny);

        let shared_state: SharedState<ConstantWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnVerifyAuthChallenge::new(
                self::mocks::webauthn::OK_AUTHENTICATION_RESULT,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::PUBLIC_KEY_CREDENTIAL_BAD_CLIENT_DATA_TYPE,
        ));
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        assert!(!res.response.answer_correct);
    }

    #[tokio::test]
    async fn verify_auth_challenge_with_expired_session() {
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_expired_discovery_session());

        let shared_state: SharedState<ConstantWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnVerifyAuthChallenge::new(
                self::mocks::webauthn::OK_AUTHENTICATION_RESULT,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL,
        ));
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        assert!(!res.response.answer_correct);
    }

    #[tokio::test]
    async fn verify_auth_challenge_of_discoverable_credential_with_update_error() {
        let update_item = self::mocks::dynamodb::update_item_write_throughput_exceeded();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_discovery_session())
            .with_rule(&self::mocks::dynamodb::query_a_credential())
            .with_rule(&update_item);

        let shared_state: SharedState<ConstantWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnVerifyAuthChallenge::new(
                self::mocks::webauthn::OK_AUTHENTICATION_RESULT_UPDATED,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL,
        ));
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        // tolerates the failure to update
        assert!(res.response.answer_correct);
        assert_eq!(update_item.num_calls(), 1);
    }

    #[tokio::test]
    async fn verify_auth_challenge_of_cognito_initiated_credential_with_update_error() {
        let update_item = self::mocks::dynamodb::update_item_write_throughput_exceeded();
        let dynamodb = MockResponseInterceptor::new()
            .rule_mode(RuleMode::MatchAny)
            .with_rule(&self::mocks::dynamodb::delete_item_no_credential())
            .with_rule(&self::mocks::dynamodb::get_item_a_credential())
            .with_rule(&update_item);

        let shared_state: SharedState<ConstantWebauthnVerifyAuthChallenge> = SharedStateBuilder::default()
            .webauthn(ConstantWebauthnVerifyAuthChallenge::new(
                self::mocks::webauthn::OK_AUTHENTICATION_RESULT_UPDATED,
            ))
            .dynamodb(self::mocks::dynamodb::new_client(dynamodb))
            .build()
            .unwrap();
        let shared_state = Arc::new(shared_state);

        let mut event = CognitoEventUserPoolsVerifyAuthChallenge::default();
        event.cognito_event_user_pools_header.user_name = Some("testuseruniqueid".to_string());
        event.request.challenge_answer = Some(serde_json::Value::from(
            self::mocks::webauthn::OK_PUBLIC_KEY_CREDENTIAL,
        ));
        event.request.private_challenge_parameters = HashMap::from([
            (
                CHALLENGE_PARAMETER_NAME.to_string(),
                self::mocks::webauthn::OK_PASSKEY_AUTHENTICATION.to_string(),
            ),
        ]);
        let res = verify_auth_challenge(shared_state, event).await.unwrap();
        // tolerates the failure to update
        assert!(res.response.answer_correct);
        assert_eq!(update_item.num_calls(), 1);
    }

    pub(crate) mod mocks {
        use super::*;

        pub(crate) mod webauthn {
            use super::*;

            pub(crate) const OK_REQUEST_CHALLENGE_RESPONSE: &str = r#"{
                "publicKey": {
                    "challenge": "fS_B1MxJouaI0QpuYtrsl6kheAAqtQlUgyAfaxOYdXE",
                    "rpId": "localhost",
                    "allowCredentials": [],
                    "userVerification": "preferred"
                },
                "mediation": null
            }"#;

            pub(crate) const OK_PASSKEY_AUTHENTICATION: &str = r#"{
                "ast": {
                    "credentials": [
                        {
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
                    ],
                    "policy": "required",
                    "challenge": "fS_B1MxJouaI0QpuYtrsl6kheAAqtQlUgyAfaxOYdXE",
                    "appid": null,
                    "allow_backup_eligible_upgrade": true
                }
            }"#;

            pub(crate) const OK_DISCOVERABLE_AUTHENTICATION: &str = OK_PASSKEY_AUTHENTICATION;

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

            pub(crate) const OK_PUBLIC_KEY_CREDENTIAL: &str = r#"{
                "id": "VD-k4AUT6FLUNmROa7OAiA",
                "rawId": "VD-k4AUT6FLUNmROa7OAiA",
                "response": {
                    "authenticatorData": "",
                    "clientDataJSON": "ewogICJ0eXBlIjogIndlYmF1dGhuLmdldCIsCiAgImNoYWxsZW5nZSI6ICJmU19CMU14Sm91YUkwUXB1WXRyc2w2a2hlQUFxdFFsVWd5QWZheE9ZZFhFIiwKICAib3JpZ2luIjogImh0dHA6Ly9sb2NhbGhvc3QiCn0K",
                    "signature": "",
                    "userHandle": "testuseruniqueid"
                },
                "extensions": {},
                "type": "public-key"
            }"#;
            // the `clientDataJSON` field is a base64url-encoded value of the
            // following JSON:
            // {
            //     "type": "webauthn.get",
            //     "challenge": "fS_B1MxJouaI0QpuYtrsl6kheAAqtQlUgyAfaxOYdXE",
            //     "origin": "http://localhost"
            // }

            pub(crate) const PUBLIC_KEY_CREDENTIAL_MALFORMED_CLIENT_DATA: &str = r#"{
                "id": "VD-k4AUT6FLUNmROa7OAiA",
                "rawId": "VD-k4AUT6FLUNmROa7OAiA",
                "response": {
                    "authenticatorData": "",
                    "clientDataJSON": "e30K",
                    "signature": "",
                    "userHandle": "testuseruniqueid"
                },
                "extensions": {},
                "type": "public-key"
            }"#;
            // the `clientDataJSON` field is a base64url-encoded value of an
            // empty JSON object; i.e., `{}`

            pub(crate) const PUBLIC_KEY_CREDENTIAL_BAD_CLIENT_DATA_TYPE: &str = r#"{
                "id": "VD-k4AUT6FLUNmROa7OAiA",
                "rawId": "VD-k4AUT6FLUNmROa7OAiA",
                "response": {
                    "authenticatorData": "",
                    "clientDataJSON": "ewogICJ0eXBlIjogIndlYmF1dGhuLmNyZWF0ZSIsCiAgImNoYWxsZW5nZSI6ICJmU19CMU14Sm91YUkwUXB1WXRyc2w2a2hlQUFxdFFsVWd5QWZheE9ZZFhFIiwKICAib3JpZ2luIjogImh0dHA6Ly9sb2NhbGhvc3QiCn0K",
                    "signature": "",
                    "userHandle": "testuseruniqueid"
                },
                "extensions": {},
                "type": "public-key"
            }"#;
            // the `clientDataJSON` field is a base64url-encoded value of the
            // following JSON:
            // {
            //     "type": "webauthn.create",
            //     "challenge": "fS_B1MxJouaI0QpuYtrsl6kheAAqtQlUgyAfaxOYdXE",
            //     "origin": "http://localhost"
            // }

            pub(crate) const OK_AUTHENTICATION_RESULT: &str = r#"{
                "cred_id": "VD-k4AUT6FLUNmROa7OAiA",
                "needs_update": false,
                "user_verified": true,
                "backup_state": false,
                "backup_eligible": true,
                "counter": 1,
                "extensions": {}
            }"#;

            pub(crate) const OK_AUTHENTICATION_RESULT_UPDATED: &str = r#"{
                "cred_id": "VD-k4AUT6FLUNmROa7OAiA",
                "needs_update": true,
                "user_verified": true,
                "backup_state": false,
                "backup_eligible": true,
                "counter": 2,
                "extensions": {}
            }"#;
            // NOTE: `webauthn-rs` does not evaluate `needs_update` but checks
            //       if any property is updated; e.g., `counter`

            pub(crate) const AUTHENTICATION_RESULT_USER_NOT_VERIFIED: &str = r#"{
                "cred_id": "VD-k4AUT6FLUNmROa7OAiA",
                "needs_update": false,
                "user_verified": false,
                "backup_state": false,
                "backup_eligible": true,
                "counter": 1,
                "extensions": {}
            }"#;

            pub(crate) struct ConstantWebauthnCreateAuthChallenge {
                request_challenge_response: String,
                passkey_authentication: String,
            }

            impl ConstantWebauthnCreateAuthChallenge {
                pub(crate) fn new(
                    request_challenge_response: impl Into<String>,
                    passkey_authentication: impl Into<String>,
                ) -> Self {
                    Self {
                        request_challenge_response: request_challenge_response.into(),
                        passkey_authentication: passkey_authentication.into(),
                    }
                }
            }

            impl WebauthnCreateAuthChallenge for ConstantWebauthnCreateAuthChallenge {
                fn start_passkey_authentication(
                    &self,
                    _creds: &[Passkey],
                ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), WebauthnError> {
                    Ok((
                        serde_json::from_str(&self.request_challenge_response).unwrap(),
                        serde_json::from_str(&self.passkey_authentication).unwrap(),
                    ))
                }
            }

            pub(crate) struct NoCredentialWebauthnCreateAuthChallenge;

            impl WebauthnCreateAuthChallenge for NoCredentialWebauthnCreateAuthChallenge {
                fn start_passkey_authentication(
                    &self,
                    _creds: &[Passkey],
                ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), WebauthnError> {
                    Err(WebauthnError::CredentialNotFound)
                }
            }

            pub(crate) struct ConstantWebauthnVerifyAuthChallenge {
                authentication_result: String,
            }

            impl ConstantWebauthnVerifyAuthChallenge {
                pub(crate) fn new(
                    authentication_result: impl Into<String>,
                ) -> Self {
                    Self {
                        authentication_result: authentication_result.into(),
                    }
                }
            }

            impl WebauthnVerifyAuthChallenge for ConstantWebauthnVerifyAuthChallenge {
                fn finish_discoverable_authentication(
                    &self,
                    _reg: &PublicKeyCredential,
                    _state: DiscoverableAuthentication,
                    _creds: &[DiscoverableKey],
                ) -> Result<AuthenticationResult, WebauthnError> {
                    Ok(serde_json::from_str(&self.authentication_result).unwrap())
                }

                fn finish_passkey_authentication(
                    &self,
                    _reg: &PublicKeyCredential,
                    _state: &PasskeyAuthentication,
                ) -> Result<AuthenticationResult, WebauthnError> {
                    Ok(serde_json::from_str(&self.authentication_result).unwrap())
                }
            }

            pub(crate) struct RejectingWebauthn;

            impl WebauthnCreateAuthChallenge for RejectingWebauthn {
                fn start_passkey_authentication(
                    &self,
                    _creds: &[Passkey],
                ) -> Result<(RequestChallengeResponse, PasskeyAuthentication), WebauthnError> {
                    Err(WebauthnError::Configuration)
                }
            }

            impl WebauthnVerifyAuthChallenge for RejectingWebauthn {
                fn finish_discoverable_authentication(
                    &self,
                    _reg: &PublicKeyCredential,
                    _state: DiscoverableAuthentication,
                    _creds: &[DiscoverableKey],
                ) -> Result<AuthenticationResult, WebauthnError> {
                    Err(WebauthnError::UserNotVerified)
                }

                fn finish_passkey_authentication(
                    &self,
                    _reg: &PublicKeyCredential,
                    _state: &PasskeyAuthentication,
                ) -> Result<AuthenticationResult, WebauthnError> {
                    Err(WebauthnError::UserNotVerified)
                }
            }

            pub(crate) struct RejectingWebauthnVerifyAuthChallenge;

            impl WebauthnVerifyAuthChallenge for RejectingWebauthnVerifyAuthChallenge {
                fn finish_discoverable_authentication(
                    &self,
                    _reg: &PublicKeyCredential,
                    _state: DiscoverableAuthentication,
                    _creds: &[DiscoverableKey],
                ) -> Result<AuthenticationResult, WebauthnError> {
                    Err(WebauthnError::UserNotVerified)
                }

                fn finish_passkey_authentication(
                    &self,
                    _reg: &PublicKeyCredential,
                    _state: &PasskeyAuthentication,
                ) -> Result<AuthenticationResult, WebauthnError> {
                    Err(WebauthnError::UserNotVerified)
                }
            }
        }

        pub(crate) mod dynamodb {
            use super::*;

            use aws_sdk_dynamodb::{
                config::Region,
                operation::{
                    delete_item::DeleteItemOutput,
                    get_item::GetItemOutput,
                    query::QueryOutput,
                    update_item::UpdateItemOutput,
                },
                Client,
                Config,
            };
            use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
            use aws_smithy_runtime_api::http::StatusCode as SmithyStatusCode;
            use aws_smithy_types::body::SdkBody;

            const RESOURCE_NOT_FOUND_EXCEPTION: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ResourceNotFoundException", "message": "No such table."}"#;

            const PROVISIONED_THROUGHPUT_EXCEEDED_EXCEPTION: &str = r#"{"__type": "com.amazonaws.dynamodb.v20120810#ProvisionedThroughputExceededException", "message": "Exceeded provisioned throughput."}"#;

            pub(crate) fn new_client(mocks: MockResponseInterceptor) -> Client {
                Client::from_conf(
                    Config::builder()
                        .with_test_defaults()
                        .region(Region::new("ap-northeast-1"))
                        .interceptor(mocks)
                        .build(),
                )
            }

            pub(crate) fn query_a_credential() -> Rule {
                mock!(Client::query)
                    .then_output(|| {
                        QueryOutput::builder()
                            .items(HashMap::from([
                                (
                                    "credential".to_string(),
                                    AttributeValue::S(super::webauthn::OK_PASSKEY.to_string()),
                                ),
                            ]))
                            .build()
                    })
            }

            pub(crate) fn query_no_credential() -> Rule {
                mock!(Client::query)
                    .then_output(|| QueryOutput::builder().build())
            }

            pub(crate) fn query_table_not_found() -> Rule {
                mock!(Client::query)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(RESOURCE_NOT_FOUND_EXCEPTION),
                        )
                    })
            }

            pub(crate) fn delete_item_discovery_session() -> Rule {
                mock!(Client::delete_item)
                    .then_output(|| {
                        let ttl = DateTime::from(SystemTime::now()).secs() + 60;
                        DeleteItemOutput::builder()
                            .attributes("ttl", AttributeValue::N(format!("{}", ttl)))
                            .attributes("state", AttributeValue::S(super::webauthn::OK_DISCOVERABLE_AUTHENTICATION.to_string()))
                            .build()
                    })
            }

            pub(crate) fn delete_item_expired_discovery_session() -> Rule {
                mock!(Client::delete_item)
                    .then_output(|| {
                        let ttl = DateTime::from(SystemTime::now()).secs() - 60;
                        DeleteItemOutput::builder()
                            .attributes("ttl", AttributeValue::N(format!("{}", ttl)))
                            .attributes("state", AttributeValue::S(super::webauthn::OK_DISCOVERABLE_AUTHENTICATION.to_string()))
                            .build()
                    })
            }

            pub(crate) fn delete_item_no_credential() -> Rule {
                mock!(Client::delete_item)
                    .then_output(|| DeleteItemOutput::builder().build())
            }

            pub(crate) fn delete_item_table_not_found() -> Rule {
                mock!(Client::delete_item)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(RESOURCE_NOT_FOUND_EXCEPTION),
                        )
                    })
            }

            pub(crate) fn get_item_a_credential() -> Rule {
                mock!(Client::get_item)
                    .then_output(|| {
                        GetItemOutput::builder()
                            .item(
                                "credential",
                                AttributeValue::S(super::webauthn::OK_PASSKEY.to_string()),
                            )
                            .build()
                    })
            }

            pub(crate) fn update_item_ok() -> Rule {
                mock!(Client::update_item)
                    .then_output(|| UpdateItemOutput::builder().build())
            }

            pub(crate) fn update_item_write_throughput_exceeded() -> Rule {
                mock!(Client::update_item)
                    .then_http_response(|| {
                        HttpResponse::new(
                            SmithyStatusCode::try_from(400).unwrap(),
                            SdkBody::from(PROVISIONED_THROUGHPUT_EXCEEDED_EXCEPTION),
                        )
                    })
            }
        }
    }
}
