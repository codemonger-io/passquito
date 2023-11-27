//! Performs Web Athentication.

use axum::{
    Extension,
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use tracing::{error, info};
use webauthn_rs::prelude::{
    DiscoverableAuthentication,
    DiscoverableKey,
    PasskeyAuthentication,
    PasskeyRegistration,
    Uuid,
};
use webauthn_rs_proto::{
    CreationChallengeResponse,
    PublicKeyCredential,
    RegisterPublicKeyCredential,
};

use crate::error::WebauthnError;
use crate::state::AppState;

const REG_STATE_KEY: &str = "reg_state";
const AUTH_STATE_KEY: &str = "auth_state";

type UserPasskeyRegistration = (String, Uuid, PasskeyRegistration);
type UserPasskeyAuthentication = (String, Uuid, PasskeyAuthentication);

/// Information on a new user.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewUserInfo {
    /// Username.
    username: String,
    /// Display name.
    display_name: String,
}

/// Information on a user.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    /// Username.
    username: String,
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

/// Start the registration session.
pub async fn start_register(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(user_info): Json<NewUserInfo>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("start register");
    let user_unique_id = {
        let users_guard = app_state.users.lock().await;
        users_guard
            .name_to_id
            .get(&user_info.username)
            .copied()
            .unwrap_or_else(Uuid::new_v4)
    };
    session
        .remove::<(String, String, PasskeyRegistration)>(REG_STATE_KEY)
        .expect("failed to remove registration session");
    let exclude_credentials = {
        let users_guard = app_state.users.lock().await;
        users_guard
            .keys
            .get(&user_unique_id)
            .map(|keys| keys.iter().map(|sk| sk.cred_id().clone()).collect())
    };
    let res = match app_state.webauthn.start_passkey_registration(
        user_unique_id,
        &user_info.username,
        &user_info.display_name,
        exclude_credentials,
    ) {
        Ok((ccr, reg_state)) => {
            session
                .insert(REG_STATE_KEY, (
                    user_info.username,
                    user_unique_id,
                    reg_state,
                ))
                .expect("failed to insert session");
            info!("Registration Successful!");
            Json(StartRegistrationSession {
                session_id: "dummy".into(),
                credential_creation_options: ccr,
            })
        }
        Err(e) => {
            error!("start_register -> {:?}", e);
            return Err(WebauthnError::Unknown);
        }
    };
    Ok(res)
}

/// Finishes the registration session.
pub async fn finish_register(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(reg): Json<FinishRegistrationSession>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("finish register");
    let (username, user_unique_id, reg_state) = session
        .remove::<UserPasskeyRegistration>(REG_STATE_KEY)
        .or(Err(WebauthnError::CorruptSession))
        .and_then(|value| value.ok_or(WebauthnError::CorruptSession))?;
    let res = match app_state
        .webauthn
        .finish_passkey_registration(&reg.public_key_credential, &reg_state)
    {
        Ok(sk) => {
            let mut users_guard = app_state.users.lock().await;
            users_guard
                .keys
                .entry(user_unique_id)
                .and_modify(|keys| keys.push(sk.clone()))
                .or_insert_with(|| vec![sk.clone()]);
            users_guard.name_to_id.insert(username, user_unique_id);
            StatusCode::OK
        }
        Err(e) => {
            error!("finish_register -> {:?}", e);
            StatusCode::BAD_REQUEST
        }
    };
    Ok(res)
}

/// Starts the authentication session.
pub async fn start_authentication(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(user_info): Json<UserInfo>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("start authentication");
    session
        .remove::<UserPasskeyAuthentication>(AUTH_STATE_KEY)
        .expect("failed to remove authentication session");
    let users_guard = app_state.users.lock().await;
    let user_unique_id = users_guard
        .name_to_id
        .get(&user_info.username)
        .copied()
        .ok_or(WebauthnError::UserNotFound)?;
    let allow_credentials = users_guard
        .keys
        .get(&user_unique_id)
        .ok_or(WebauthnError::UserHasNoCredentials)?;
    let res = match app_state
        .webauthn
        .start_passkey_authentication(allow_credentials)
    {
        Ok((rcr, auth_state)) => {
            drop(users_guard);
            session
                .insert(AUTH_STATE_KEY, (Some(user_unique_id), auth_state))
                .expect("failed to start authentication session");
            Json(rcr)
        }
        Err(e) => {
            error!("start_authentication -> {:?}", e);
            return Err(WebauthnError::Unknown);
        }
    };
    Ok(res)
}

/// Starts the authentication session for anyone who requested.
pub async fn start_authentication_for_anyone(
    Extension(app_state): Extension<AppState>,
    session: Session,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("start authentication for anyone");
    session
        .remove::<DiscoverableAuthentication>(AUTH_STATE_KEY)
        .expect("failed to remove authentication session");
    let res = match app_state
        .webauthn
        .start_discoverable_authentication()
    {
        Ok((rcr, auth_state)) => {
            session
                .insert(AUTH_STATE_KEY, auth_state)
                .expect("failed to start authentication session");
            Json(rcr)
        }
        Err(e) => {
            error!("start_authentication -> {:?}", e);
            return Err(WebauthnError::Unknown);
        }
    };
    Ok(res)
}

/// Finishes the authentication seession.
pub async fn finish_authentication_for_anyone(
    Extension(app_state): Extension<AppState>,
    session: Session,
    Json(auth): Json<PublicKeyCredential>,
) -> Result<impl IntoResponse, WebauthnError> {
    info!("finish authentication");
    let auth_state = session
        .remove::<DiscoverableAuthentication>(AUTH_STATE_KEY)
        .or(Err(WebauthnError::CorruptSession))
        .and_then(|value| value.ok_or(WebauthnError::CorruptSession))?;
    let user_unique_id = auth
        .get_user_unique_id()
        .and_then(|id| Uuid::from_slice(id).ok())
        .ok_or(WebauthnError::BadRequest)?;
    let credentials: Vec<DiscoverableKey> = {
        let users_guard = app_state.users.lock().await;
        users_guard
            .keys
            .get(&user_unique_id)
            .map(|keys| keys.iter().map(|sk| sk.into()).collect())
            .ok_or(WebauthnError::UserHasNoCredentials)?
    };
    let body = match app_state
        .webauthn
        .finish_discoverable_authentication(&auth, auth_state, &credentials)
    {
        Ok(auth_result) => {
            let mut users_guard = app_state.users.lock().await;
            users_guard
                .keys
                .get_mut(&user_unique_id)
                .map(|keys| {
                    keys.iter_mut().for_each(|sk| {
                        sk.update_credential(&auth_result);
                    })
                })
                .ok_or(WebauthnError::UserHasNoCredentials)?;
            "{ \"message\": \"TODO: return username\" }"
        }
        Err(e) => {
            error!("finish_authentication -> {:?}", e);
            return Err(WebauthnError::BadRequest);
        }
    };
    Ok(body)
}
