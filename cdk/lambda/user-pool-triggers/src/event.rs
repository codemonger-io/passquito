//! Cognito trigger event.

use aws_lambda_events::event::cognito::{
    CognitoEventUserPoolsChallengeResult,
    CognitoEventUserPoolsCreateAuthChallengeRequest,
    CognitoEventUserPoolsCreateAuthChallengeResponse,
    CognitoEventUserPoolsDefineAuthChallenge,
    CognitoEventUserPoolsDefineAuthChallengeRequest,
    CognitoEventUserPoolsDefineAuthChallengeResponse,
    CognitoEventUserPoolsHeader,
    CognitoEventUserPoolsVerifyAuthChallengeRequest,
    CognitoEventUserPoolsVerifyAuthChallengeResponse,
};
use serde::{
    Deserialize, Serialize,
    de::Deserializer,
};
use std::collections::HashMap;

use crate::error::Error;

/// Union of challenge events.
///
/// Packs the following events.
/// - "Define auth challenge"
/// - "Create auth challenge"
/// - "Verify auth challenge"
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CognitoChallengeEvent {
    /// Common part.
    #[serde(rename = "CognitoEventUserPoolsHeader")]
    #[serde(flatten)]
    pub cognito_event_user_pools_header: CognitoEventUserPoolsHeader,

    /// Request part.
    pub request: CognitoChallengeEventRequest,

    /// Response part.
    pub response: CognitoChallengeEventResponse,
}

impl CognitoChallengeEvent {
    /// Determines the actual type of the event.
    ///
    /// Returns `self` wrapped with `Err` if the type is ambiguous or invalid.
    pub fn determine(self) -> Result<CognitoChallengeEventCase, Error> {
        if self.request.challenge_name.is_some() {
            // CognitoEventUserPoolsCreateAuthChallenge::challenge_name is
            // Option though
            Ok(CognitoChallengeEventCase::Create(self.try_into()?))
        } else if self.request.private_challenge_parameters.is_some() {
            Ok(CognitoChallengeEventCase::Verify(self.try_into()?))
        } else {
            Ok(CognitoChallengeEventCase::Define(self.try_into()?))
        }
    }
}

macro_rules! impl_try_into {
    ($event:ident) => {
        impl TryInto<$event> for CognitoChallengeEvent {
            type Error = Error;

            fn try_into(self) -> Result<$event, Error> {
                Ok($event {
                    cognito_event_user_pools_header:
                        self.cognito_event_user_pools_header,
                    request: self.request.try_into()?,
                    response: self.response.try_into()?,
                })
            }
        }
    };
}

impl_try_into! { CognitoEventUserPoolsDefineAuthChallenge }
impl_try_into! { CognitoEventUserPoolsCreateAuthChallengeExt }
impl_try_into! { CognitoEventUserPoolsVerifyAuthChallengeExt }

macro_rules! impl_from {
    ($event:ident) => {
        impl From<$event> for CognitoChallengeEvent {
            fn from(from: $event) -> CognitoChallengeEvent {
                CognitoChallengeEvent {
                    cognito_event_user_pools_header:
                        from.cognito_event_user_pools_header,
                    request: from.request.into(),
                    response: from.response.into(),
                }
            }
        }
    };
}

impl_from! { CognitoEventUserPoolsDefineAuthChallenge }
impl_from! { CognitoEventUserPoolsCreateAuthChallengeExt }
impl_from! { CognitoEventUserPoolsVerifyAuthChallengeExt }

/// Operations on [`CognitoEventUserPoolsDefineAuthChallengeResponse`].
pub trait CognitoEventUserPoolsDefineAuthChallengeOps {
    /// Returns the sessions.
    fn sessions(&self) -> &Vec<Option<CognitoEventUserPoolsChallengeResult>>;

    /// Starts custom challenge.
    fn start_custom_challenge(&mut self);

    /// Allows the authentication.
    fn allow(&mut self);

    /// Denies the authentication.
    fn deny(&mut self);
}

impl CognitoEventUserPoolsDefineAuthChallengeOps
    for CognitoEventUserPoolsDefineAuthChallenge
{
    fn sessions(&self) -> &Vec<Option<CognitoEventUserPoolsChallengeResult>> {
        &self.request.session
    }

    fn start_custom_challenge(&mut self) {
        self.response.issue_tokens = false;
        self.response.fail_authentication = false;
        self.response.challenge_name = Some("CUSTOM_CHALLENGE".into());
    }

    fn allow(&mut self) {
        self.response.issue_tokens = true;
        self.response.fail_authentication = false;
    }

    fn deny(&mut self) {
        self.response.issue_tokens = false;
        self.response.fail_authentication = true;
    }
}

/// [`CognitoEventUserPoolsCreateAuthChallenge`] extended with
/// `user_not_found` field.
pub struct CognitoEventUserPoolsCreateAuthChallengeExt {
    /// Common part.
    pub cognito_event_user_pools_header: CognitoEventUserPoolsHeader,

    /// Request part with `user_not_found`.
    ///
    /// The second item indicates user's absence.
    pub request: (CognitoEventUserPoolsCreateAuthChallengeRequest, bool),

    /// Response part.
    pub response: CognitoEventUserPoolsCreateAuthChallengeResponse,
}

impl CognitoEventUserPoolsCreateAuthChallengeExt {
    /// Returns the sessions.
    pub fn sessions(&self) -> &Vec<Option<CognitoEventUserPoolsChallengeResult>> {
        &self.request.0.session
    }

    /// Sets the challenge metadata.
    pub fn set_challenge_metadata(&mut self, metadata: impl Into<String>) {
        self.response.challenge_metadata = Some(metadata.into());
    }

    /// Sets a public challenge parameter.
    pub fn set_public_challenge_parameter(
        &mut self,
        key: impl Into<String>,
        value: &(impl Serialize + ?Sized),
    ) -> Result<(), Error> {
        self.response.public_challenge_parameters.insert(
            key.into(),
            serde_json::to_string(value)
                .or(Err(Error::Inconvertible("non-serializable challenge parameter")))?,
        );
        Ok(())
    }

    /// Sets a private challenge parameter.
    pub fn set_private_challenge_parameter(
        &mut self,
        key: impl Into<String>,
        value: &(impl Serialize + ?Sized),
    ) -> Result<(), Error> {
        self.response.private_challenge_parameters.insert(
            key.into(),
            serde_json::to_string(value)
                .or(Err(Error::Inconvertible("non-serializable challenge parameter")))?,
        );
        Ok(())
    }
}

/// [`CognitoEventUserPoolsVerifyAuthChallenge`] extended with
/// `user_not_found` field.
pub struct CognitoEventUserPoolsVerifyAuthChallengeExt {
    /// Common part.
    pub cognito_event_user_pools_header: CognitoEventUserPoolsHeader,

    /// Request part with `user_not_found`.
    ///
    /// The second item indicates user's absence.
    pub request: (CognitoEventUserPoolsVerifyAuthChallengeRequest<String>, bool),

    /// Response part.
    pub response: CognitoEventUserPoolsVerifyAuthChallengeResponse,
}

impl CognitoEventUserPoolsVerifyAuthChallengeExt {
    /// Obtains the challenge answer.
    pub fn get_challenge_answer<'de, T>(&'de self) -> Result<T, Error>
    where
        T: Deserialize<'de>,
    {
        let challenge_answer = self.request.0.challenge_answer
            .as_ref()
            .ok_or(Error::Inconvertible("missing challenge_answer"))?;
        serde_json::from_str(challenge_answer)
            .or(Err(Error::Inconvertible("incompatible challenge_answer")))
    }

    /// Obtains a private public parameter.
    pub fn get_private_challenge_parameter<'de, T, K>(
        &'de self,
        key: &K,
    ) -> Result<Option<T>, Error>
    where
        String: std::borrow::Borrow<K>,
        K: Eq + std::hash::Hash + ?Sized,
        T: Deserialize<'de>,
    {
        self.request.0.private_challenge_parameters
            .get(key)
            .map(|v| serde_json::from_str(v)
                .or(Err(Error::Inconvertible("incompatible challenge parameter"))))
            .transpose()
    }

    /// Accepts the challenge answer.
    pub fn accept(&mut self) {
        self.response.answer_correct = true;
    }

    /// Rejects the challenge answer.
    pub fn reject(&mut self) {
        self.response.answer_correct = false;
    }
}

/// Union of the request parts of challenge events.
///
/// Packs the request parts of the following events.
/// - "Define auth challenge"
/// - "Create auth challenge"
/// - "Verify auth challenge"
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CognitoChallengeEventRequest {
    /// User attributes.
    #[serde(deserialize_with = "deserialize_lambda_map")]
    #[serde(default)]
    pub user_attributes: HashMap<String, String>,

    /// Challenge name.
    ///
    /// Only "Create auth challenge" uses this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub challenge_name: Option<String>,

    /// Session history.
    ///
    /// "Verify auth challenge" lacks this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub session: Option<Vec<Option<CognitoEventUserPoolsChallengeResult>>>,

    /// Private challenge parameters.
    ///
    /// Only "Verify auth challenge" uses this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub private_challenge_parameters: Option<HashMap<String, String>>,

    /// Challenge answer.
    ///
    /// Only "Verify auth challenge" uses this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_answer: Option<String>,

    /// Client metadata.
    #[serde(deserialize_with = "deserialize_lambda_map")]
    #[serde(default)]
    pub client_metadata: HashMap<String, String>,

    /// User's absence.
    ///
    /// All the challenge events should have this field but only
    /// [`CognitoEventUserPoolsDefineAuthChallengeRequest`] has it.
    #[serde(default)]
    pub user_not_found: bool,
}

impl TryInto<CognitoEventUserPoolsDefineAuthChallengeRequest>
    for CognitoChallengeEventRequest
{
    type Error = Error;

    fn try_into(self) ->
        Result<CognitoEventUserPoolsDefineAuthChallengeRequest, Self::Error>
    {
        Ok(CognitoEventUserPoolsDefineAuthChallengeRequest {
            user_attributes: self.user_attributes,
            session: self.session
                .ok_or(Error::Inconvertible("missing session"))?,
            client_metadata: self.client_metadata,
            user_not_found: self.user_not_found,
        })
    }
}

impl From<CognitoEventUserPoolsDefineAuthChallengeRequest>
    for CognitoChallengeEventRequest
{
    fn from(from: CognitoEventUserPoolsDefineAuthChallengeRequest) -> Self {
        Self {
            user_attributes: from.user_attributes,
            session: Some(from.session),
            client_metadata: from.client_metadata,
            user_not_found: from.user_not_found,
            challenge_name: None,
            private_challenge_parameters: None,
            challenge_answer: None,
        }
    }
}

impl TryInto<(CognitoEventUserPoolsCreateAuthChallengeRequest, bool)>
    for CognitoChallengeEventRequest
{
    type Error = Error;

    fn try_into(self) -> Result<
        (CognitoEventUserPoolsCreateAuthChallengeRequest, bool),
        Self::Error,
    > {
        Ok((
            CognitoEventUserPoolsCreateAuthChallengeRequest {
                user_attributes: self.user_attributes,
                challenge_name: self.challenge_name,
                session: self.session
                    .ok_or(Error::Inconvertible("missing session"))?,
                client_metadata: self.client_metadata,
            },
            self.user_not_found,
        ))
    }
}

impl From<(CognitoEventUserPoolsCreateAuthChallengeRequest, bool)>
    for CognitoChallengeEventRequest
{
    fn from(
        (from, user_not_found): (
            CognitoEventUserPoolsCreateAuthChallengeRequest,
            bool,
        ),
    ) -> Self {
        Self {
            user_attributes: from.user_attributes,
            challenge_name: from.challenge_name,
            session: Some(from.session),
            client_metadata: from.client_metadata,
            user_not_found,
            private_challenge_parameters: None,
            challenge_answer: None,
        }
    }
}

impl TryInto<(CognitoEventUserPoolsVerifyAuthChallengeRequest<String>, bool)>
    for CognitoChallengeEventRequest
{
    type Error = Error;

    fn try_into(self) -> Result<
        (CognitoEventUserPoolsVerifyAuthChallengeRequest<String>, bool),
        Self::Error,
    > {
        Ok((
            CognitoEventUserPoolsVerifyAuthChallengeRequest {
                user_attributes: self.user_attributes,
                private_challenge_parameters: self.private_challenge_parameters
                    .ok_or(Error::Inconvertible("missing private_challenge_parameters"))?,
                challenge_answer: self.challenge_answer,
                client_metadata: self.client_metadata,
            },
            self.user_not_found,
        ))
    }
}

impl From<(CognitoEventUserPoolsVerifyAuthChallengeRequest<String>, bool)>
    for CognitoChallengeEventRequest
{
    fn from(
        (from, user_not_found): (
            CognitoEventUserPoolsVerifyAuthChallengeRequest<String>,
            bool,
        ),
    ) -> Self {
        Self {
            user_attributes: from.user_attributes,
            private_challenge_parameters:
                Some(from.private_challenge_parameters),
            challenge_answer: from.challenge_answer,
            client_metadata: from.client_metadata,
            user_not_found,
            challenge_name: None,
            session: None,
        }
    }
}

/// Union of the response parts of challenge events.
///
/// Packs the response parts of the following events.
/// - "Define auth challenge"
/// - "Create auth challenge"
/// - "Verify auth challenge"
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CognitoChallengeEventResponse {
    /// Challenge name.
    ///
    /// Only "Define auth challenge" uses this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub challenge_name: Option<String>,

    /// Whether tokens are issued.
    ///
    /// Only "Define auth challenge" uses this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub issue_tokens: Option<bool>,

    /// Whether the authentication fails.
    ///
    /// Only "Define auth challenge" uses this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub fail_authentication: Option<bool>,

    /// Public challenge parameters.
    ///
    /// Only "Create auth challenge" uses this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub public_challenge_parameters: Option<HashMap<String, String>>,

    /// Private challenge parameters.
    ///
    /// Only "Create auth challenge" uses this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub private_challenge_parameters: Option<HashMap<String, String>>,

    /// Challenge metadata.
    ///
    /// Only "Create auth challenge" uses this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub challenge_metadata: Option<String>,

    /// Whether the answer is correct.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub answer_correct: Option<bool>,
}

impl TryInto<CognitoEventUserPoolsDefineAuthChallengeResponse>
    for CognitoChallengeEventResponse
{
    type Error = Error;

    fn try_into(self) ->
        Result<CognitoEventUserPoolsDefineAuthChallengeResponse, Error>
    {
        Ok(CognitoEventUserPoolsDefineAuthChallengeResponse {
            challenge_name: self.challenge_name,
            issue_tokens: self.issue_tokens
                .ok_or(Error::Inconvertible("missing issue_tokens"))?,
            fail_authentication: self.fail_authentication
                .ok_or(Error::Inconvertible("missing fail_authentication"))?,
        })
    }
}

impl From<CognitoEventUserPoolsDefineAuthChallengeResponse>
    for CognitoChallengeEventResponse
{
    fn from(from: CognitoEventUserPoolsDefineAuthChallengeResponse) -> Self {
        Self {
            challenge_name: from.challenge_name,
            issue_tokens: Some(from.issue_tokens),
            fail_authentication: Some(from.fail_authentication),
            public_challenge_parameters: None,
            private_challenge_parameters: None,
            challenge_metadata: None,
            answer_correct: None,
        }
    }
}

impl TryInto<CognitoEventUserPoolsCreateAuthChallengeResponse>
    for CognitoChallengeEventResponse
{
    type Error = Error;

    fn try_into(self) ->
        Result<CognitoEventUserPoolsCreateAuthChallengeResponse, Error>
    {
        Ok(CognitoEventUserPoolsCreateAuthChallengeResponse {
            public_challenge_parameters: self.public_challenge_parameters
                .ok_or(Error::Inconvertible("missing public_challenge_parameters"))?,
            private_challenge_parameters: self.private_challenge_parameters
                .ok_or(Error::Inconvertible("missing private_challenge_parameters"))?,
            challenge_metadata: self.challenge_metadata,
        })
    }
}

impl From<CognitoEventUserPoolsCreateAuthChallengeResponse>
    for CognitoChallengeEventResponse
{
    fn from(from: CognitoEventUserPoolsCreateAuthChallengeResponse) -> Self {
        Self {
            public_challenge_parameters: Some(from.public_challenge_parameters),
            private_challenge_parameters:
                Some(from.private_challenge_parameters),
            challenge_metadata: from.challenge_metadata,
            challenge_name: None,
            issue_tokens: None,
            fail_authentication: None,
            answer_correct: None,
        }
    }
}

impl TryInto<CognitoEventUserPoolsVerifyAuthChallengeResponse>
    for CognitoChallengeEventResponse
{
    type Error = Error;

    fn try_into(self) ->
        Result<CognitoEventUserPoolsVerifyAuthChallengeResponse, Error>
    {
        Ok(CognitoEventUserPoolsVerifyAuthChallengeResponse {
            answer_correct: self.answer_correct
                .ok_or(Error::Inconvertible("missing answer_correct"))?,
        })
    }
}

impl From<CognitoEventUserPoolsVerifyAuthChallengeResponse>
    for CognitoChallengeEventResponse
{
    fn from(from: CognitoEventUserPoolsVerifyAuthChallengeResponse) -> Self {
        Self {
            answer_correct: Some(from.answer_correct),
            challenge_name: None,
            issue_tokens: None,
            fail_authentication: None,
            public_challenge_parameters: None,
            private_challenge_parameters: None,
            challenge_metadata: None,
        }
    }
}

/// Enumerates specific types of [`CognitoChallengeEvent`].
pub enum CognitoChallengeEventCase {
    /// [`CognitoUserPoolsDefineAuthChallenge`].
    Define(CognitoEventUserPoolsDefineAuthChallenge),

    /// [`CognitoUserPoolsCreateAuthChallengeExt`].
    Create(CognitoEventUserPoolsCreateAuthChallengeExt),

    /// [`CognitoUserPoolsVerifyAuthChallengeExt`].
    Verify(CognitoEventUserPoolsVerifyAuthChallengeExt),
}

/// Deserializes `HashMap<_>`, mapping JSON `null` to an empty map.
///
/// Taken from:
/// https://github.com/awslabs/aws-lambda-rust-runtime/blob/45525e0dfe1196315dd130101b9cec64ac6b67f0/lambda-events/src/custom_serde/mod.rs#L51-L63
pub(crate) fn deserialize_lambda_map<'de, D, K, V>(deserializer: D) -> Result<HashMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de>,
    K: std::hash::Hash,
    K: std::cmp::Eq,
    V: Deserialize<'de>,
{
    // https://github.com/serde-rs/serde/issues/1098
    let opt = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}
