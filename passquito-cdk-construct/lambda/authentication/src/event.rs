//! Cognito trigger event.

use aws_lambda_events::event::cognito::{
    CognitoEventUserPoolsChallengeResult,
    CognitoEventUserPoolsCreateAuthChallenge,
    CognitoEventUserPoolsCreateAuthChallengeRequest,
    CognitoEventUserPoolsCreateAuthChallengeResponse,
    CognitoEventUserPoolsDefineAuthChallenge,
    CognitoEventUserPoolsDefineAuthChallengeRequest,
    CognitoEventUserPoolsDefineAuthChallengeResponse,
    CognitoEventUserPoolsHeader,
    CognitoEventUserPoolsVerifyAuthChallenge,
    CognitoEventUserPoolsVerifyAuthChallengeRequest,
    CognitoEventUserPoolsVerifyAuthChallengeResponse,
};
// trigger sources
use aws_lambda_events::event::cognito::{
    CognitoEventUserPoolsCreateAuthChallengeTriggerSource,
    CognitoEventUserPoolsCustomMessageTriggerSource,
    CognitoEventUserPoolsDefineAuthChallengeTriggerSource,
    CognitoEventUserPoolsMigrateUserTriggerSource,
    CognitoEventUserPoolsPostAuthenticationTriggerSource,
    CognitoEventUserPoolsPostConfirmationTriggerSource,
    CognitoEventUserPoolsPreAuthenticationTriggerSource,
    CognitoEventUserPoolsPreSignupTriggerSource,
    CognitoEventUserPoolsPreTokenGenTriggerSource,
    CognitoEventUserPoolsVerifyAuthChallengeTriggerSource,
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
    pub cognito_event_user_pools_header: CognitoEventUserPoolsHeader<UniversalTriggerSource>,

    /// Request part.
    pub request: CognitoChallengeEventRequest,

    /// Response part.
    pub response: CognitoChallengeEventResponse,
}

impl CognitoChallengeEvent {
    /// Determines the actual type of the event.
    ///
    /// Determines from the trigger source if it is provided.
    /// Otherwise, guesses from fields.
    pub fn determine(self) -> Result<CognitoChallengeEventCase, Error> {
        use UniversalTriggerSource::*;
        match self.cognito_event_user_pools_header.trigger_source.as_ref() {
            Some(DefineAuthChallenge(CognitoEventUserPoolsDefineAuthChallengeTriggerSource::Authentication)) =>
                Ok(CognitoChallengeEventCase::Define(self.try_into()?)),
            Some(CreateAuthChallenge(CognitoEventUserPoolsCreateAuthChallengeTriggerSource::Authentication)) =>
                Ok(CognitoChallengeEventCase::Create(self.try_into()?)),
            Some(VerifyAuthChallenge(CognitoEventUserPoolsVerifyAuthChallengeTriggerSource::Authentication)) =>
                Ok(CognitoChallengeEventCase::Verify(self.try_into()?)),
            _ => {
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
    }
}

macro_rules! impl_try_into_for_cognito_challenge_event {
    ($event:ident) => {
        impl TryInto<$event> for CognitoChallengeEvent {
            type Error = Error;

            fn try_into(self) -> Result<$event, Self::Error> {
                Ok($event {
                    cognito_event_user_pools_header:
                        try_convert_cognito_event_user_pools_header_trigger_source(self.cognito_event_user_pools_header)?,
                    request: self.request.try_into()?,
                    response: self.response.into(),
                })
            }
        }
    };
}

impl_try_into_for_cognito_challenge_event! { CognitoEventUserPoolsDefineAuthChallenge }
impl_try_into_for_cognito_challenge_event! { CognitoEventUserPoolsCreateAuthChallenge }
impl_try_into_for_cognito_challenge_event! { CognitoEventUserPoolsVerifyAuthChallenge }

macro_rules! impl_from_for_cognito_challenge_event {
    ($event:ident) => {
        impl From<$event> for CognitoChallengeEvent {
            fn from(from: $event) -> CognitoChallengeEvent {
                CognitoChallengeEvent {
                    cognito_event_user_pools_header:
                        convert_cognito_event_user_pools_header_trigger_source(from.cognito_event_user_pools_header),
                    request: from.request.into(),
                    response: from.response.into(),
                }
            }
        }
    };
}

impl_from_for_cognito_challenge_event! { CognitoEventUserPoolsDefineAuthChallenge }
impl_from_for_cognito_challenge_event! { CognitoEventUserPoolsCreateAuthChallenge }
impl_from_for_cognito_challenge_event! { CognitoEventUserPoolsVerifyAuthChallenge }

fn try_convert_cognito_event_user_pools_header_trigger_source<T, U>(
    value: CognitoEventUserPoolsHeader<T>,
) -> Result<CognitoEventUserPoolsHeader<U>, Error>
where
    T: TryInto<U, Error=Error>,
{
    Ok(CognitoEventUserPoolsHeader {
        version: value.version,
        trigger_source: value.trigger_source.map(TryInto::try_into).transpose()?,
        region: value.region,
        user_pool_id: value.user_pool_id,
        caller_context: value.caller_context,
        user_name: value.user_name,
    })
}

fn convert_cognito_event_user_pools_header_trigger_source<T, U>(
    value: CognitoEventUserPoolsHeader<T>,
) -> CognitoEventUserPoolsHeader<U>
where
    T: Into<U>,
{
    CognitoEventUserPoolsHeader {
        version: value.version,
        trigger_source: value.trigger_source.map(Into::into),
        region: value.region,
        user_pool_id: value.user_pool_id,
        caller_context: value.caller_context,
        user_name: value.user_name,
    }
}

/// Universal trigger source for Cognito user pools.
#[allow(missing_docs)]
#[derive(Deserialize, Serialize, Clone, Debug, Default, Eq, PartialEq)]
#[serde(untagged)]
pub enum UniversalTriggerSource {
    /// For `Default` derivation, and should not be used.
    #[default]
    Null,
    PreSignup(CognitoEventUserPoolsPreSignupTriggerSource),
    MigrateUser(CognitoEventUserPoolsMigrateUserTriggerSource),
    PreTokenGen(CognitoEventUserPoolsPreTokenGenTriggerSource),
    CustomMessage(CognitoEventUserPoolsCustomMessageTriggerSource),
    PostConfirmation(CognitoEventUserPoolsPostConfirmationTriggerSource),
    PreAuthentication(CognitoEventUserPoolsPreAuthenticationTriggerSource),
    PostAuthentication(CognitoEventUserPoolsPostAuthenticationTriggerSource),
    CreateAuthChallenge(CognitoEventUserPoolsCreateAuthChallengeTriggerSource),
    DefineAuthChallenge(CognitoEventUserPoolsDefineAuthChallengeTriggerSource),
    VerifyAuthChallenge(CognitoEventUserPoolsVerifyAuthChallengeTriggerSource),
}

macro_rules! impl_try_into_for_universal_trigger_source {
    ($from:ident, $into:ident) => {
        impl TryInto<$into> for UniversalTriggerSource {
            type Error = Error;

            fn try_into(self) -> Result<$into, Self::Error> {
                match self {
                    UniversalTriggerSource::$from(v) => Ok(v),
                    _ => Err(Error::Inconvertible(stringify!($from -> $into))),
                }
            }
        }
    };
}

impl_try_into_for_universal_trigger_source! {
    PreSignup,
    CognitoEventUserPoolsPreSignupTriggerSource
}
impl_try_into_for_universal_trigger_source! {
    MigrateUser,
    CognitoEventUserPoolsMigrateUserTriggerSource
}
impl_try_into_for_universal_trigger_source! {
    PreTokenGen,
    CognitoEventUserPoolsPreTokenGenTriggerSource
}
impl_try_into_for_universal_trigger_source! {
    CustomMessage,
    CognitoEventUserPoolsCustomMessageTriggerSource
}
impl_try_into_for_universal_trigger_source! {
    PostConfirmation,
    CognitoEventUserPoolsPostConfirmationTriggerSource
}
impl_try_into_for_universal_trigger_source! {
    PreAuthentication,
    CognitoEventUserPoolsPreAuthenticationTriggerSource
}
impl_try_into_for_universal_trigger_source! {
    PostAuthentication,
    CognitoEventUserPoolsPostAuthenticationTriggerSource
}
impl_try_into_for_universal_trigger_source! {
    CreateAuthChallenge,
    CognitoEventUserPoolsCreateAuthChallengeTriggerSource
}
impl_try_into_for_universal_trigger_source! {
    DefineAuthChallenge,
    CognitoEventUserPoolsDefineAuthChallengeTriggerSource
}
impl_try_into_for_universal_trigger_source! {
    VerifyAuthChallenge,
    CognitoEventUserPoolsVerifyAuthChallengeTriggerSource
}

macro_rules! impl_from_for_universal_trigger_source {
    ($from:ident, $into:ident) => {
        impl From<$from> for UniversalTriggerSource {
            fn from(from: $from) -> UniversalTriggerSource {
                UniversalTriggerSource::$into(from)
            }
        }
    }
}

impl_from_for_universal_trigger_source! {
    CognitoEventUserPoolsPreSignupTriggerSource,
    PreSignup
}
impl_from_for_universal_trigger_source! {
    CognitoEventUserPoolsMigrateUserTriggerSource,
    MigrateUser
}
impl_from_for_universal_trigger_source! {
    CognitoEventUserPoolsPreTokenGenTriggerSource,
    PreTokenGen
}
impl_from_for_universal_trigger_source! {
    CognitoEventUserPoolsCustomMessageTriggerSource,
    CustomMessage
}
impl_from_for_universal_trigger_source! {
    CognitoEventUserPoolsPostConfirmationTriggerSource,
    PostConfirmation
}
impl_from_for_universal_trigger_source! {
    CognitoEventUserPoolsPreAuthenticationTriggerSource,
    PreAuthentication
}
impl_from_for_universal_trigger_source! {
    CognitoEventUserPoolsPostAuthenticationTriggerSource,
    PostAuthentication
}
impl_from_for_universal_trigger_source! {
    CognitoEventUserPoolsCreateAuthChallengeTriggerSource,
    CreateAuthChallenge
}
impl_from_for_universal_trigger_source! {
    CognitoEventUserPoolsDefineAuthChallengeTriggerSource,
    DefineAuthChallenge
}
impl_from_for_universal_trigger_source! {
    CognitoEventUserPoolsVerifyAuthChallengeTriggerSource,
    VerifyAuthChallenge
}

/// Operations on
/// [`CognitoEventUserPoolsDefineAuthChallengeResponse`](https://docs.rs/aws_lambda_events/latest/aws_lambda_events/event/cognito/struct.CognitoEventUserPoolsDefineAuthChallengeResponse.html).
pub trait CognitoEventUserPoolsDefineAuthChallengeOps {
    /// Returns whether the user exists.
    fn user_exists(&self) -> bool;

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
    fn user_exists(&self) -> bool {
        !self.request.user_not_found
    }

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

/// Operations on
/// [`CognitoEventUserPoolsCreateAuthChallenge`](https://docs.rs/aws_lambda_events/latest/aws_lambda_events/event/cognito/struct.CognitoEventUserPoolsCreateAuthChallenge.html).
pub trait CognitoEventUserPoolsCreateAuthChallengeOps {
    /// Returns whether the user exists.
    fn user_exists(&self) -> bool;

    /// Returns the sessions.
    fn sessions(&self) -> &Vec<Option<CognitoEventUserPoolsChallengeResult>>;

    /// Sets the challenge metadata.
    fn set_challenge_metadata(&mut self, metadata: impl Into<String>);

    /// Sets a public challenge parameter.
    fn set_public_challenge_parameter(
        &mut self,
        key: impl Into<String>,
        value: &(impl Serialize + ?Sized),
    ) -> Result<(), Error>;

    /// Sets a private challenge parameter.
    fn set_private_challenge_parameter(
        &mut self,
        key: impl Into<String>,
        value: &(impl Serialize + ?Sized),
    ) -> Result<(), Error>;
}

impl CognitoEventUserPoolsCreateAuthChallengeOps
    for CognitoEventUserPoolsCreateAuthChallenge
{
    fn user_exists(&self) -> bool {
        !self.request.user_not_found
    }

    fn sessions(&self) -> &Vec<Option<CognitoEventUserPoolsChallengeResult>> {
        &self.request.session
    }

    fn set_challenge_metadata(&mut self, metadata: impl Into<String>) {
        self.response.challenge_metadata = Some(metadata.into());
    }

    fn set_public_challenge_parameter(
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

    fn set_private_challenge_parameter(
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

/// Operations on
/// [`CognitoEventUserPoolsVerifyAuthChallenge`](https://docs.rs/aws_lambda_events/latest/aws_lambda_events/event/cognito/struct.CognitoEventUserPoolsVerifyAuthChallenge.html).
pub trait CognitoEventUserPoolsVerifyAuthChallengeOps {
    /// Returns whether the user exists.
    fn user_exists(&self) -> bool;

    /// Obtains the challenge answer.
    fn get_challenge_answer<'de, T>(&'de self) -> Result<T, Error>
    where
        T: Deserialize<'de>;

    /// Returns the raw challenge answer.
    fn get_raw_challenge_answer(&self) -> Option<&str>;

    /// Obtains a private public parameter.
    fn get_private_challenge_parameter<'de, T, K>(
        &'de self,
        key: &K,
    ) -> Result<Option<T>, Error>
    where
        String: std::borrow::Borrow<K>,
        K: Eq + std::hash::Hash + ?Sized,
        T: Deserialize<'de>;

    /// Accepts the challenge answer.
    fn accept(&mut self);

    /// Rejects the challenge answer.
    fn reject(&mut self);
}

impl CognitoEventUserPoolsVerifyAuthChallengeOps
    for CognitoEventUserPoolsVerifyAuthChallenge
{
    fn user_exists(&self) -> bool {
        !self.request.user_not_found
    }

    fn get_challenge_answer<'de, T>(&'de self) -> Result<T, Error>
    where
        T: Deserialize<'de>,
    {
        let challenge_answer = self.request.challenge_answer
            .as_ref()
            .and_then(|v| v.as_str())
            .ok_or(Error::Inconvertible("missing challenge_answer"))?;
        serde_json::from_str(challenge_answer)
            .or(Err(Error::Inconvertible("incompatible challenge_answer")))
    }

    fn get_raw_challenge_answer(&self) -> Option<&str> {
        self.request.challenge_answer.as_ref().and_then(|v| v.as_str())
    }

    fn get_private_challenge_parameter<'de, T, K>(
        &'de self,
        key: &K,
    ) -> Result<Option<T>, Error>
    where
        String: std::borrow::Borrow<K>,
        K: Eq + std::hash::Hash + ?Sized,
        T: Deserialize<'de>,
    {
        self.request.private_challenge_parameters
            .get(key)
            .map(|v| serde_json::from_str(v)
                .or(Err(Error::Inconvertible("incompatible challenge parameter"))))
            .transpose()
    }

    fn accept(&mut self) {
        self.response.answer_correct = true;
    }

    fn reject(&mut self) {
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

impl TryInto<CognitoEventUserPoolsCreateAuthChallengeRequest>
    for CognitoChallengeEventRequest
{
    type Error = Error;

    fn try_into(self) ->
        Result<CognitoEventUserPoolsCreateAuthChallengeRequest, Self::Error>
    {
        Ok(CognitoEventUserPoolsCreateAuthChallengeRequest {
            user_attributes: self.user_attributes,
            challenge_name: self.challenge_name,
            session: self.session
                .ok_or(Error::Inconvertible("missing session"))?,
            client_metadata: self.client_metadata,
            user_not_found: self.user_not_found,
        })
    }
}

impl From<CognitoEventUserPoolsCreateAuthChallengeRequest>
    for CognitoChallengeEventRequest
{
    fn from(from: CognitoEventUserPoolsCreateAuthChallengeRequest) -> Self {
        Self {
            user_attributes: from.user_attributes,
            challenge_name: from.challenge_name,
            session: Some(from.session),
            client_metadata: from.client_metadata,
            user_not_found: from.user_not_found,
            private_challenge_parameters: None,
            challenge_answer: None,
        }
    }
}

impl TryInto<CognitoEventUserPoolsVerifyAuthChallengeRequest<serde_json::Value>>
    for CognitoChallengeEventRequest
{
    type Error = Error;

    fn try_into(self) -> Result<
        CognitoEventUserPoolsVerifyAuthChallengeRequest<serde_json::Value>,
        Self::Error,
    > {
        Ok(CognitoEventUserPoolsVerifyAuthChallengeRequest {
            user_attributes: self.user_attributes,
            private_challenge_parameters: self.private_challenge_parameters
                .ok_or(Error::Inconvertible("missing private_challenge_parameters"))?,
            challenge_answer: self.challenge_answer.map(|v| v.into()),
            client_metadata: self.client_metadata,
            user_not_found: self.user_not_found,
        })
    }
}

impl From<CognitoEventUserPoolsVerifyAuthChallengeRequest<serde_json::Value>>
    for CognitoChallengeEventRequest
{
    fn from(
        from: CognitoEventUserPoolsVerifyAuthChallengeRequest<serde_json::Value>,
    ) -> Self {
        Self {
            user_attributes: from.user_attributes,
            private_challenge_parameters:
                Some(from.private_challenge_parameters),
            challenge_answer: from.challenge_answer.and_then(|v| match v {
                serde_json::Value::String(s) => Some(s),
                _ => None,
            }),
            client_metadata: from.client_metadata,
            user_not_found: from.user_not_found,
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

impl Into<CognitoEventUserPoolsDefineAuthChallengeResponse>
    for CognitoChallengeEventResponse
{
    fn into(self) -> CognitoEventUserPoolsDefineAuthChallengeResponse {
        CognitoEventUserPoolsDefineAuthChallengeResponse {
            challenge_name: self.challenge_name,
            issue_tokens: self.issue_tokens.unwrap_or_default(),
            fail_authentication: self.fail_authentication.unwrap_or_default(),
        }
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

impl Into<CognitoEventUserPoolsCreateAuthChallengeResponse>
    for CognitoChallengeEventResponse
{
    fn into(self) -> CognitoEventUserPoolsCreateAuthChallengeResponse {
        CognitoEventUserPoolsCreateAuthChallengeResponse {
            public_challenge_parameters: self.public_challenge_parameters
                .unwrap_or_else(HashMap::new),
            private_challenge_parameters: self.private_challenge_parameters
                .unwrap_or_else(HashMap::new),
            challenge_metadata: self.challenge_metadata,
        }
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

impl Into<CognitoEventUserPoolsVerifyAuthChallengeResponse>
    for CognitoChallengeEventResponse
{
    fn into(self) -> CognitoEventUserPoolsVerifyAuthChallengeResponse {
        CognitoEventUserPoolsVerifyAuthChallengeResponse {
            answer_correct: self.answer_correct.unwrap_or_default(),
        }
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CognitoChallengeEventCase {
    /// [`CognitoEventUserPoolsDefineAuthChallenge`](https://docs.rs/aws_lambda_events/latest/aws_lambda_events/event/cognito/struct.CognitoEventUserPoolsDefineAuthChallenge.html).
    Define(CognitoEventUserPoolsDefineAuthChallenge),

    /// [`CognitoEventUserPoolsCreateAuthChallenge`](https://docs.rs/aws_lambda_events/latest/aws_lambda_events/event/cognito/struct.CognitoEventUserPoolsCreateAuthChallenge.html).
    Create(CognitoEventUserPoolsCreateAuthChallenge),

    /// [`CognitoEventUserPoolsVerifyAuthChallenge`](https://docs.rs/aws_lambda_events/latest/aws_lambda_events/event/cognito/struct.CognitoEventUserPoolsVerifyAuthChallenge.html).
    Verify(CognitoEventUserPoolsVerifyAuthChallenge),
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

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lambda_events::event::cognito::CognitoEventUserPoolsCallerContext;

    use UniversalTriggerSource::*;

    #[test]
    fn serialize_universal_trigger_source_pre_sign_up() {
        use CognitoEventUserPoolsPreSignupTriggerSource as TriggerSource;
        assert_eq!(serde_json::to_string(&PreSignup(TriggerSource::SignUp)).unwrap(), "\"PreSignUp_SignUp\"");
        assert_eq!(serde_json::to_string(&PreSignup(TriggerSource::AdminCreateUser)).unwrap(), "\"PreSignUp_AdminCreateUser\"");
        assert_eq!(serde_json::to_string(&PreSignup(TriggerSource::ExternalProvider)).unwrap(), "\"PreSignUp_ExternalProvider\"");
    }

    #[test]
    fn serialize_universal_trigger_source_migrate_user() {
        use CognitoEventUserPoolsMigrateUserTriggerSource as TriggerSource;
        assert_eq!(serde_json::to_string(&MigrateUser(TriggerSource::Authentication)).unwrap(), "\"UserMigration_Authentication\"");
        assert_eq!(serde_json::to_string(&MigrateUser(TriggerSource::ForgotPassword)).unwrap(), "\"UserMigration_ForgotPassword\"");
    }

    #[test]
    fn serialize_universal_trigger_source_pre_token_gen() {
        use CognitoEventUserPoolsPreTokenGenTriggerSource as TriggerSource;
        assert_eq!(serde_json::to_string(&PreTokenGen(TriggerSource::HostedAuth)).unwrap(), "\"TokenGeneration_HostedAuth\"");
        assert_eq!(serde_json::to_string(&PreTokenGen(TriggerSource::Authentication)).unwrap(), "\"TokenGeneration_Authentication\"");
        assert_eq!(serde_json::to_string(&PreTokenGen(TriggerSource::NewPasswordChallenge)).unwrap(), "\"TokenGeneration_NewPasswordChallenge\"");
        assert_eq!(serde_json::to_string(&PreTokenGen(TriggerSource::AuthenticateDevice)).unwrap(), "\"TokenGeneration_AuthenticateDevice\"");
        assert_eq!(serde_json::to_string(&PreTokenGen(TriggerSource::RefreshTokens)).unwrap(), "\"TokenGeneration_RefreshTokens\"");
    }

    #[test]
    fn serialize_universal_trigger_source_custom_message() {
        use CognitoEventUserPoolsCustomMessageTriggerSource as TriggerSource;
        assert_eq!(serde_json::to_string(&CustomMessage(TriggerSource::SignUp)).unwrap(), "\"CustomMessage_SignUp\"");
        assert_eq!(serde_json::to_string(&CustomMessage(TriggerSource::AdminCreateUser)).unwrap(), "\"CustomMessage_AdminCreateUser\"");
        assert_eq!(serde_json::to_string(&CustomMessage(TriggerSource::ResendCode)).unwrap(), "\"CustomMessage_ResendCode\"");
        assert_eq!(serde_json::to_string(&CustomMessage(TriggerSource::ForgotPassword)).unwrap(), "\"CustomMessage_ForgotPassword\"");
        assert_eq!(serde_json::to_string(&CustomMessage(TriggerSource::UpdateUserAttribute)).unwrap(), "\"CustomMessage_UpdateUserAttribute\"");
        assert_eq!(serde_json::to_string(&CustomMessage(TriggerSource::VerifyUserAttribute)).unwrap(), "\"CustomMessage_VerifyUserAttribute\"");
        assert_eq!(serde_json::to_string(&CustomMessage(TriggerSource::Authentication)).unwrap(), "\"CustomMessage_Authentication\"");
    }

    #[test]
    fn serialize_universal_trigger_source_post_confirmation() {
        use CognitoEventUserPoolsPostConfirmationTriggerSource as TriggerSource;
        assert_eq!(serde_json::to_string(&PostConfirmation(TriggerSource::ConfirmForgotPassword)).unwrap(), "\"PostConfirmation_ConfirmForgotPassword\"");
        assert_eq!(serde_json::to_string(&PostConfirmation(TriggerSource::ConfirmSignUp)).unwrap(), "\"PostConfirmation_ConfirmSignUp\"");
    }

    #[test]
    fn serialize_universal_trigger_source_pre_authentication() {
        use CognitoEventUserPoolsPreAuthenticationTriggerSource as TriggerSource;
        assert_eq!(serde_json::to_string(&PreAuthentication(TriggerSource::Authentication)).unwrap(), "\"PreAuthentication_Authentication\"");
    }

    #[test]
    fn serialize_universal_trigger_source_post_authentication() {
        use CognitoEventUserPoolsPostAuthenticationTriggerSource as TriggerSource;
        assert_eq!(serde_json::to_string(&PostAuthentication(TriggerSource::Authentication)).unwrap(), "\"PostAuthentication_Authentication\"");
    }

    #[test]
    fn serialize_universal_trigger_source_create_auth_challenge() {
        use CognitoEventUserPoolsCreateAuthChallengeTriggerSource as TriggerSource;
        assert_eq!(serde_json::to_string(&CreateAuthChallenge(TriggerSource::Authentication)).unwrap(), "\"CreateAuthChallenge_Authentication\"");
    }

    #[test]
    fn serialize_universal_trigger_source_define_auth_challenge() {
        use CognitoEventUserPoolsDefineAuthChallengeTriggerSource as TriggerSource;
        assert_eq!(serde_json::to_string(&DefineAuthChallenge(TriggerSource::Authentication)).unwrap(), "\"DefineAuthChallenge_Authentication\"");
    }

    #[test]
    fn serialize_universal_trigger_source_verify_auth_challenge() {
        use CognitoEventUserPoolsVerifyAuthChallengeTriggerSource as TriggerSource;
        assert_eq!(serde_json::to_string(&VerifyAuthChallenge(TriggerSource::Authentication)).unwrap(), "\"VerifyAuthChallengeResponse_Authentication\"");
    }

    #[test]
    fn serialize_universal_trigger_source_null() {
        assert_eq!(serde_json::to_string(&Null).unwrap(), "null");
    }

    fn deserialize_universal_trigger_source(s: &str) -> UniversalTriggerSource {
        serde_json::from_str::<UniversalTriggerSource>(&format!("\"{s}\"")).unwrap()
    }

    #[test]
    fn deserialize_universal_trigger_source_pre_sign_up() {
        use CognitoEventUserPoolsPreSignupTriggerSource as TriggerSource;
        assert_eq!(deserialize_universal_trigger_source("PreSignUp_SignUp"), PreSignup(TriggerSource::SignUp));
        assert_eq!(deserialize_universal_trigger_source("PreSignUp_AdminCreateUser"), PreSignup(TriggerSource::AdminCreateUser));
        assert_eq!(deserialize_universal_trigger_source("PreSignUp_ExternalProvider"), PreSignup(TriggerSource::ExternalProvider));
    }

    #[test]
    fn deserialize_universal_trigger_source_migrate_user() {
        use CognitoEventUserPoolsMigrateUserTriggerSource as TriggerSource;
        assert_eq!(deserialize_universal_trigger_source("UserMigration_Authentication"), MigrateUser(TriggerSource::Authentication));
        assert_eq!(deserialize_universal_trigger_source("UserMigration_ForgotPassword"), MigrateUser(TriggerSource::ForgotPassword));
    }

    #[test]
    fn deserialize_universal_trigger_source_pre_token_gen() {
        use CognitoEventUserPoolsPreTokenGenTriggerSource as TriggerSource;
        assert_eq!(deserialize_universal_trigger_source("TokenGeneration_HostedAuth"), PreTokenGen(TriggerSource::HostedAuth));
        assert_eq!(deserialize_universal_trigger_source("TokenGeneration_Authentication"), PreTokenGen(TriggerSource::Authentication));
        assert_eq!(deserialize_universal_trigger_source("TokenGeneration_NewPasswordChallenge"), PreTokenGen(TriggerSource::NewPasswordChallenge));
        assert_eq!(deserialize_universal_trigger_source("TokenGeneration_AuthenticateDevice"), PreTokenGen(TriggerSource::AuthenticateDevice));
        assert_eq!(deserialize_universal_trigger_source("TokenGeneration_RefreshTokens"), PreTokenGen(TriggerSource::RefreshTokens));
    }

    #[test]
    fn deserialize_universal_trigger_source_custom_message() {
        use CognitoEventUserPoolsCustomMessageTriggerSource as TriggerSource;
        assert_eq!(deserialize_universal_trigger_source("CustomMessage_SignUp"), CustomMessage(TriggerSource::SignUp));
        assert_eq!(deserialize_universal_trigger_source("CustomMessage_AdminCreateUser"), CustomMessage(TriggerSource::AdminCreateUser));
        assert_eq!(deserialize_universal_trigger_source("CustomMessage_ResendCode"), CustomMessage(TriggerSource::ResendCode));
        assert_eq!(deserialize_universal_trigger_source("CustomMessage_ForgotPassword"), CustomMessage(TriggerSource::ForgotPassword));
        assert_eq!(deserialize_universal_trigger_source("CustomMessage_UpdateUserAttribute"), CustomMessage(TriggerSource::UpdateUserAttribute));
        assert_eq!(deserialize_universal_trigger_source("CustomMessage_VerifyUserAttribute"), CustomMessage(TriggerSource::VerifyUserAttribute));
        assert_eq!(deserialize_universal_trigger_source("CustomMessage_Authentication"), CustomMessage(TriggerSource::Authentication));
    }

    #[test]
    fn deserialize_universal_trigger_source_post_confirmation() {
        use CognitoEventUserPoolsPostConfirmationTriggerSource as TriggerSource;
        assert_eq!(deserialize_universal_trigger_source("PostConfirmation_ConfirmForgotPassword"), PostConfirmation(TriggerSource::ConfirmForgotPassword));
        assert_eq!(deserialize_universal_trigger_source("PostConfirmation_ConfirmSignUp"), PostConfirmation(TriggerSource::ConfirmSignUp));
    }

    #[test]
    fn deserialize_universal_trigger_source_pre_authentication() {
        use CognitoEventUserPoolsPreAuthenticationTriggerSource as TriggerSource;
        assert_eq!(deserialize_universal_trigger_source("PreAuthentication_Authentication"), PreAuthentication(TriggerSource::Authentication));
    }

    #[test]
    fn deserialize_universal_trigger_source_post_authentication() {
        use CognitoEventUserPoolsPostAuthenticationTriggerSource as TriggerSource;
        assert_eq!(deserialize_universal_trigger_source("PostAuthentication_Authentication"), PostAuthentication(TriggerSource::Authentication));
    }

    #[test]
    fn deserialize_universal_trigger_source_create_auth_challenge() {
        use CognitoEventUserPoolsCreateAuthChallengeTriggerSource as TriggerSource;
        assert_eq!(deserialize_universal_trigger_source("CreateAuthChallenge_Authentication"), CreateAuthChallenge(TriggerSource::Authentication));
    }

    #[test]
    fn deserialize_universal_trigger_source_define_auth_challenge() {
        use CognitoEventUserPoolsDefineAuthChallengeTriggerSource as TriggerSource;
        assert_eq!(deserialize_universal_trigger_source("DefineAuthChallenge_Authentication"), DefineAuthChallenge(TriggerSource::Authentication));
    }

    #[test]
    fn deserialize_universal_trigger_source_verify_auth_challenge() {
        use CognitoEventUserPoolsVerifyAuthChallengeTriggerSource as TriggerSource;
        assert_eq!(deserialize_universal_trigger_source("VerifyAuthChallengeResponse_Authentication"), VerifyAuthChallenge(TriggerSource::Authentication));
    }

    #[test]
    fn deserialize_universal_trigger_source_null() {
        assert_eq!(serde_json::from_str::<UniversalTriggerSource>("null").unwrap(), Null);
    }

    #[test]
    fn deserialize_universal_trigger_source_invalid() {
        assert!(serde_json::from_str::<UniversalTriggerSource>("\"Undefined\"").is_err());
        assert!(serde_json::from_str::<UniversalTriggerSource>("\"\"").is_err());
    }

    #[test]
    fn cognito_challenge_event_can_determine_define_auth_challenge() {
        let event = CognitoChallengeEvent {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader {
                version: Some("1".into()),
                trigger_source: Some(DefineAuthChallenge(CognitoEventUserPoolsDefineAuthChallengeTriggerSource::Authentication)),
                region: Some("ap-northeast-1".into()),
                user_pool_id: Some("ap-northeast-1_XYZ".into()),
                caller_context: CognitoEventUserPoolsCallerContext {
                    awssdk_version: Some("aws-sdk-js-3.437.0".into()),
                    client_id: Some("xyz".into()),
                },
                user_name: Some("kemoto".into()),
            },
            request: CognitoChallengeEventRequest {
                user_attributes: HashMap::from([
                    ("sub".into(), "xyz".into()),
                    ("cognito:user_status".into(), "CONFIRMED".into()),
                ]),
                challenge_name: None,
                session: Some(vec![]),
                private_challenge_parameters: None,
                challenge_answer: None,
                client_metadata: HashMap::new(),
                user_not_found: false,
            },
            response: CognitoChallengeEventResponse {
                challenge_name: None,
                issue_tokens: None,
                fail_authentication: None,
                public_challenge_parameters: None,
                private_challenge_parameters: None,
                challenge_metadata: None,
                answer_correct: None,
            },
        };
        let expected = CognitoEventUserPoolsDefineAuthChallenge {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader {
                version: event.cognito_event_user_pools_header.version.clone(),
                trigger_source: Some(CognitoEventUserPoolsDefineAuthChallengeTriggerSource::Authentication),
                region: event.cognito_event_user_pools_header.region.clone(),
                user_pool_id: event.cognito_event_user_pools_header.user_pool_id.clone(),
                caller_context: event.cognito_event_user_pools_header.caller_context.clone(),
                user_name: event.cognito_event_user_pools_header.user_name.clone(),
            },
            request: CognitoEventUserPoolsDefineAuthChallengeRequest {
                user_attributes: event.request.user_attributes.clone(),
                session: vec![],
                client_metadata: HashMap::new(),
                user_not_found: false,
            },
            response: CognitoEventUserPoolsDefineAuthChallengeResponse {
                challenge_name: None,
                issue_tokens: false,
                fail_authentication: false,
            },
        };
        assert_eq!(event.determine().unwrap(), CognitoChallengeEventCase::Define(expected));
    }

    #[test]
    fn cognito_challenge_event_can_determine_create_auth_challenge() {
        let event = CognitoChallengeEvent {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader {
                version: Some("1".into()),
                trigger_source: Some(CreateAuthChallenge(CognitoEventUserPoolsCreateAuthChallengeTriggerSource::Authentication)),
                region: Some("ap-northeast-1".into()),
                user_pool_id: Some("ap-northeast-1_XYZ".into()),
                caller_context: CognitoEventUserPoolsCallerContext {
                    awssdk_version: Some("aws-sdk-js-3.437.0".into()),
                    client_id: Some("xyz".into()),
                },
                user_name: Some("kemoto".into()),
            },
            request: CognitoChallengeEventRequest {
                user_attributes: HashMap::from([
                    ("cognito:user_status".into(), "CONFIRMED".into()),
                    ("sub".into(), "xyz".into()),
                ]),
                challenge_name: Some("CUSTOM_CHALLENGE".into()),
                session: Some(vec![]),
                private_challenge_parameters: None,
                challenge_answer: None,
                client_metadata: HashMap::new(),
                user_not_found: false,
            },
            response: CognitoChallengeEventResponse {
                challenge_name: None,
                issue_tokens: None,
                fail_authentication: None,
                public_challenge_parameters: None,
                private_challenge_parameters: None,
                challenge_metadata: None,
                answer_correct: None,
            },
        };
        let expected = CognitoEventUserPoolsCreateAuthChallenge {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader {
                version: event.cognito_event_user_pools_header.version.clone(),
                trigger_source: Some(CognitoEventUserPoolsCreateAuthChallengeTriggerSource::Authentication),
                region: event.cognito_event_user_pools_header.region.clone(),
                user_pool_id: event.cognito_event_user_pools_header.user_pool_id.clone(),
                caller_context: event.cognito_event_user_pools_header.caller_context.clone(),
                user_name: event.cognito_event_user_pools_header.user_name.clone(),
            },
            request: CognitoEventUserPoolsCreateAuthChallengeRequest {
                user_attributes: event.request.user_attributes.clone(),
                challenge_name: Some("CUSTOM_CHALLENGE".into()),
                session: vec![],
                client_metadata: HashMap::new(),
                user_not_found: false,
            },
            response: CognitoEventUserPoolsCreateAuthChallengeResponse {
                public_challenge_parameters: HashMap::new(),
                private_challenge_parameters: HashMap::new(),
                challenge_metadata: None,
            },
        };
        assert_eq!(event.determine().unwrap(), CognitoChallengeEventCase::Create(expected));
    }

    #[test]
    fn cognito_challenge_event_can_determine_verify_auth_challenge() {
        let event = CognitoChallengeEvent {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader {
                version: Some("1".into()),
                trigger_source: Some(VerifyAuthChallenge(CognitoEventUserPoolsVerifyAuthChallengeTriggerSource::Authentication)),
                region: Some("ap-northeast-1".into()),
                user_pool_id: Some("ap-northeast-1_XYZ".into()),
                caller_context: CognitoEventUserPoolsCallerContext {
                    awssdk_version: Some("aws-sdk-js-3.437.0".into()),
                    client_id: Some("xyz".into()),
                }, user_name: Some("kemoto".into()),
            },
            request: CognitoChallengeEventRequest {
                user_attributes: HashMap::from([
                    ("sub".into(), "xyz".into()),
                    ("cognito:user_status".into(), "CONFIRMED".into()),
                ]),
                challenge_name: None,
                session: None,
                private_challenge_parameters: Some(HashMap::from([
                    ("passkeyTestChallenge".into(), "{\"dummy\":\"dummy\"}".into()),
                ])),
                challenge_answer: Some("{\"dummy\":\"dummy\"}".into()),
                client_metadata: HashMap::new(),
                user_not_found: false,
            },
            response: CognitoChallengeEventResponse {
                challenge_name: None,
                issue_tokens: None,
                fail_authentication: None,
                public_challenge_parameters: None,
                private_challenge_parameters: None,
                challenge_metadata: None,
                answer_correct: None,
            },
        };
        let expected = CognitoEventUserPoolsVerifyAuthChallenge {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader {
                version: event.cognito_event_user_pools_header.version.clone(),
                trigger_source: Some(CognitoEventUserPoolsVerifyAuthChallengeTriggerSource::Authentication),
                region: event.cognito_event_user_pools_header.region.clone(),
                user_pool_id: event.cognito_event_user_pools_header.user_pool_id.clone(),
                caller_context: event.cognito_event_user_pools_header.caller_context.clone(),
                user_name: event.cognito_event_user_pools_header.user_name.clone(),
            },
            request: CognitoEventUserPoolsVerifyAuthChallengeRequest {
                user_attributes: event.request.user_attributes.clone(),
                private_challenge_parameters: HashMap::from([
                    ("passkeyTestChallenge".into(), "{\"dummy\":\"dummy\"}".into()),
                ]),
                challenge_answer: Some("{\"dummy\":\"dummy\"}".into()),
                client_metadata: HashMap::new(),
                user_not_found: false,
            },
            response: CognitoEventUserPoolsVerifyAuthChallengeResponse {
                answer_correct: false,
            },
        };
        assert_eq!(event.determine().unwrap(), CognitoChallengeEventCase::Verify(expected));
    }

    #[test]
    fn cognito_challenge_event_can_guess_define_auth_challenge_without_trigger_source() {
        let event = CognitoChallengeEvent {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader::default(),
            request: CognitoChallengeEventRequest {
                user_attributes: HashMap::new(),
                challenge_name: None,
                session: Some(vec![]),
                private_challenge_parameters: None,
                challenge_answer: None,
                client_metadata: HashMap::new(),
                user_not_found: false,
            },
            response: CognitoChallengeEventResponse {
                challenge_name: None,
                issue_tokens: None,
                fail_authentication: None,
                public_challenge_parameters: None,
                private_challenge_parameters: None,
                challenge_metadata: None,
                answer_correct: None,
            },
        };
        let expected = CognitoEventUserPoolsDefineAuthChallenge {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader::default(),
            request: CognitoEventUserPoolsDefineAuthChallengeRequest {
                user_attributes: HashMap::new(),
                session: vec![],
                client_metadata: HashMap::new(),
                user_not_found: false,
            },
            response: CognitoEventUserPoolsDefineAuthChallengeResponse {
                challenge_name: None,
                issue_tokens: false,
                fail_authentication: false,
            },
        };
        assert_eq!(event.determine().unwrap(), CognitoChallengeEventCase::Define(expected));
    }

    #[test]
    fn cognito_challenge_event_can_guess_create_auth_challenge_without_trigger_source() {
        let event = CognitoChallengeEvent {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader::default(),
            request: CognitoChallengeEventRequest {
                user_attributes: HashMap::new(),
                challenge_name: Some("CUSTOM_CHALLENGE".into()),
                session: Some(vec![]),
                private_challenge_parameters: None,
                challenge_answer: None,
                client_metadata: HashMap::new(),
                user_not_found: false,
            },
            response: CognitoChallengeEventResponse {
                challenge_name: None,
                issue_tokens: None,
                fail_authentication: None,
                public_challenge_parameters: None,
                private_challenge_parameters: None,
                challenge_metadata: None,
                answer_correct: None,
            },
        };
        let expected = CognitoEventUserPoolsCreateAuthChallenge {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader::default(),
            request: CognitoEventUserPoolsCreateAuthChallengeRequest {
                user_attributes: HashMap::new(),
                challenge_name: Some("CUSTOM_CHALLENGE".into()),
                session: vec![],
                client_metadata: HashMap::new(),
                user_not_found: false,
            },
            response: CognitoEventUserPoolsCreateAuthChallengeResponse {
                public_challenge_parameters: HashMap::new(),
                private_challenge_parameters: HashMap::new(),
                challenge_metadata: None,
            },
        };
        assert_eq!(event.determine().unwrap(), CognitoChallengeEventCase::Create(expected));
    }

    #[test]
    fn cognito_challenge_event_can_guess_verify_auth_challenge_without_trigger_source() {
        let event = CognitoChallengeEvent {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader::default(),
            request: CognitoChallengeEventRequest {
                user_attributes: HashMap::new(),
                challenge_name: None,
                session: None,
                private_challenge_parameters: Some(HashMap::from([
                    ("passkeyTestChallenge".into(), "{\"dummy\":\"dummy\"}".into()),
                ])),
                challenge_answer: Some("{\"dummy\":\"dummy\"}".into()),
                client_metadata: HashMap::new(),
                user_not_found: false,
            },
            response: CognitoChallengeEventResponse {
                challenge_name: None,
                issue_tokens: None,
                fail_authentication: None,
                public_challenge_parameters: None,
                private_challenge_parameters: None,
                challenge_metadata: None,
                answer_correct: None,
            },
        };
        let expected = CognitoEventUserPoolsVerifyAuthChallenge {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader::default(),
            request: CognitoEventUserPoolsVerifyAuthChallengeRequest {
                user_attributes: HashMap::new(),
                private_challenge_parameters: HashMap::from([
                    ("passkeyTestChallenge".into(), "{\"dummy\":\"dummy\"}".into()),
                ]),
                challenge_answer: Some("{\"dummy\":\"dummy\"}".into()),
                client_metadata: HashMap::new(),
                user_not_found: false,
            },
            response: CognitoEventUserPoolsVerifyAuthChallengeResponse {
                answer_correct: false,
            },
        };
        assert_eq!(event.determine().unwrap(), CognitoChallengeEventCase::Verify(expected));
    }

    #[test]
    fn cognito_challenge_event_should_supplement_user_not_found_for_create_auth_challenge() {
        let event = CognitoChallengeEvent {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader::default(),
            request: CognitoChallengeEventRequest {
                user_attributes: HashMap::new(),
                challenge_name: Some("CUSTOM_CHALLENGE".into()),
                session: Some(vec![]),
                private_challenge_parameters: None,
                challenge_answer: None,
                client_metadata: HashMap::new(),
                user_not_found: true,
            },
            response: CognitoChallengeEventResponse {
                challenge_name: None,
                issue_tokens: None,
                fail_authentication: None,
                public_challenge_parameters: None,
                private_challenge_parameters: None,
                challenge_metadata: None,
                answer_correct: None,
            },
        };
        let expected = CognitoEventUserPoolsCreateAuthChallenge {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader::default(),
            request: CognitoEventUserPoolsCreateAuthChallengeRequest {
                user_attributes: HashMap::new(),
                challenge_name: Some("CUSTOM_CHALLENGE".into()),
                session: vec![],
                client_metadata: HashMap::new(),
                user_not_found: true,
            },
            response: CognitoEventUserPoolsCreateAuthChallengeResponse {
                public_challenge_parameters: HashMap::new(),
                private_challenge_parameters: HashMap::new(),
                challenge_metadata: None,
            },
        };
        assert_eq!(event.determine().unwrap(), CognitoChallengeEventCase::Create(expected));
    }

    #[test]
    fn cognito_challenge_event_should_supplement_user_not_found_for_verify_auth_challenge() {
        let event = CognitoChallengeEvent {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader::default(),
            request: CognitoChallengeEventRequest {
                user_attributes: HashMap::new(),
                challenge_name: None,
                session: None,
                private_challenge_parameters: Some(HashMap::from([
                    ("passkeyTestChallenge".into(), "{\"dummy\":\"dummy\"}".into()),
                ])),
                challenge_answer: Some("{\"dummy\":\"dummy\"}".into()),
                client_metadata: HashMap::new(),
                user_not_found: true,
            },
            response: CognitoChallengeEventResponse {
                challenge_name: None,
                issue_tokens: None,
                fail_authentication: None,
                public_challenge_parameters: None,
                private_challenge_parameters: None,
                challenge_metadata: None,
                answer_correct: None,
            },
        };
        let expected = CognitoEventUserPoolsVerifyAuthChallenge {
            cognito_event_user_pools_header: CognitoEventUserPoolsHeader::default(),
            request: CognitoEventUserPoolsVerifyAuthChallengeRequest {
                user_attributes: HashMap::new(),
                private_challenge_parameters: HashMap::from([
                    ("passkeyTestChallenge".into(), "{\"dummy\":\"dummy\"}".into()),
                ]),
                challenge_answer: Some("{\"dummy\":\"dummy\"}".into()),
                client_metadata: HashMap::new(),
                user_not_found: true,
            },
            response: CognitoEventUserPoolsVerifyAuthChallengeResponse {
                answer_correct: false,
            },
        };
        assert_eq!(event.determine().unwrap(), CognitoChallengeEventCase::Verify(expected));
    }
}
