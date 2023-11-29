//! Provides access to parameters in Parameter Store on AWS Systems Manager.

use std::env;
use tracing::error;
use webauthn_rs::prelude::Url;

use crate::error::Error;

/// Loads the relying party origin from the Parameter Store.
///
/// You have to specify to `RP_ORIGIN_PARAMETER_PATH` environment variable the
/// path to the parameter that stores the origin (URL) of the relying party in
/// Parameter Store on AWS Systems Manager.
///
/// The domain of the URL is used as the ID of the relying party.
pub async fn load_relying_party_origin(
    ssm: aws_sdk_ssm::Client,
) -> Result<(String, Url), Error> {
    let parameter_name = env::var("RP_ORIGIN_PARAMETER_PATH")
        .map_err(|_| Error::ParameterNotFound("RP_ORIGIN_PARAMETER_PATH"))?;
    let origin = ssm.get_parameter()
        .name(parameter_name)
        .with_decryption(false)
        .send()
        .await
        .map_err(|e| {
            error!(?e, "getting SSM parameter");
            Error::ParameterNotFound("RP_ORIGIN_PARAMETER_PATH")
        })?
        .parameter
        .and_then(|p| p.value)
        .ok_or_else(|| {
            error!("missing SSM parameter value");
            Error::ParameterNotFound("RP_ORIGIN_PARAMETER_PATH")
        })?;
    parse_relying_party_origin(origin)
}

fn parse_relying_party_origin(origin: impl Into<String>) -> Result<(String, Url), Error> {
    let origin = origin.into();
    let rp_origin = Url::parse(&origin)
        .map_err(|e| {
            error!(?e, "parsing relying party origin");
            Error::BadRelyingPartyOrigin(origin.clone())
        })?;
    let rp_id = rp_origin.domain()
        .map(String::from)
        .ok_or_else(|| {
            error!("missing domain");
            Error::BadRelyingPartyOrigin(origin.clone())
        })?;
    Ok((rp_id, rp_origin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_relying_party_origin_should_extract_rp_id_and_origin_from_valid_url() {
        let origin = "http://localhost:5173";
        assert_eq!(
            parse_relying_party_origin(origin).unwrap(),
            ("localhost".to_string(), Url::parse(origin).unwrap()),
        );
        let origin = "https://passkey-test.codemonger.io";
        assert_eq!(
            parse_relying_party_origin(origin).unwrap(),
            ("passkey-test.codemonger.io".to_string(), Url::parse(origin).unwrap()),
        );
    }

    #[test]
    fn parse_relying_party_origin_should_fail_for_non_url() {
        let origin = "localhost:5173";
        assert!(parse_relying_party_origin(origin).is_err());
        let origin = "passkey-test.codemonger.io";
        assert!(parse_relying_party_origin(origin).is_err());
    }
}
