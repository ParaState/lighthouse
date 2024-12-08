use super::types::*;
use crate::Error;
use account_utils::ZeroizeString;
use reqwest::{
    header::{HeaderMap, HeaderValue},
    IntoUrl,
};
use sensitive_url::SensitiveUrl;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::{self, Display};
use std::fs;
use std::path::Path;

pub use reqwest;
pub use reqwest::{Response, StatusCode, Url};
use types::graffiti::GraffitiString;

/// A wrapper around `reqwest::Client` which provides convenience methods for interfacing with a
/// Lighthouse Validator Client HTTP server (`validator_client/src/http_api`).
#[derive(Clone)]
pub struct ValidatorClientHttpClient {
    client: reqwest::Client,
    server: SensitiveUrl,
    api_token: Option<ZeroizeString>,
    authorization_header: AuthorizationHeader,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthorizationHeader {
    /// Do not send any Authorization header.
    Omit,
    /// Send a `Basic` Authorization header (legacy).
    Basic,
    /// Send a `Bearer` Authorization header.
    Bearer,
}

impl Display for AuthorizationHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // The `Omit` variant should never be `Display`ed, but would result in a harmless rejection.
        write!(f, "{:?}", self)
    }
}

impl ValidatorClientHttpClient {
    /// Create a new client pre-initialised with an API token.
    pub fn new(server: SensitiveUrl, secret: String) -> Result<Self, Error> {
        Ok(Self {
            client: reqwest::Client::new(),
            server,
            api_token: Some(secret.into()),
            authorization_header: AuthorizationHeader::Bearer,
        })
    }

    /// Create a client without an API token.
    ///
    /// A token can be fetched by using `self.get_auth`, and then reading the token from disk.
    pub fn new_unauthenticated(server: SensitiveUrl) -> Result<Self, Error> {
        Ok(Self {
            client: reqwest::Client::new(),
            server,
            api_token: None,
            authorization_header: AuthorizationHeader::Omit,
        })
    }

    pub fn from_components(
        server: SensitiveUrl,
        client: reqwest::Client,
        secret: String,
    ) -> Result<Self, Error> {
        Ok(Self {
            client,
            server,
            api_token: Some(secret.into()),
            authorization_header: AuthorizationHeader::Bearer,
        })
    }

    /// Get a reference to this client's API token, if any.
    pub fn api_token(&self) -> Option<&ZeroizeString> {
        self.api_token.as_ref()
    }

    /// Read an API token from the specified `path`, stripping any trailing whitespace.
    pub fn load_api_token_from_file(path: &Path) -> Result<ZeroizeString, Error> {
        let token = fs::read_to_string(path).map_err(|e| Error::TokenReadError(path.into(), e))?;
        Ok(ZeroizeString::from(token.trim_end().to_string()))
    }

    /// Add an authentication token to use when making requests.
    pub fn add_auth_token(&mut self, token: ZeroizeString) -> Result<(), Error> {
        self.api_token = Some(token);
        self.authorization_header = AuthorizationHeader::Bearer;

        Ok(())
    }

    /// Set to `false` to disable sending the `Authorization` header on requests.
    ///
    /// Failing to send the `Authorization` header will cause the VC to reject requests with a 403.
    /// This function is intended only for testing purposes.
    pub fn send_authorization_header(&mut self, should_send: bool) {
        if should_send {
            self.authorization_header = AuthorizationHeader::Bearer;
        } else {
            self.authorization_header = AuthorizationHeader::Omit;
        }
    }

    /// Use the legacy basic auth style (bearer auth preferred by default now).
    pub fn use_basic_auth(&mut self) {
        self.authorization_header = AuthorizationHeader::Basic;
    }

    fn headers(&self) -> Result<HeaderMap, Error> {
        let mut headers = HeaderMap::new();

        if self.authorization_header == AuthorizationHeader::Basic
            || self.authorization_header == AuthorizationHeader::Bearer
        {
            let auth_header_token = self.api_token().ok_or(Error::NoToken)?;
            let header_value = HeaderValue::from_str(&format!(
                "{} {}",
                self.authorization_header,
                auth_header_token.as_str()
            ))
            .map_err(|e| {
                Error::InvalidSecret(format!("secret is invalid as a header value: {}", e))
            })?;

            headers.insert("Authorization", header_value);
        }

        Ok(headers)
    }

    /// Perform a HTTP GET request, returning the `Response` for further processing.
    async fn get_response<U: IntoUrl>(&self, url: U) -> Result<Response, Error> {
        let response = self
            .client
            .get(url)
            .headers(self.headers()?)
            .send()
            .await
            .map_err(Error::from)?;
        ok_or_error(response).await
    }

    /// Perform a HTTP DELETE request, returning the `Response` for further processing.
    async fn delete_response<U: IntoUrl>(&self, url: U) -> Result<Response, Error> {
        let response = self
            .client
            .delete(url)
            .headers(self.headers()?)
            .send()
            .await
            .map_err(Error::from)?;
        ok_or_error(response).await
    }

    async fn get<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<T, Error> {
        let response = self.get_response(url).await?;
        let body = response.bytes().await.map_err(Error::from)?;
        serde_json::from_slice(&body).map_err(Error::InvalidJson)
    }

    async fn delete<U: IntoUrl>(&self, url: U) -> Result<(), Error> {
        let response = self.delete_response(url).await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::StatusCode(response.status()))
        }
    }

    async fn get_unsigned<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<T, Error> {
        self.get_response(url)
            .await?
            .json()
            .await
            .map_err(Error::from)
    }

    /// Perform a HTTP GET request, returning `None` on a 404 error.
    async fn get_opt<T: DeserializeOwned, U: IntoUrl>(&self, url: U) -> Result<Option<T>, Error> {
        match self.get_response(url).await {
            Ok(resp) => {
                let body = resp.bytes().await.map(Option::Some)?;
                if let Some(body) = body {
                    serde_json::from_slice(&body).map_err(Error::InvalidJson)
                } else {
                    Ok(None)
                }
            }
            Err(err) => {
                if err.status() == Some(StatusCode::NOT_FOUND) {
                    Ok(None)
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Perform a HTTP POST request.
    async fn post_with_raw_response<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
    ) -> Result<Response, Error> {
        let response = self
            .client
            .post(url)
            .headers(self.headers()?)
            .json(body)
            .send()
            .await
            .map_err(Error::from)?;
        ok_or_error(response).await
    }

    async fn post<T: Serialize, U: IntoUrl, V: DeserializeOwned>(
        &self,
        url: U,
        body: &T,
    ) -> Result<V, Error> {
        let response = self.post_with_raw_response(url, body).await?;
        let body = response.bytes().await.map_err(Error::from)?;
        serde_json::from_slice(&body).map_err(Error::InvalidJson)
    }

    async fn post_with_unsigned_response<T: Serialize, U: IntoUrl, V: DeserializeOwned>(
        &self,
        url: U,
        body: &T,
    ) -> Result<V, Error> {
        let response = self.post_with_raw_response(url, body).await?;
        Ok(response.json().await?)
    }

    /// Perform a HTTP PATCH request.
    async fn patch<T: Serialize, U: IntoUrl>(&self, url: U, body: &T) -> Result<(), Error> {
        let response = self
            .client
            .patch(url)
            .headers(self.headers()?)
            .json(body)
            .send()
            .await
            .map_err(Error::from)?;
        ok_or_error(response).await?;
        Ok(())
    }

    /// Perform a HTTP DELETE request.
    async fn delete_with_raw_response<T: Serialize, U: IntoUrl>(
        &self,
        url: U,
        body: &T,
    ) -> Result<Response, Error> {
        let response = self
            .client
            .delete(url)
            .headers(self.headers()?)
            .json(body)
            .send()
            .await
            .map_err(Error::from)?;
        ok_or_error(response).await
    }

    /// Perform a HTTP DELETE request.
    async fn delete_with_unsigned_response<T: Serialize, U: IntoUrl, V: DeserializeOwned>(
        &self,
        url: U,
        body: &T,
    ) -> Result<V, Error> {
        let response = self.delete_with_raw_response(url, body).await?;
        Ok(response.json().await?)
    }

    /// `GET lighthouse/version`
    pub async fn get_lighthouse_version(&self) -> Result<GenericResponse<VersionData>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("version");

        self.get(path).await
    }

    /// `GET lighthouse/health`
    pub async fn get_lighthouse_health(&self) -> Result<GenericResponse<Health>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("health");

        self.get(path).await
    }

    /// `GET lighthouse/spec`
    pub async fn get_lighthouse_spec<T: Serialize + DeserializeOwned>(
        &self,
    ) -> Result<GenericResponse<T>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("spec");

        self.get(path).await
    }

    /// `GET lighthouse/validators`
    pub async fn get_lighthouse_validators(
        &self,
    ) -> Result<GenericResponse<Vec<ValidatorData>>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators");

        self.get(path).await
    }

    /// `GET lighthouse/validators/{validator_pubkey}`
    pub async fn get_lighthouse_validators_pubkey(
        &self,
        validator_pubkey: &PublicKeyBytes,
    ) -> Result<Option<GenericResponse<ValidatorData>>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push(&validator_pubkey.to_string());

        self.get_opt(path).await
    }

    /// `POST lighthouse/validators`
    pub async fn post_lighthouse_validators(
        &self,
        validators: Vec<ValidatorRequest>,
    ) -> Result<GenericResponse<PostValidatorsResponseData>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators");

        self.post(path, &validators).await
    }

    /// `POST lighthouse/validators/mnemonic`
    pub async fn post_lighthouse_validators_mnemonic(
        &self,
        request: &CreateValidatorsMnemonicRequest,
    ) -> Result<GenericResponse<Vec<CreatedValidator>>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push("mnemonic");

        self.post(path, &request).await
    }

    /// `POST lighthouse/validators/keystore`
    pub async fn post_lighthouse_validators_keystore(
        &self,
        request: &KeystoreValidatorsPostRequest,
    ) -> Result<GenericResponse<ValidatorData>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push("keystore");

        self.post(path, &request).await
    }

    /// `POST lighthouse/validators/web3signer`
    pub async fn post_lighthouse_validators_web3signer(
        &self,
        request: &[Web3SignerValidatorRequest],
    ) -> Result<(), Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push("web3signer");

        self.post(path, &request).await
    }

    /// `PATCH lighthouse/validators/{validator_pubkey}`
    #[allow(clippy::too_many_arguments)]
    pub async fn patch_lighthouse_validators(
        &self,
        voting_pubkey: &PublicKeyBytes,
        enabled: Option<bool>,
        gas_limit: Option<u64>,
        builder_proposals: Option<bool>,
        builder_boost_factor: Option<u64>,
        prefer_builder_proposals: Option<bool>,
        graffiti: Option<GraffitiString>,
    ) -> Result<(), Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push(&voting_pubkey.to_string());

        self.patch(
            path,
            &ValidatorPatchRequest {
                enabled,
                gas_limit,
                builder_proposals,
                builder_boost_factor,
                prefer_builder_proposals,
                graffiti,
            },
        )
        .await
    }

    /// `DELETE eth/v1/keystores`
    pub async fn delete_lighthouse_keystores(
        &self,
        req: &DeleteKeystoresRequest,
    ) -> Result<ExportKeystoresResponse, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("keystores");

        self.delete_with_unsigned_response(path, req).await
    }

    fn make_keystores_url(&self) -> Result<Url, Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("keystores");
        Ok(url)
    }

    fn make_remotekeys_url(&self) -> Result<Url, Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("remotekeys");
        Ok(url)
    }

    fn make_fee_recipient_url(&self, pubkey: &PublicKeyBytes) -> Result<Url, Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("validator")
            .push(&pubkey.to_string())
            .push("feerecipient");
        Ok(url)
    }

    fn make_graffiti_url(&self, pubkey: &PublicKeyBytes) -> Result<Url, Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("validator")
            .push(&pubkey.to_string())
            .push("graffiti");
        Ok(url)
    }

    fn make_gas_limit_url(&self, pubkey: &PublicKeyBytes) -> Result<Url, Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("validator")
            .push(&pubkey.to_string())
            .push("gas_limit");
        Ok(url)
    }

    /// `GET lighthouse/auth`
    pub async fn get_auth(&self) -> Result<AuthResponse, Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("auth");
        self.get_unsigned(url).await
    }

    /// `GET eth/v1/keystores`
    pub async fn get_keystores(&self) -> Result<ListKeystoresResponse, Error> {
        let url = self.make_keystores_url()?;
        self.get_unsigned(url).await
    }

    /// `POST eth/v1/keystores`
    pub async fn post_keystores(
        &self,
        req: &ImportKeystoresRequest,
    ) -> Result<ImportKeystoresResponse, Error> {
        let url = self.make_keystores_url()?;
        self.post_with_unsigned_response(url, req).await
    }

    /// `DELETE eth/v1/keystores`
    pub async fn delete_keystores(
        &self,
        req: &DeleteKeystoresRequest,
    ) -> Result<DeleteKeystoresResponse, Error> {
        let url = self.make_keystores_url()?;
        self.delete_with_unsigned_response(url, req).await
    }

    /// `GET eth/v1/remotekeys`
    pub async fn get_remotekeys(&self) -> Result<ListRemotekeysResponse, Error> {
        let url = self.make_remotekeys_url()?;
        self.get_unsigned(url).await
    }

    /// `POST eth/v1/remotekeys`
    pub async fn post_remotekeys(
        &self,
        req: &ImportRemotekeysRequest,
    ) -> Result<ImportRemotekeysResponse, Error> {
        let url = self.make_remotekeys_url()?;
        self.post_with_unsigned_response(url, req).await
    }

    /// `DELETE eth/v1/remotekeys`
    pub async fn delete_remotekeys(
        &self,
        req: &DeleteRemotekeysRequest,
    ) -> Result<DeleteRemotekeysResponse, Error> {
        let url = self.make_remotekeys_url()?;
        self.delete_with_unsigned_response(url, req).await
    }

    /// `GET /eth/v1/validator/{pubkey}/feerecipient`
    pub async fn get_fee_recipient(
        &self,
        pubkey: &PublicKeyBytes,
    ) -> Result<GetFeeRecipientResponse, Error> {
        let url = self.make_fee_recipient_url(pubkey)?;
        self.get(url)
            .await
            .map(|generic: GenericResponse<GetFeeRecipientResponse>| generic.data)
    }

    /// `POST /eth/v1/validator/{pubkey}/feerecipient`
    pub async fn post_fee_recipient(
        &self,
        pubkey: &PublicKeyBytes,
        req: &UpdateFeeRecipientRequest,
    ) -> Result<Response, Error> {
        let url = self.make_fee_recipient_url(pubkey)?;
        self.post_with_raw_response(url, req).await
    }

    /// `DELETE /eth/v1/validator/{pubkey}/feerecipient`
    pub async fn delete_fee_recipient(&self, pubkey: &PublicKeyBytes) -> Result<Response, Error> {
        let url = self.make_fee_recipient_url(pubkey)?;
        self.delete_with_raw_response(url, &()).await
    }

    /// `GET /eth/v1/validator/{pubkey}/gas_limit`
    pub async fn get_gas_limit(
        &self,
        pubkey: &PublicKeyBytes,
    ) -> Result<GetGasLimitResponse, Error> {
        let url = self.make_gas_limit_url(pubkey)?;
        self.get(url)
            .await
            .map(|generic: GenericResponse<GetGasLimitResponse>| generic.data)
    }

    /// `POST /eth/v1/validator/{pubkey}/gas_limit`
    pub async fn post_gas_limit(
        &self,
        pubkey: &PublicKeyBytes,
        req: &UpdateGasLimitRequest,
    ) -> Result<Response, Error> {
        let url = self.make_gas_limit_url(pubkey)?;
        self.post_with_raw_response(url, req).await
    }

    /// `DELETE /eth/v1/validator/{pubkey}/gas_limit`
    pub async fn delete_gas_limit(&self, pubkey: &PublicKeyBytes) -> Result<Response, Error> {
        let url = self.make_gas_limit_url(pubkey)?;
        self.delete_with_raw_response(url, &()).await
    }

    /// `POST /eth/v1/validator/{pubkey}/voluntary_exit`
    pub async fn post_validator_voluntary_exit(
        &self,
        pubkey: &PublicKeyBytes,
        epoch: Option<Epoch>,
    ) -> Result<GenericResponse<SignedVoluntaryExit>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("validator")
            .push(&pubkey.to_string())
            .push("voluntary_exit");

        if let Some(epoch) = epoch {
            path.query_pairs_mut()
                .append_pair("epoch", &epoch.to_string());
        }

        self.post(path, &()).await
    }

    /// `GET /eth/v1/validator/{pubkey}/graffiti`
    pub async fn get_graffiti(
        &self,
        pubkey: &PublicKeyBytes,
    ) -> Result<GetGraffitiResponse, Error> {
        let url = self.make_graffiti_url(pubkey)?;
        self.get(url)
            .await
            .map(|generic: GenericResponse<GetGraffitiResponse>| generic.data)
    }

    /// `POST /eth/v1/validator/{pubkey}/graffiti`
    pub async fn set_graffiti(
        &self,
        pubkey: &PublicKeyBytes,
        graffiti: GraffitiString,
    ) -> Result<(), Error> {
        let url = self.make_graffiti_url(pubkey)?;
        let set_graffiti_request = SetGraffitiRequest { graffiti };
        self.post(url, &set_graffiti_request).await
    }

    /// `DELETE /eth/v1/validator/{pubkey}/graffiti`
    pub async fn delete_graffiti(&self, pubkey: &PublicKeyBytes) -> Result<(), Error> {
        let url = self.make_graffiti_url(pubkey)?;
        self.delete(url).await
    }

    /// `POST lighthouse/validators/keystore_share`
    pub async fn post_validators_keystore_share(
        &self,
        request: &KeystoreShareValidatorPostRequest,
    ) -> Result<GenericResponse<ValidatorData>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push("keystore_share");

        self.post(path, &request).await
    }

    // DELETE lighthouse/validators/keystore_share
    pub async fn delete_validators_keystore_share(
        &self,
        req: &KeystoreShareValidatorPostRequest,
    ) -> Result<GenericResponse<ValidatorData>, Error> {
        let mut path = self.server.full.clone();

        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("lighthouse")
            .push("validators")
            .push("keystore_share");

        self.delete_with_unsigned_response(path, req).await
    }

    // POST /eth/v1/validator/{pubkey}/enable
    pub async fn post_validators_enable(&self, pubkey: &PublicKeyBytes) -> Result<(), Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("validator")
            .push(&pubkey.to_string())
            .push("enable");
        let _ = self
            .client
            .post(url)
            .headers(self.headers()?)
            .send()
            .await
            .map_err(Error::from)?;
        Ok(())
    }

    // POST /eth/v1/validator/{pubkey}/disable
    pub async fn post_validators_disable(&self, pubkey: &PublicKeyBytes) -> Result<(), Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("validator")
            .push(&pubkey.to_string())
            .push("disable");
        let _ = self
            .client
            .post(url)
            .headers(self.headers()?)
            .send()
            .await
            .map_err(Error::from)?;
        Ok(())
    }

    // POST /eth/v1/validator/{pubkey}/sign
    pub async fn post_keypair_sign(&self, pubkey: &PublicKeyBytes, msg: Hash256) -> Result<Option<Signature>, Error> {
        let mut url = self.server.full.clone();
        url.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server.clone()))?
            .push("eth")
            .push("v1")
            .push("validator")
            .push(&pubkey.to_string())
            .push("sign");
        let request = KeypairShareSignRequest { msg };
        let response: GenericResponse<KeypairShareSignResponse> = self.post(url, &request).await?;
        Ok(response.data.signature)
    }
}

/// Returns `Ok(response)` if the response is a `200 OK` response or a
/// `202 Accepted` response. Otherwise, creates an appropriate error message.
async fn ok_or_error(response: Response) -> Result<Response, Error> {
    let status = response.status();

    if status == StatusCode::OK
        || status == StatusCode::ACCEPTED
        || status == StatusCode::NO_CONTENT
    {
        Ok(response)
    } else if let Ok(message) = response.json().await {
        Err(Error::ServerMessage(message))
    } else {
        Err(Error::StatusCode(status))
    }
}
