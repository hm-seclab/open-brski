use brski_prm_artifacts::content_type::{JOSE, JSON, JWS_VOUCHER, PKCS7};
use common::server_error::ServerError;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use tracing::event;

use super::{PledgeCommunicator, PledgeCtx};

#[derive(Debug, Clone)]
pub struct HTTPCommunicator {
    client: reqwest::Client,
}

impl HTTPCommunicator {
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl PledgeCommunicator for HTTPCommunicator {
    async fn send_pvr_trigger(
        &self,
        trigger: String,
        ctx: PledgeCtx,
    ) -> Result<String, common::server_error::ServerError> {

        let url = format!("{}/.well-known/brski/tpvr", ctx.pledge_url);

        event!(tracing::Level::INFO, "Sending PVR to pledge at: {}", url);

        let response = self
            .client
            .post(url)
            .header(ACCEPT, "application/jose+json")
            .header(CONTENT_TYPE, JSON)
            .body(trigger)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ServerError::BadResponse(format!(
                "{}, {}",
                "Sending TPVR to pledge failed",
                response.status()
            )));
        }

        if let None = response.headers().get(CONTENT_TYPE) {
            return Err(ServerError::BadResponse(
                "No content type in response".to_string(),
            ));
        }

        if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
            if content_type != JWS_VOUCHER {
                return Err(ServerError::BadResponse(
                    "Wrong content type in response".to_string(),
                ));
            }
        }

        let response_data = response.text().await?;

        std::result::Result::Ok(response_data)
    }

    async fn send_per_trigger(
        &self,
        trigger: String,
        ctx: PledgeCtx,
    ) -> Result<String, common::server_error::ServerError> {

        let url = format!("{}/.well-known/brski/tper", ctx.pledge_url);
    
        event!(tracing::Level::INFO, "Sending tPER to pledge at {}", url);


        let response = self
            .client
            .post(url)
            .header(ACCEPT, "application/jose+json")
            .header(CONTENT_TYPE, JSON)
            .body(trigger)
            .send()
            .await?;

        event!(tracing::Level::INFO, "Received tPER response");

        event!(tracing::Level::INFO, "Verifying tPER response");

        if !response.status().is_success() {
            return Err(ServerError::BadResponse(
                "Sending PER to pledge failed".to_string(),
            ));
        }

        if response.headers().get(CONTENT_TYPE).is_none() {
            return Err(ServerError::BadResponse(
                "No content type in response".to_string(),
            ));
        }

        if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
            if content_type != JOSE {
                return Err(ServerError::BadResponse(
                    "Wrong content type in response".to_string(),
                ));
            }
        }

        let response_data = response.text().await?;

        std::result::Result::Ok(response_data)
    }

    async fn send_voucher(
        &self,
        voucher: String,
        ctx: PledgeCtx,
    ) -> Result<String, common::server_error::ServerError> {

        let url = format!(
            "{}/.well-known/brski/svr",
            ctx.pledge_url
        );
    
        event!(tracing::Level::INFO, "Sending Voucher to pledge at: {}", url);
        event!(tracing::Level::DEBUG, "Voucher: {}", voucher);

        let response = self
            .client
            .post(url)
            .header(CONTENT_TYPE, JWS_VOUCHER)
            .header(CONTENT_TYPE, JWS_VOUCHER)
            .body(voucher)
            .send()
            .await?;

        event!(tracing::Level::INFO, "Received response");

        if !response.status().is_success() {
            return Err(ServerError::BadResponse(format!(
                "Sending Voucher to pledge failed - Status: {}",
                response.status().to_string()
            )));
        }

        if response.headers().get(CONTENT_TYPE).is_none() {
            return Err(ServerError::BadResponse(
                "No content type in response".to_string(),
            ));
        }

        if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
            if content_type != JOSE {
                return Err(ServerError::BadResponse(
                    "Wrong content type in response".to_string(),
                ));
            }
        }

        let response_data = response.text().await?;

        std::result::Result::Ok(response_data)
    }

    async fn send_ca_certs(
        &self,
        cacerts: String,
        ctx: PledgeCtx,
    ) -> Result<(), common::server_error::ServerError> {

        let url = format!(
            "{}/.well-known/brski/scac",
            ctx.pledge_url
        );

        event!(tracing::Level::INFO, "Sending Wrapped CA Certs to pledge at: {}", url);
        event!(tracing::Level::DEBUG, "Wrapped CA Certs: {}", cacerts);

        let response = self
            .client
            .post(url)
            .header(CONTENT_TYPE, JOSE)
            .header(ACCEPT, JOSE)
            .body(cacerts)
            .send()
            .await?;

        event!(tracing::Level::INFO, "Received response");

        if !response.status().is_success() {
            return Err(ServerError::BadResponse(
                "Sending CA Certs to pledge failed".to_string(),
            ));
        }

        std::result::Result::Ok(())
    }

    async fn send_enroll_response(
        &self,
        response: Vec<u8>,
        ctx: PledgeCtx,
    ) -> Result<String, common::server_error::ServerError> {

        let url = format!(
            "{}/.well-known/brski/ser",
            ctx.pledge_url
        );
    
        event!(tracing::Level::INFO, "Sending Registrar Enroll-Response to pledge at: {}", url);
        event!(tracing::Level::DEBUG, "Registrar-Enroll-Response: {:?}", response);

        let response = self.client
            .post(url)
            .header(CONTENT_TYPE, PKCS7)
            .body(response)
            .send()
            .await?;

        event!(tracing::Level::INFO, "Received response");

        if !response.status().is_success() {
            return Err(ServerError::BadResponse(
                "Sending registrar enroll response to pledge failed".to_string(),
            ));
        }

        let response_body = response.text().await?;

        std::result::Result::Ok(response_body)
    }
}
