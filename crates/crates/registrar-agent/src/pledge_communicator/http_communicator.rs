use brski_prm_artifacts::token_type::{DataInterchangeFormat, PKCS7};
use common::server_error::ServerError;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use tracing::event;

use super::{DiscoveredPledge, PledgeCommunicator, PledgeCtx};

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
    #[tracing::instrument(skip(self, trigger, ctx))]
    async fn send_pvr_trigger(
        &self,
        trigger: Vec<u8>,
        ctx: PledgeCtx,
    ) -> Result<Vec<u8>, common::server_error::ServerError> {
        let url = format!("{}/.well-known/brski/tpvr", ctx.pledge_url);

        event!(tracing::Level::INFO, "Sending PVR to pledge at: {}", url);

        let response = self
            .client
            .post(url)
            .header(
                ACCEPT,
                ctx.pledge_info.supported_voucher_type.as_content_type(),
            )
            .header(
                CONTENT_TYPE,
                ctx.pledge_info.data_interchance_format.as_content_type(),
            )
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
            if content_type != ctx.pledge_info.supported_voucher_type.as_content_type() {
                return Err(ServerError::BadResponse(
                    "Wrong content type in response".to_string(),
                ));
            }
        }

        let response_data = response.bytes().await?;

        std::result::Result::Ok(response_data.to_vec())
    }

    #[tracing::instrument(skip(self, trigger, ctx))]
    async fn send_per_trigger(
        &self,
        trigger: Vec<u8>,
        ctx: PledgeCtx,
    ) -> Result<Vec<u8>, common::server_error::ServerError> {
        let url = format!("{}/.well-known/brski/tper", ctx.pledge_url);

        event!(tracing::Level::INFO, "Sending tPER to pledge at {}", url);

        let response = self
            .client
            .post(url)
            .header(
                ACCEPT,
                ctx.pledge_info.supported_token_type.as_content_type(),
            )
            .header(
                CONTENT_TYPE,
                ctx.pledge_info.data_interchance_format.as_content_type(),
            )
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
            if content_type != ctx.pledge_info.supported_token_type.as_content_type() {
                return Err(ServerError::BadResponse(
                    "Wrong content type in response".to_string(),
                ));
            }
        }

        let response_data = response.bytes().await?;

        std::result::Result::Ok(response_data.to_vec())
    }

    #[tracing::instrument(skip(self, voucher, ctx))]
    async fn send_voucher(
        &self,
        voucher: Vec<u8>,
        ctx: PledgeCtx,
    ) -> Result<Vec<u8>, common::server_error::ServerError> {
        let url = format!("{}/.well-known/brski/svr", ctx.pledge_url);

        event!(
            tracing::Level::INFO,
            "Sending Voucher to pledge at: {}",
            url
        );
        //event!(tracing::Level::DEBUG, "Voucher: {}", voucher);

        let response = self
            .client
            .post(url)
            .header(
                CONTENT_TYPE,
                ctx.pledge_info.supported_voucher_type.as_content_type(),
            )
            .header(
                ACCEPT,
                ctx.pledge_info.supported_token_type.as_content_type(),
            )
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
            if content_type != ctx.pledge_info.supported_token_type.as_content_type() {
                return Err(ServerError::BadResponse(
                    "Wrong content type in response".to_string(),
                ));
            }
        }

        let response_data = response.bytes().await?;

        std::result::Result::Ok(response_data.to_vec())
    }

    #[tracing::instrument(skip(self, cacerts, ctx))]
    async fn send_ca_certs(
        &self,
        cacerts: Vec<u8>,
        ctx: PledgeCtx,
    ) -> Result<(), common::server_error::ServerError> {
        let url = format!("{}/.well-known/brski/scac", ctx.pledge_url);

        event!(
            tracing::Level::INFO,
            "Sending Wrapped CA Certs to pledge at: {}",
            url
        );
        //event!(tracing::Level::DEBUG, "Wrapped CA Certs: {}", cacerts);

        let response = self
            .client
            .post(url)
            .header(
                CONTENT_TYPE,
                ctx.pledge_info.supported_token_type.as_content_type(),
            )
            .header(
                ACCEPT,
                ctx.pledge_info.supported_token_type.as_content_type(),
            )
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

    #[tracing::instrument(skip(self, response, ctx))]
    async fn send_enroll_response(
        &self,
        response: Vec<u8>,
        ctx: PledgeCtx,
    ) -> Result<Vec<u8>, common::server_error::ServerError> {
        let url = format!("{}/.well-known/brski/ser", ctx.pledge_url);

        event!(
            tracing::Level::INFO,
            "Sending Registrar Enroll-Response to pledge at: {}",
            url
        );
        event!(
            tracing::Level::DEBUG,
            "Registrar-Enroll-Response: {:?}",
            response
        );

        let response = self
            .client
            .post(url)
            .header(CONTENT_TYPE, PKCS7)
            .header(
                ACCEPT,
                ctx.pledge_info.supported_token_type.as_content_type(),
            )
            .body(response)
            .send()
            .await?;

        event!(tracing::Level::INFO, "Received response");

        if !response.status().is_success() {
            return Err(ServerError::BadResponse(
                "Sending registrar enroll response to pledge failed".to_string(),
            ));
        }

        let response_body = response.bytes().await?;

        std::result::Result::Ok(response_body.to_vec())
    }

    #[tracing::instrument(skip(self, pledge))]
    async fn get_data_interchange_format(
        &self,
        pledge: DiscoveredPledge,
    ) -> Result<String, ServerError> {
        let url = format!("{}/.well-known/brski/dif", pledge.url);

        event!(
            tracing::Level::INFO,
            "Sending Data Interchange Format negotiation request to pledge at: {}",
            url
        );

        let response = self
            .client
            .get(url)
            .header(ACCEPT, "text/plain")
            .send()
            .await?;

        event!(tracing::Level::INFO, "Received response");

        if !response.status().is_success() {
            return Err(ServerError::BadResponse(
                "Sending data interchange format negotiation request to pledge failed".to_string(),
            ));
        }

        let response_body = response.text().await?;

        std::result::Result::Ok(response_body.to_string())
    }

    #[tracing::instrument(skip(self, pledge, format))]
    async fn get_pledge_info(
        &self,
        pledge: DiscoveredPledge,
        format: DataInterchangeFormat,
    ) -> Result<Vec<u8>, ServerError> {
        let url = format!("{}/.well-known/brski/pi", pledge.url);

        event!(
            tracing::Level::INFO,
            "Sending pledge info request to pledge at: {}",
            url
        );

        let response = self
            .client
            .get(url)
            .header(ACCEPT, format.as_content_type())
            .send()
            .await?;

        event!(tracing::Level::INFO, "Received response");

        if !response.status().is_success() {
            return Err(ServerError::BadResponse(format!(
                "Sending pledge info request to pledge failed, reason: {}",
                response.status().to_string()
            )));
        }

        let response_body = response.bytes().await?;

        std::result::Result::Ok(response_body.to_vec())
    }
}
