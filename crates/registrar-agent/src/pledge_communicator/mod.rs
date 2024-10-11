use brski_prm_artifacts::{
    pledge_info::PledgeInfo,
    token_type::{DataInterchangeFormat, PlainTokenType, TokenType, VoucherTokenType},
};
use common::server_error::ServerError;
use dyn_clone::DynClone;
use signeable_payload::SignatureType;

pub mod http_communicator;

#[async_trait::async_trait]
pub trait PledgeCommunicator: Send + Sync + DynClone {
    async fn send_pvr_trigger(
        &self,
        trigger: Vec<u8>,
        ctx: PledgeCtx,
    ) -> Result<Vec<u8>, ServerError>;

    async fn send_per_trigger(
        &self,
        trigger: Vec<u8>,
        ctx: PledgeCtx,
    ) -> Result<Vec<u8>, ServerError>;

    async fn send_voucher(&self, voucher: Vec<u8>, ctx: PledgeCtx) -> Result<Vec<u8>, ServerError>;

    async fn send_ca_certs(&self, cacerts: Vec<u8>, ctx: PledgeCtx) -> Result<(), ServerError>;

    async fn send_enroll_response(
        &self,
        cacerts: Vec<u8>,
        ctx: PledgeCtx,
    ) -> Result<Vec<u8>, ServerError>;

    async fn get_data_interchange_format(
        &self,
        pledge: DiscoveredPledge,
    ) -> Result<String, ServerError>;

    async fn get_pledge_info(
        &self,
        pledge: DiscoveredPledge,
        format: DataInterchangeFormat,
    ) -> Result<Vec<u8>, ServerError>;
}

impl Clone for Box<dyn PledgeCommunicator> {
    fn clone(&self) -> Self {
        dyn_clone::clone_box(&**self)
    }
}

#[derive(Debug, Default, Clone)]
pub struct DiscoveredPledge {
    pub serial: String,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct PledgeCtx {
    /// for anything else that needs to be passed to the communicators
    pub ctx: String,
    pub pledge_serial: String,
    pub pledge_url: String,
    pub pledge_info: PledgeInfo,
}

impl Default for PledgeCtx {
    fn default() -> Self {
        PledgeCtx {
            ctx: "".to_string(),
            pledge_serial: "".to_string(),
            pledge_url: "".to_string(),
            pledge_info: PledgeInfo {
                data_interchance_format: DataInterchangeFormat::JSON,
                supported_token_type: PlainTokenType::JOSE,
                supported_voucher_type: VoucherTokenType::JWS,
            },
        }
    }
}
