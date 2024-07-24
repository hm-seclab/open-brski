use common::server_error::ServerError;
use dyn_clone::DynClone;

pub mod http_communicator;

#[async_trait::async_trait]
pub trait PledgeCommunicator: Send + Sync + DynClone {

    async fn send_pvr_trigger(&self, trigger: String, ctx: PledgeCtx) -> Result<String, ServerError>;

    async fn send_per_trigger(&self, trigger: String, ctx: PledgeCtx) -> Result<String, ServerError>;

    async fn send_voucher(&self, voucher: String, ctx: PledgeCtx) -> Result<String, ServerError>;

    async fn send_ca_certs(&self, cacerts: String, ctx: PledgeCtx) -> Result<(), ServerError>;

    async fn send_enroll_response(&self, cacerts: Vec<u8>, ctx: PledgeCtx) -> Result<String, ServerError>;
}

impl Clone for Box<dyn PledgeCommunicator> {
    fn clone(&self) -> Self {
        dyn_clone::clone_box(&**self)
    }
}

#[derive(Debug, Default, Clone)]
pub struct PledgeCtx {
    /// for anything else that needs to be passed to the communicators
    pub ctx: String,
    pub pledge_serial: String,
    pub pledge_url: String,
}