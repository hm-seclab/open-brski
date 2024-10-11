use std::sync::Arc;

use brski_prm_artifacts::token_type::DataInterchangeFormat;
pub use flutter_rust_bridge::DartFnFuture;
use registrar_agent::{PledgeCommunicator, PledgeCtx, DiscoveredPledge};
use registrar_agent::{start, ParsedConfig};
use common::server_error::ServerError;

#[derive(Default)]
pub struct FFIBLECommunicatorBuilder {
    pub ffi_send_pvr_trigger: Option<Arc<Box<dyn Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send>>>,
    pub ffi_send_per_trigger: Option<Arc<Box<dyn Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send>>>,
    pub ffi_send_voucher: Option<Arc<Box<dyn Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send>>>,
    pub ffi_send_ca_certs: Option<Arc<Box<dyn Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send>>>,
    pub ffi_send_enroll_response: Option<Arc<Box<dyn Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send>>>,
    pub ffi_get_data_interchange_format: Option<Arc<Box<dyn Fn(DiscoveredPledge) -> DartFnFuture<String> + Sync + Send>>>,
    pub ffi_get_pledge_info: Option<Arc<Box<dyn Fn(DiscoveredPledge, DataInterchangeFormat) -> DartFnFuture<Vec<u8>> + Sync + Send>>>,
}

impl FFIBLECommunicatorBuilder {

    pub fn init() -> FFIBLECommunicatorBuilder {
        FFIBLECommunicatorBuilder::default()
    }

    pub fn set_pvr_ffi(self, callback: impl Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send + 'static) -> Self {
        FFIBLECommunicatorBuilder {
            ffi_send_pvr_trigger: Some(Arc::new(Box::new(callback))),
            ..self
        }
    }

    pub fn set_per_ffi(self, callback: impl Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send + 'static) -> Self {
        FFIBLECommunicatorBuilder {
            ffi_send_per_trigger: Some(Arc::new(Box::new(callback))),
            ..self
        }
    }

    pub fn set_voucher_ffi(self, callback: impl Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send + 'static) -> Self {
        FFIBLECommunicatorBuilder {
            ffi_send_voucher: Some(Arc::new(Box::new(callback))),
            ..self
        }
    }

    pub fn set_ca_certs_ffi(self, callback: impl Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send + 'static) -> Self {
        FFIBLECommunicatorBuilder {
            ffi_send_ca_certs: Some(Arc::new(Box::new(callback))),
            ..self
        }
    }

    pub fn set_enroll_response_ffi(self, callback: impl Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send + 'static) -> Self {
        FFIBLECommunicatorBuilder {
            ffi_send_enroll_response: Some(Arc::new(Box::new(callback))),
            ..self
        }
    }

    pub fn set_data_interchange_format_ffi(self, callback: impl Fn(DiscoveredPledge) -> DartFnFuture<String> + Sync + Send + 'static) -> Self {
        FFIBLECommunicatorBuilder {
            ffi_get_data_interchange_format: Some(Arc::new(Box::new(callback))),
            ..self
        }
    } 
    pub fn set_pledge_info_ffi(self, callback: impl Fn(DiscoveredPledge, DataInterchangeFormat) -> DartFnFuture<Vec<u8>> + Sync + Send + 'static) -> Self {
        FFIBLECommunicatorBuilder {
            ffi_get_pledge_info: Some(Arc::new(Box::new(callback))),
            ..self
        }
    } 

    pub fn build (self) -> FFIBLECommunicator {
        FFIBLECommunicator {
            ffi_send_pvr_trigger: self.ffi_send_pvr_trigger.expect("ffi_send_pvr_trigger is required"),
            ffi_send_per_trigger: self.ffi_send_per_trigger.expect("ffi_send_per_trigger is required"),
            ffi_send_voucher: self.ffi_send_voucher.expect("ffi_send_voucher is required"),
            ffi_send_ca_certs: self.ffi_send_ca_certs.expect("ffi_send_ca_certs is required"),
            ffi_send_enroll_response: self.ffi_send_enroll_response.expect("ffi_send_enroll_response is required"),
            ffi_get_data_interchange_format: self.ffi_get_data_interchange_format.expect("ffi_get_data_interchange_format is required"),
            ffi_get_pledge_info: self.ffi_get_pledge_info.expect("ffi_get_pledge_info is required"),
        }
    }

}

#[derive(Clone)]
pub struct FFIBLECommunicator {
    //pub ffi_send_pvr_trigger: &'static (dyn Fn(&brski_prm_artifacts::pvr::trigger::Trigger, &String) -> DartFnFuture<String> + Sync + Send),
    // create place to store the function
    ffi_send_pvr_trigger: Arc<Box<dyn Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send>>,
    ffi_send_per_trigger: Arc<Box<dyn Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send>>,
    ffi_send_voucher: Arc<Box<dyn Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send>>,
    ffi_send_ca_certs: Arc<Box<dyn Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send>>,
    ffi_send_enroll_response: Arc<Box<dyn Fn(Vec<u8>, PledgeCtx) -> DartFnFuture<Vec<u8>> + Sync + Send>>,
    ffi_get_data_interchange_format: Arc<Box<dyn Fn(DiscoveredPledge) -> DartFnFuture<String> + Sync + Send>>,
    ffi_get_pledge_info: Arc<Box<dyn Fn(DiscoveredPledge, DataInterchangeFormat) -> DartFnFuture<Vec<u8>> + Sync + Send>>,
}

#[async_trait::async_trait]
impl PledgeCommunicator for FFIBLECommunicator {
    #[tracing::instrument(skip(self, ctx), target = "RegistrarAgent", name="send_pvr_trigger")]
    async fn send_pvr_trigger(&self, trigger: Vec<u8>, ctx: PledgeCtx) -> Result<Vec<u8>, ServerError> {
        let result = (self.ffi_send_pvr_trigger)(trigger, ctx).await;
        Ok(result)
    }

    #[tracing::instrument(skip(self, ctx), target = "RegistrarAgent", name="send_per_trigger")]
    async fn send_per_trigger(&self, trigger: Vec<u8>, ctx: PledgeCtx) -> Result<Vec<u8>, ServerError> {
        let result = (self.ffi_send_per_trigger)(trigger, ctx).await;
        Ok(result)
    }

    #[tracing::instrument(skip(self, ctx), target = "RegistrarAgent", name="send_voucher")]
    async fn send_voucher(&self, voucher: Vec<u8>, ctx: PledgeCtx) -> Result<Vec<u8>, ServerError> {
        let result = (self.ffi_send_voucher)(voucher, ctx).await;
        Ok(result)
    }

    #[tracing::instrument(skip(self, ctx), target = "RegistrarAgent", name="send_ca_certs")]
    async fn send_ca_certs(&self, cacerts: Vec<u8>, ctx: PledgeCtx) -> Result<(), ServerError> {
        let result = (self.ffi_send_ca_certs)(cacerts, ctx).await;
        Ok(())
    }

    #[tracing::instrument(skip(self, ctx), target = "RegistrarAgent", name="send_enroll_response")]
    async fn send_enroll_response(&self, response: Vec<u8>, ctx: PledgeCtx) -> Result<Vec<u8>, ServerError> {
        let result = (self.ffi_send_enroll_response)(response, ctx).await;
        Ok(result)
    }

    #[tracing::instrument(skip(self), target = "RegistrarAgent", name="send_enroll_response")]
    async fn get_data_interchange_format(&self, pledge: DiscoveredPledge) -> Result<String, ServerError> {
        let result = (self.ffi_get_data_interchange_format)(pledge).await;
        Ok(result)
    }

    #[tracing::instrument(skip(self), target = "RegistrarAgent", name="send_enroll_response")]
    async fn get_pledge_info(&self, pledge: DiscoveredPledge, format: DataInterchangeFormat) -> Result<Vec<u8>, ServerError> {
        let result = (self.ffi_get_pledge_info)(pledge, format).await;
        Ok(result)
    }
}
