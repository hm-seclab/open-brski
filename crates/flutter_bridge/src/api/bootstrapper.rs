pub use registrar_agent::{ParsedConfig, ServerState, PledgeCtx};

use super::ffiblecommunicator::FFIBLECommunicator;

pub struct Bootstrapper {
    state: ServerState
}

impl Bootstrapper {
    #[tracing::instrument(skip(config, communicator), target = "RegistrarAgent", name="init_bootstrapper")]
    pub fn init(config: ParsedConfig, communicator: FFIBLECommunicator) -> Self {
        
        let state = registrar_agent::get_state(&config, Box::new(communicator)).unwrap();

        Bootstrapper {
            state
        }
    }
}

impl Bootstrapper { 
    #[tracing::instrument(skip(self, serial_number), target = "RegistrarAgent", name="bootstrap")]
    pub async fn bootstrap(self, serial_number: String) -> anyhow::Result<()> {
        let res = registrar_agent::bootstrap_pledge(&self.state, &(PledgeCtx { ctx: "".to_string(), pledge_serial: serial_number, pledge_url: "".to_string() })).await;
        if let Err(e) = res {   
            return Err(anyhow::Error::new(e));
        }
        Ok(())
    }
}