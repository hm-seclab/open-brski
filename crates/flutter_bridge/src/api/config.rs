use cli::config::RegistrarAgentConfig;
use openssl::{ec::EcKey, pkey::PKey, x509::X509};
pub use registrar_agent::ParsedConfig;

#[tracing::instrument(target = "RegistrarAgent", name="get_config")]
pub fn get_config(ee_cert: String, ee_key: String, registrar_cert: String) -> ParsedConfig {

    let reg_agt_config = RegistrarAgentConfig {   
        registrar_url: "https://registrar.brski.hm.edu".to_string(),
        ..Default::default()
    };
    
    let ee_certificate = X509::from_pem(ee_cert.as_bytes()).expect("Failed to load EE certificate");
    
    let ee_key = EcKey::private_key_from_pem(ee_key.as_bytes() ).expect("Failed to load EE key");
    let ee_key_pkcs8 = PKey::from_ec_key(ee_key).expect("Failed to convert EE key to PKey").private_key_to_pkcs8().expect("Failed to convert EE key to PKCS8");    
    let registrar_certificate = X509::from_pem(registrar_cert.as_bytes()).expect("Failed to load registrar certificate");

    ParsedConfig {
        config: reg_agt_config, 
        ee_certificate,
        ee_key: ee_key_pkcs8,
        registrar_certificate
    }

}