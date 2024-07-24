use std::env::current_dir;

use common::error::AppError;
use tokio::task::JoinHandle;
use tracing_forest::ForestLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Registry};


#[tokio::main]
async fn main() -> anyhow::Result<(), AppError> {

    let level_filter = tracing_subscriber::filter::LevelFilter::INFO;
    tracing_subscriber::registry().with(ForestLayer::default()).with(level_filter).init();
    //tracing_subscriber::registry().with(ForestLayer::default()).init(); 

    let cli = cli::parse_args();
    let config = cli::get_config()?;

    if matches!(cli.command, cli::Command::TestCerts) {
        let certs = example_certs::generate_certs();
        example_certs::serialize_certs(
            certs,
            current_dir().unwrap().join("reference_keys"),
        );
        return Ok(());
    }

    let mut tasks: Vec<JoinHandle<_>> = match &cli.command {
        cli::Command::RegistrarAgent(_) => vec![registrar_agent::start(config.registrar_agent).await.unwrap()],
        cli::Command::Registrar(_) => vec![registrar::start(config.registrar).await.unwrap()],
        cli::Command::Masa(_) => vec![masa::start(config.masa).await.unwrap()],
        cli::Command::Pledge(_) => vec![pledge::start(config.pledge).await.unwrap()],
        cli::Command::TestCerts => unreachable!(),
        cli::Command::All => {
            vec![
                registrar_agent::start(config.registrar_agent).await.unwrap(),
                registrar::start(config.registrar).await.unwrap(),
                masa::start(config.masa).await.unwrap(),
                pledge::start(config.pledge).await.unwrap(),
            ]
        }
    };

    if tasks.len() == 1 {
        let _ = tasks.pop().unwrap().await?;
    } else {
        let _ = futures::future::join_all(tasks).await;
    }

    Ok(())
}
