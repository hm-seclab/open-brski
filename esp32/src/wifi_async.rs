
use embedded_svc::wifi::{ClientConfiguration, Configuration};




use esp_idf_svc::wifi::{AsyncWifi, EspWifi};

use esp_idf_svc::sys::{EspError};
use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};


pub async fn run_wifi(wifi: AsyncWifi<EspWifi<'static>> ) -> tokio::task::JoinHandle<()> {

  tokio::spawn(async move {
    let mut wifi_loop = WifiLoop { wifi };
    wifi_loop.configure().await.unwrap();
    wifi_loop.initial_connect().await.unwrap();

    info!("Preparing to launch echo server...");
    //tokio::spawn(echo_server());

    info!("Entering main Wi-Fi run loop...");
    wifi_loop.stay_connected().await.unwrap();
  })

}
// Edit these or provide your own way of provisioning...

// To test, run `cargo run`, then when the server is up, use `nc -v espressif 12345` from
// a machine on the same Wi-Fi network.
const TCP_LISTENING_PORT: u16 = 3001;
pub struct WifiLoop<'a> {
  pub wifi: AsyncWifi<EspWifi<'a>>,
}

impl<'a> WifiLoop<'a> {
  pub async fn configure(&mut self) -> Result<(), EspError> {

    let mut ssid: heapless::String<32> = heapless::String::new();
    ssid.push_str("HM-iotroam").unwrap();

    let mut password: heapless::String<64> = heapless::String::new();
    password.push_str("ESP-Julian!").unwrap(); 

    info!("Setting Wi-Fi credentials...");
    self.wifi.set_configuration(&Configuration::Client(ClientConfiguration {
      ssid,
      password,
      ..Default::default()
    }))?;

    info!("Starting Wi-Fi driver...");
    self.wifi.start().await
  }

  pub async fn initial_connect(&mut self) -> Result<(), EspError> {
    self.do_connect_loop(true).await
  }

  pub async fn stay_connected(mut self) -> Result<(), EspError> {
    self.do_connect_loop(false).await
  }

  async fn do_connect_loop(
    &mut self,
    exit_after_first_connect: bool,
  ) -> Result<(), EspError> {
    loop {
      let wifi = &mut self.wifi;
      // Wait for disconnect before trying to connect again.  This loop ensures
      // we stay connected and is commonly missing from trivial examples as it's
      // way too difficult to showcase the core logic of an example and have
      // a proper Wi-Fi event loop without a robust async runtime.  Fortunately, we can do it
      // now!
      wifi.wifi_wait(|s| s.is_up(), None).await?;

      info!("Connecting to Wi-Fi...");
      wifi.connect().await?;

      info!("Waiting for association...");
      wifi.ip_wait_while(|s| s.is_up().map(|s| !s), None).await?;

      if exit_after_first_connect {
        return Ok(());
      }
    }
  }
}

pub async fn echo_server() -> anyhow::Result<()> {
  let addr = format!("0.0.0.0:{TCP_LISTENING_PORT}");

  info!("Binding to {addr}...");
  let listener = TcpListener::bind(&addr).await?;

  let app = axum::Router::new().route("/", axum::routing::get(|| async { "Hello, World!" }));
  info!("Starting axum server");
  axum::serve(listener, app).await.unwrap();
  info!("Server started");

  Ok(())


  // loop {
  //   info!("Waiting for new connection on socket: {listener:?}");
  //   let (socket, _) = listener.accept().await?;

  //   info!("Spawning handle for: {socket:?}...");
  //   tokio::spawn(async move {
  //     info!("Spawned handler!");
  //     let peer = socket.peer_addr();
  //     if let Err(e) = serve_client(socket).await {
  //       info!("Got error handling {peer:?}: {e:?}");
  //     }
  //   });
  // }
}

pub async fn serve_client(mut stream: TcpStream) -> anyhow::Result<()> {
  info!("Handling {stream:?}...");

  let mut buf = [0u8; 512];
  loop {
    info!("About to read...");
    let n = stream.read(&mut buf).await?;
    info!("Read {n} bytes...");

    if n == 0 {
      break;
    }

    stream.write_all(&buf[0..n]).await?;
    info!("Wrote {n} bytes back...");
  }

  Ok(())
}