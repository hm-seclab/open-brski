use crate::frb_generated::StreamSink;
use anyhow::bail;
use anyhow::Result;
pub use flutter_rust_bridge::DartFnFuture;
use std::env;
use std::io::Write;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
struct LogSink {
    sink: StreamSink<String>,
}

/// Write log lines to our Flutter's sink.
impl<'a> Write for &'a LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let line = String::from_utf8_lossy(buf).to_string();
        self.sink.add(line).unwrap();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogSink {
    type Writer = &'a LogSink;

    fn make_writer(&'a self) -> Self::Writer {
        self
    }
}

/// Public method that Dart will call into.
pub fn setup_logs(sink: StreamSink<String>) -> Result<()> {
    if(env::var("RUST_BACKTRACE").is_err()){
        bail!("RUST_BACKTRACE not set");
    }
    let log_sink = LogSink { sink };
    // Subscribe to tracing events and publish them to the UI
    if let Err(err) = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().pretty().with_ansi(false))
        .with(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with(tracing_subscriber::fmt::layer().with_writer(log_sink).with_ansi(false).with_line_number(true).with_file(true))
        .try_init()
    {
        bail!("{}", err);
    }
    Ok(())
}

#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    env::set_var("RUST_BACKTRACE", "1");
    // Default utilities - feel free to customize
    flutter_rust_bridge::setup_default_user_utils();

    // let provider = TracerProvider::builder()
    //     .with_simple_exporter(opentelemetry_stdout::SpanExporter::default())
    //     .build();

    // let tracer = provider.tracer("readme_example");

    // let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    // Registry::default().with(telemetry).init();
    // setup registrar-agent config
}
