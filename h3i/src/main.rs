use std::io::BufReader;
use std::time;

use foundations::service_info;
use foundations::telemetry::log;
use foundations::telemetry::settings::{LogVerbosity, TelemetrySettings};
use h3i::config::AppConfig;
use h3i::h3::actions::Action;
use h3i::h3::prompts::Prompter;
use qlog::reader::QlogSeqReader;
use tokio_quiche::quiche::h3::frame::Frame;

#[tokio::main]
async fn main() {
    env_logger::builder()
        .default_format_timestamp_nanos(true)
        .init();

    let config = match AppConfig::from_clap() {
        Ok(v) => v,

        Err(e) => {
            println!("Error loading configuration, exiting: {}", e);
            return;
        },
    };

    let mut settings: TelemetrySettings = Default::default();
    settings.logging.verbosity = config.log_verbosity.unwrap();
    let _ = foundations::telemetry::init(&service_info!(), &settings);

    let frame_actions = match &config.qlog_input {
        Some(v) => read_qlog(v),
        None => prompt_frames(&config),
    };

    let frame_rx = h3i::client::connect(&config, frame_actions).await;
    let received_frames = frame_rx.unwrap().await.unwrap();

    log::info!("received stream map: {:?}", received_frames);
}

fn read_qlog(filename: &str) -> Vec<Action> {
    let file = std::fs::File::open(filename).expect("failed to open file");
    let reader = BufReader::new(file);

    let qlog_reader = QlogSeqReader::new(Box::new(reader)).unwrap();
    let mut actions = vec![];

    for event in qlog_reader {
        match event {
            qlog::reader::Event::Qlog(ev) => {
                let ac = Action::from_qlog(&ev);
                actions.extend(ac);
            },

            qlog::reader::Event::Json(_ev) => unimplemented!(),
        }
    }

    actions
}

fn prompt_frames(config: &AppConfig) -> Vec<Action> {
    let mut prompter = Prompter::with_config(config);
    let frame_actions = prompter.prompt();

    if config.seperate_qlog_output {
        let writer = make_qlog_writer();
        let mut streamer = make_streamer(std::boxed::Box::new(writer));

        for action in &frame_actions {
            for (ev, ex) in action.to_qlog() {
                streamer.add_event_data_ex_now(ev, ex).ok();
            }
        }
    }

    frame_actions
}

/// Makes a buffered writer for a qlog.
pub fn make_qlog_writer() -> std::io::BufWriter<std::fs::File> {
    let mut path = std::env::current_dir().unwrap();
    let now = time::SystemTime::now();
    let filename = format!(
        "{}-qlog.sqlog",
        now.duration_since(time::UNIX_EPOCH).unwrap().as_millis()
    );
    path.push(filename.clone());

    println!("Session will be recorded to {}", filename);

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),

        Err(e) => panic!(
            "Error creating qlog file attempted path was {:?}: {}",
            path, e
        ),
    }
}

pub fn make_streamer(
    writer: Box<dyn std::io::Write + Send + Sync>,
) -> qlog::streamer::QlogStreamer {
    let vp = qlog::VantagePointType::Client;

    let trace = qlog::TraceSeq::new(
        qlog::VantagePoint {
            name: None,
            ty: vp,
            flow: None,
        },
        Some("h3i".into()),
        Some("h3i".into()),
        Some(qlog::Configuration {
            time_offset: Some(0.0),
            original_uris: None,
        }),
        None,
    );

    let mut streamer = qlog::streamer::QlogStreamer::new(
        qlog::QLOG_VERSION.to_string(),
        Some("h3i".into()),
        Some("h3i".into()),
        None,
        time::Instant::now(),
        trace,
        qlog::events::EventImportance::Extra,
        writer,
    );

    streamer.start_log().ok();

    streamer
}
