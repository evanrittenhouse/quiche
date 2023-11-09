use std::io::BufReader;
use std::time;

use h3i::actions::Action;
use h3i::config::AppConfig;
use h3i::prompts::Prompter;
use qlog::QlogSeq;

fn main() {
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

    let frame_actions = match &config.qlog_input {
        Some(v) => read_qlog(v),
        None => prompt_frames(&config),
    };

    println!();

    h3i::client::connect(&config, &frame_actions).unwrap();
}

fn read_qlog(filename: &str) -> Vec<Action> {
    let file = std::fs::File::open(filename).expect("failed to open file");
    let reader = BufReader::new(file);

    let qlog_reader = QlogSeqReader::new(Box::new(reader)).unwrap();
    let mut actions = vec![];

    for event in qlog_reader {
        let ac = Action::from_qlog(&event);
        actions.extend(ac);
    }

    // println!("action = {:?}", actions);

    actions
}

fn prompt_frames(config: &AppConfig) -> Vec<Action> {
    let mut prompter = Prompter::with_config(config);
    let frame_actions = prompter.prompt();

    if config.seperate_qlog_output {
        let writer = make_qlog_writer();
        let mut streamer = make_streamer(std::boxed::Box::new(writer));

        for action in &frame_actions {
            for ev in action.to_qlog() {
                streamer.add_event_data_now(ev).ok();
            }
        }
    }

    frame_actions
}

struct QlogSeqReader {
    pub _qlog: QlogSeq,
    reader: Box<dyn std::io::BufRead + Send + Sync>,
}

impl QlogSeqReader {
    pub fn new(
        mut reader: Box<dyn std::io::BufRead + Send + Sync>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // "null record" skip it
        Self::read_record(reader.as_mut());

        let header = Self::read_record(reader.as_mut()).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "oh no!")
        })?;

        let res: Result<QlogSeq, serde_json::Error> =
            serde_json::from_slice(&header);
        match res {
            Ok(qlog) => Ok(Self {
                _qlog: qlog,
                reader,
            }),

            Err(e) => {
                println!("Error deserializing: {}", e);
                println!("input value {}", String::from_utf8_lossy(&header));

                Err(e.into())
            },
        }
    }

    fn read_record(
        reader: &mut (dyn std::io::BufRead + Send + Sync),
    ) -> Option<Vec<u8>> {
        let mut buf = Vec::<u8>::new();
        let size = reader.read_until(b'', &mut buf).unwrap();
        if size <= 1 {
            return None;
        }

        buf.truncate(buf.len() - 1);

        Some(buf)
    }
}

impl Iterator for QlogSeqReader {
    type Item = qlog::events::Event;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(bytes) = Self::read_record(&mut self.reader) {
            let res: Result<qlog::events::Event, serde_json::Error> =
                serde_json::from_slice(&bytes);

            match res {
                Ok(event) => {
                    return Some(event);
                },

                Err(e) => {
                    println!("Error deserializing: {}", e);
                    println!("input value {}", String::from_utf8_lossy(&bytes));
                },
            }
        }

        None
    }
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
