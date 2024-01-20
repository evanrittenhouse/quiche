use clap::App;
use clap::Arg;

pub struct AppConfig {
    pub host_port: String,
    pub connect_to: Option<String>,
    pub source_port: u32,
    pub verify_peer: bool,
    pub qlog_input: Option<String>,
    pub seperate_qlog_output: bool,
}

impl AppConfig {
    pub fn from_clap() -> std::result::Result<Self, String> {
        let matches = App::new("h3i")
            .version("v0.1.0")
            .about("Interactive HTTP/3 console debugger")
            .arg(
                Arg::with_name("host:port")
                    .help("Hostname and port of the HTTP/3 server")
                    .required(true)
                    .index(1),
            )
            .arg(
                Arg::with_name("connect-to")
                    .long("connect-to")
                    .help("Override ther server's address.")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("no-verify")
                    .long("no-verify")
                    .help("Don't verify server's certificate."),
            )
            .arg(
                Arg::with_name("qlog-input")
                    .long("qlog-input")
                    .help("Drive connection via qlog rather than cli.")
                    .takes_value(true),
            )
            .get_matches();

        let host_port = matches.value_of("host:port").unwrap().to_string();
        let connect_to: Option<String> =
            matches.value_of("connect-to").map(|s| s.to_string());
        let verify_peer = !matches.is_present("no-verify");

        let qlog_input = matches.value_of("qlog-input").and_then(|q| {
            std::path::Path::new(q)
                .file_name()
                .unwrap()
                .to_str()
                .map(|s| s.to_string())
        });

        let config = Self {
            host_port,
            connect_to,
            source_port: 0,
            verify_peer,
            qlog_input,
            seperate_qlog_output: true,
        };

        Ok(config)
    }
}
