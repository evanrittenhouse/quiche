use crate::h3::actions::Action;
use crate::quiche;
use inquire::error::InquireResult;
use inquire::validator::Validation;
use inquire::Text;

use super::squish_suggester;
use super::stream::prompt_fin_stream;
use super::SuggestionResult;
use crate::h3::prompts;

const QPACK_MAX_TABLE_CAPACITY: &str = "QPACK_MAX_TABLE_CAPACITY";
const MAX_FIELD_SECTION_SIZE: &str = "MAX_FIELD_SECTION_SIZE";
const QPACK_BLOCKED_STREAMS: &str = "QPACK_BLOCKED_STREAMS";
const ENABLE_CONNECT_PROTOCOL: &str = "ENABLE_CONNECT_PROTOCOL";
const H3_DATAGRAM: &str = "H3_DATAGRAM";

type RawSettings = Vec<(u64, u64)>;

#[derive(Default, Debug)]
pub struct Settings {
    pub stream_id: u64,
    pub settings: RawSettings,
}

pub fn prompt_settings() -> InquireResult<Action> {
    let stream_id = prompts::prompt_control_stream_id()?;
    let raw = settings_read_loop();

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            h3_datagram: None,
            grease: None,
            raw: Some(raw),
        },
    };

    Ok(action)
}

fn settings_read_loop() -> RawSettings {
    let mut settings = vec![];

    loop {
        let ty = match Text::new("setting type:")
            .with_validator(validate_setting_type)
            .with_autocomplete(&settings_type_suggestor)
            .with_help_message("type 'q!' to stop adding settings")
            .prompt()
        {
            Ok(h) => {
                if h == "q!" {
                    break;
                }

                h
            },
            Err(_) => {
                println!("An error happened, stopping.");
                break;
            },
        };

        let ty = match ty.as_str() {
            QPACK_MAX_TABLE_CAPACITY => 0x1,
            MAX_FIELD_SECTION_SIZE => 0x6,
            QPACK_BLOCKED_STREAMS => 0x7,
            ENABLE_CONNECT_PROTOCOL => 0x8,
            H3_DATAGRAM => 0x33,

            v => v.parse::<u64>().unwrap(),
        };

        let value = Text::new("setting value:")
            .with_validator(prompts::validate_varint)
            .prompt()
            .expect("An error happened, stopping.")
            .parse::<u64>()
            .unwrap();

        settings.push((ty, value));
    }

    settings
}

fn validate_setting_type(id: &str) -> SuggestionResult<Validation> {
    if matches!(
        id,
        "q!" | QPACK_MAX_TABLE_CAPACITY
            | MAX_FIELD_SECTION_SIZE
            | QPACK_BLOCKED_STREAMS
            | ENABLE_CONNECT_PROTOCOL
            | H3_DATAGRAM
    ) {
        return Ok(Validation::Valid);
    }

    prompts::validate_varint(id)
}

fn settings_type_suggestor(val: &str) -> SuggestionResult<Vec<String>> {
    let suggestions = [
        QPACK_MAX_TABLE_CAPACITY,
        MAX_FIELD_SECTION_SIZE,
        QPACK_BLOCKED_STREAMS,
        ENABLE_CONNECT_PROTOCOL,
        H3_DATAGRAM,
    ];

    squish_suggester(&suggestions, val)
}
