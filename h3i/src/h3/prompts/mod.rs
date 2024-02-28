use crate::quiche;

use inquire::error::CustomUserError;
use inquire::error::InquireResult;
use inquire::validator::ErrorMessage;
use inquire::validator::Validation;
use inquire::InquireError;
use inquire::Text;

use crate::config::AppConfig;
use crate::h3::actions::Action;
use crate::h3::prompts;
use crate::h3::prompts::headers::prompt_push_promise;
use crate::StreamIdAllocator;

use std::sync::OnceLock;

use self::stream::prompt_fin_stream;

/// An error indicating that the provided buffer is not big enough.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InternalError,
    BufferTooShort,
}

impl std::convert::From<octets::BufferTooShortError> for Error {
    fn from(_err: octets::BufferTooShortError) -> Self {
        Error::BufferTooShort
    }
}

/// A specialized [`Result`] type for prompt operations.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// A specialized [`Result`] type for internal prompt suggestion.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
type SuggestionResult<T> = std::result::Result<T, CustomUserError>;

pub type PromptedFrame = (u64, quiche::h3::frame::Frame);

static HOST_PORT: OnceLock<String> = OnceLock::new();

const HEADERS: &str = "headers";
const HEADERS_RAW: &str = "headers_raw";
const DATA: &str = "data";
const SETTINGS: &str = "settings";
const PUSH_PROMISE: &str = "push_promise";
const CANCEL_PUSH: &str = "cancel_push";
const GOAWAY: &str = "goaway";
const MAX_PUSH_ID: &str = "max_push_id";
const PRIORITY_UPDATE: &str = "priority_update";
const GREASE: &str = "grease";
const EXTENSION: &str = "extension";
const OPEN_UNI_STREAM: &str = "open_uni_stream";
const RESET_STREAM: &str = "reset_stream";
const STOP_SENDING: &str = "stop_sending";
const FLUSH: &str = "flush";
const QUIT: &str = "quit";

enum PromptOutcome {
    Action(Action),
    Repeat,
    Flush,
    Clear,
}

pub struct Prompter {
    bidi_sid_alloc: StreamIdAllocator,
    uni_sid_alloc: StreamIdAllocator,
}

impl Prompter {
    pub fn with_config(config: &AppConfig) -> Self {
        HOST_PORT.set(config.host_port.clone()).unwrap();

        Self {
            bidi_sid_alloc: StreamIdAllocator { id: 0 },
            uni_sid_alloc: StreamIdAllocator { id: 2 },
        }
    }

    fn foo(&mut self, action: &str) -> PromptOutcome {
        let res = match action {
            HEADERS | HEADERS_RAW => {
                let raw = action == HEADERS_RAW;
                headers::prompt_headers(&mut self.bidi_sid_alloc, raw)
            },

            DATA => prompt_data(),
            SETTINGS => settings::prompt_settings(),
            OPEN_UNI_STREAM => {
                stream::prompt_open_uni_stream(&mut self.uni_sid_alloc)
            },
            RESET_STREAM => stream::prompt_reset_stream(),
            STOP_SENDING => stream::prompt_stop_sending(),
            GREASE => prompt_grease(),
            EXTENSION => prompt_extension(),
            GOAWAY => prompt_goaway(),
            MAX_PUSH_ID => prompt_max_push_id(),
            CANCEL_PUSH => prompt_cancel_push(),
            PUSH_PROMISE => prompt_push_promise(),
            PRIORITY_UPDATE => priority::prompt_priority(),
            FLUSH => return PromptOutcome::Flush,
            QUIT => return PromptOutcome::Clear,

            _ => {
                println!("error: unknown action {}", action);
                return PromptOutcome::Repeat;
            },
        };

        match res {
            Ok(action) => PromptOutcome::Action(action),
            Err(e) => {
                if handle_action_loop_error(e) {
                    PromptOutcome::Flush
                } else {
                    PromptOutcome::Repeat
                }
            },
        }
    }

    pub fn prompt(&mut self) -> Vec<Action> {
        let mut actions = vec![];

        loop {
            println!();
            let action = match prompt_action() {
                Ok(v) => v,
                Err(inquire::InquireError::OperationCanceled)
                | Err(inquire::InquireError::OperationInterrupted) => {
                    return actions
                },
                Err(e) => {
                    println!("Unexpected error while determining action: {}", e);
                    return actions;
                },
            };

            match self.foo(&action) {
                PromptOutcome::Action(action) => actions.push(action),
                PromptOutcome::Repeat => continue,
                PromptOutcome::Flush => return actions,
                PromptOutcome::Clear => return vec![],
            }
        }
    }
}

fn handle_action_loop_error(err: InquireError) -> bool {
    match err {
        inquire::InquireError::OperationCanceled
        | inquire::InquireError::OperationInterrupted => false,

        _ => {
            println!("Unexpected error: {}", err);
            true
        },
    }
}

fn prompt_action() -> InquireResult<String> {
    let name = Text::new("action:")
        .with_autocomplete(&action_suggester)
        .prompt();

    name
}

fn action_suggester(val: &str) -> SuggestionResult<Vec<String>> {
    let suggestions = [
        HEADERS,
        HEADERS_RAW,
        DATA,
        OPEN_UNI_STREAM,
        SETTINGS,
        GOAWAY,
        PRIORITY_UPDATE,
        GREASE,
        EXTENSION,
        RESET_STREAM,
        STOP_SENDING,
        PUSH_PROMISE,
        CANCEL_PUSH,
        MAX_PUSH_ID,
        FLUSH,
        QUIT,
    ];

    squish_suggester(&suggestions, val)
}

fn squish_suggester(
    suggestions: &[&str], val: &str,
) -> SuggestionResult<Vec<String>> {
    let val_lower = val.to_lowercase();

    Ok(suggestions
        .iter()
        .filter(|s| s.to_lowercase().contains(&val_lower))
        .map(|s| String::from(*s))
        .collect())
}

fn validate_varint(id: &str) -> SuggestionResult<Validation> {
    let x = id.parse::<u64>();

    match x {
        Ok(v) => {
            if v >= u64::pow(2, 62) {
                return Ok(Validation::Invalid(ErrorMessage::Default));
            }
        },

        Err(_) => {
            return Ok(Validation::Invalid(ErrorMessage::Default));
        },
    }

    Ok(Validation::Valid)
}

fn prompt_stream_id() -> InquireResult<u64> {
    prompt_varint("stream ID:")
}

fn prompt_control_stream_id() -> InquireResult<u64> {
    let id = Text::new("stream ID:")
        .with_validator(prompts::validate_varint)
        .with_autocomplete(&control_stream_suggestor)
        .prompt()?;

    // id is already validated so unwrap always succeeds
    Ok(id.parse::<u64>().unwrap())
}

fn prompt_varint(str: &str) -> InquireResult<u64> {
    let id = Text::new(str)
        .with_validator(prompts::validate_varint)
        .prompt()?;

    // id is already validated so unwrap always succeeds
    Ok(id.parse::<u64>().unwrap())
}

fn control_stream_suggestor(val: &str) -> SuggestionResult<Vec<String>> {
    let suggestions = ["2"];

    squish_suggester(&suggestions, val)
}

pub fn prompt_data() -> InquireResult<Action> {
    let stream_id = prompts::prompt_stream_id()?;

    let payload = Text::new("payload:").prompt()?;

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::Data {
            payload: payload.into(),
        },
    };

    Ok(action)
}

pub fn prompt_max_push_id() -> InquireResult<Action> {
    let stream_id = prompts::prompt_stream_id()?;
    let push_id = prompts::prompt_varint("push ID:")?;

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::MaxPushId { push_id },
    };

    Ok(action)
}

pub fn prompt_cancel_push() -> InquireResult<Action> {
    let stream_id = prompts::prompt_stream_id()?;
    let push_id = prompts::prompt_varint("push ID:")?;

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::CancelPush { push_id },
    };

    Ok(action)
}

pub fn prompt_goaway() -> InquireResult<Action> {
    let stream_id = prompts::prompt_stream_id()?;
    let id = prompts::prompt_varint("ID:")?;

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::GoAway { id },
    };

    Ok(action)
}

pub fn prompt_grease() -> InquireResult<Action> {
    let stream_id = prompts::prompt_control_stream_id()?;
    let raw_type = quiche::h3::grease_value();
    let payload = Text::new("payload:")
        .prompt()
        .expect("An error happened when asking for payload, try again later.");

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::Unknown {
            raw_type,
            payload: payload.into(),
        },
    };

    Ok(action)
}

pub fn prompt_extension() -> InquireResult<Action> {
    let stream_id = prompts::prompt_control_stream_id()?;
    let raw_type = prompts::prompt_varint("frame type:")?;
    let payload = Text::new("payload:")
        .prompt()
        .expect("An error happened when asking for payload, try again later.");

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: quiche::h3::frame::Frame::Unknown {
            raw_type,
            payload: payload.into(),
        },
    };

    Ok(action)
}

mod headers;
mod priority;
mod settings;
mod stream;
