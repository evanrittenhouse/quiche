use crate::quiche;
use inquire::error::InquireResult;
use inquire::validator::Validation;
use inquire::Text;
use quiche::h3::frame::Frame;

use crate::encode_header_block;
use crate::h3;
use crate::h3::prompts;
use crate::StreamIdAllocator;

use super::squish_suggester;
use super::stream::prompt_fin_stream;
use super::SuggestionResult;
use super::HOST_PORT;
use crate::h3::actions::Action;

pub fn prompt_headers(
    sid_alloc: &mut StreamIdAllocator, raw: bool,
) -> InquireResult<Action> {
    let stream_id = Text::new("stream ID:")
        .with_placeholder("empty picks next available ID")
        .with_help_message("ESC to return to actions")
        .with_validator(validate_stream_id)
        .prompt()?;

    let stream_id = match stream_id.as_str() {
        "" => {
            let id = sid_alloc.peek_next_id();
            println!("autopick Stream ID={}", id);
            id
        },

        _ => stream_id.parse::<u64>().unwrap(),
    };

    let mut headers = vec![];

    if !raw {
        headers.extend_from_slice(&pseudo_headers()?);
    }

    headers.extend_from_slice(&headers_read_loop()?);

    sid_alloc.take_next_id();

    let header_block = encode_header_block(&headers).unwrap();

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendHeadersFrame {
        stream_id,
        fin_stream,
        headers,
        frame: Frame::Headers { header_block },
    };

    Ok(action)
}

pub fn prompt_push_promise() -> InquireResult<Action> {
    let stream_id = prompts::prompt_stream_id()?;
    let push_id = prompts::prompt_varint("push ID:")?;

    let headers = headers_read_loop()?;
    let header_block = if headers.is_empty() {
        vec![]
    } else {
        encode_header_block(&headers).unwrap()
    };

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame: Frame::PushPromise {
            push_id,
            header_block,
        },
    };

    Ok(action)
}

fn pseudo_headers() -> InquireResult<Vec<quiche::h3::Header>> {
    let method = Text::new("method:")
        .with_autocomplete(&method_suggester)
        .with_help_message("ESC to return to actions")
        .prompt()?;

    let authority = Text::new("authority:")
        .with_autocomplete(&authority_suggester)
        .with_help_message("ESC to return to actions")
        .prompt()?;

    let path = Text::new("path:").prompt()?;

    let scheme = Text::new("scheme:")
        .with_autocomplete(&scheme_suggester)
        .with_help_message("ESC to return to actions")
        .prompt()?;

    Ok(vec![
        quiche::h3::Header::new(b":method", method.as_bytes()),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b":scheme", scheme.as_bytes()),
    ])
}

fn headers_read_loop() -> InquireResult<Vec<quiche::h3::Header>> {
    let mut headers = vec![];
    loop {
        let name = Text::new("field name:")
            .with_help_message(
                "type 'q!' to complete headers, or ESC to return to actions",
            )
            .prompt()?;

        if name == "q!" {
            break;
        }

        let value = Text::new("field value:")
            .with_help_message("ESC to return to actions")
            .prompt()?;

        headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
    }

    Ok(headers)
}

fn method_suggester(val: &str) -> SuggestionResult<Vec<String>> {
    let suggestions = ["GET", "POST", "PUT", "DELETE"];

    squish_suggester(&suggestions, val)
}

fn authority_suggester(val: &str) -> SuggestionResult<Vec<String>> {
    let suggestions = [HOST_PORT.get().unwrap().as_str()];

    squish_suggester(&suggestions, val)
}

fn scheme_suggester(val: &str) -> SuggestionResult<Vec<String>> {
    let suggestions = ["https"];

    squish_suggester(&suggestions, val)
}

fn validate_stream_id(id: &str) -> SuggestionResult<Validation> {
    if id.is_empty() {
        return Ok(Validation::Valid);
    }

    h3::prompts::validate_varint(id)
}
