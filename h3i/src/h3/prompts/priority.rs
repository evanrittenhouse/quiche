use crate::quiche;
use inquire::error::InquireResult;
use inquire::Select;
use inquire::Text;

use super::stream::prompt_fin_stream;
use crate::h3::actions::Action;
use crate::h3::prompts;

const REQUEST: &str = "request";
const PUSH: &str = "push";

pub fn prompt_priority() -> InquireResult<Action> {
    let stream_id = prompts::prompt_stream_id()?;

    let ty = prompt_request_or_push()?;
    let prioritized_element_id =
        prompts::prompt_varint("Prioritized Element ID:")?;

    let priority_field_value = Text::new("priority field value:").prompt()?;

    let frame = if ty.as_str() == REQUEST {
        quiche::h3::frame::Frame::PriorityUpdateRequest {
            prioritized_element_id,
            priority_field_value: priority_field_value.into(),
        }
    } else {
        quiche::h3::frame::Frame::PriorityUpdatePush {
            prioritized_element_id,
            priority_field_value: priority_field_value.into(),
        }
    };

    let fin_stream = prompt_fin_stream()?;

    let action = Action::SendFrame {
        stream_id,
        fin_stream,
        frame,
    };

    Ok(action)
}

fn prompt_request_or_push() -> InquireResult<String> {
    Ok(Select::new("request or push:", vec![REQUEST, PUSH])
        .prompt()?
        .to_string())
}
