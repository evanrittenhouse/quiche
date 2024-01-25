use std::collections::BTreeMap;

use qlog::events::h3::H3FrameCreated;
use qlog::events::h3::Http3Frame;
use qlog::events::quic::QuicFrame;
use qlog::events::Event;
use qlog::events::EventData;
use qlog::events::ExData;
use quiche::h3::NameValue;
use serde_json::json;

use crate::dummy_packet_with_stream_frame;
use crate::encode_header_block;

#[derive(Debug)]
pub enum Action {
    SendFrame {
        stream_id: u64,
        fin_stream: bool,
        frame: quiche::h3::frame::Frame,
    },

    SendHeadersFrame {
        stream_id: u64,
        fin_stream: bool,
        headers: Vec<quiche::h3::Header>,
        frame: quiche::h3::frame::Frame,
    },

    StreamBytes {
        stream_id: u64,
        fin_stream: bool,
        bytes: Vec<u8>,
    },

    ResetStream {
        stream_id: u64,
        transport: bool,
        error_code: u64,
    },

    StopSending {
        stream_id: u64,
        transport: bool,
        error_code: u64,
    },
}

impl Action {
    pub fn to_qlog(&self) -> Vec<(EventData, ExData)> {
        match self {
            Action::SendFrame {
                stream_id,
                fin_stream,
                frame,
            } => {
                let frame_ev = EventData::H3FrameCreated(H3FrameCreated {
                    stream_id: *stream_id,
                    length: None,
                    frame: frame.to_qlog(),
                    raw: None,
                });

                let mut ex = BTreeMap::new();

                if *fin_stream {
                    ex.insert("fin_stream".to_string(), json!(true));
                }

                vec![(frame_ev, ex)]
            },

            Action::SendHeadersFrame {
                stream_id,
                fin_stream,
                headers,
                frame: _,
            } => {
                let qlog_headers = headers
                    .iter()
                    .map(|h| qlog::events::h3::HttpHeader {
                        name: String::from_utf8_lossy(h.name()).into_owned(),
                        value: String::from_utf8_lossy(h.value()).into_owned(),
                    })
                    .collect();

                let frame = Http3Frame::Headers {
                    headers: qlog_headers,
                };

                let frame_ev = EventData::H3FrameCreated(H3FrameCreated {
                    stream_id: *stream_id,
                    length: None,
                    frame,
                    raw: None,
                });

                let mut ex = BTreeMap::new();

                if *fin_stream {
                    ex.insert("fin_stream".to_string(), json!(true));
                }

                vec![(frame_ev, ex)]
            },

            Action::StreamBytes {
                stream_id,
                fin_stream,
                bytes: _,
            } => {
                if let Some(dummy) =
                    dummy_packet_with_stream_frame(*stream_id, *fin_stream)
                {
                    vec![(dummy, BTreeMap::new())]
                } else {
                    vec![]
                }
            },

            _ => vec![],
        }
    }

    pub fn from_qlog(event: &Event) -> Vec<Self> {
        let mut actions = vec![];
        match &event.data {
            EventData::PacketSent(ps) => {
                if let Some(frames) = &ps.frames {
                    for frame in frames {
                        match &frame {
                            // TODO add these
                            QuicFrame::ResetStream { .. } => (),
                            QuicFrame::StopSending { .. } => (),

                            QuicFrame::Stream { stream_id, fin, .. } => {
                                let fin = fin.unwrap_or_default();

                                if fin {
                                    actions.push(Action::StreamBytes {
                                        stream_id: *stream_id,
                                        fin_stream: true,
                                        bytes: vec![],
                                    });
                                }
                            },

                            _ => (),
                        }
                    }
                }
            },

            EventData::H3FrameCreated(fc) => match &fc.frame {
                Http3Frame::Headers { headers } => {
                    let fin_stream = event.ex_data["fin_stream"].as_bool().unwrap_or_default();

                    let hdrs: Vec<quiche::h3::Header> = headers
                        .iter()
                        .map(|h| {
                            quiche::h3::Header::new(
                                h.name.as_bytes(),
                                h.value.as_bytes(),
                            )
                        })
                        .collect();
                    let header_block = encode_header_block(&hdrs).unwrap();
                    actions.push(Action::SendHeadersFrame {
                        stream_id: fc.stream_id,
                        fin_stream,
                        headers: hdrs,
                        frame: quiche::h3::frame::Frame::Headers { header_block },
                    });
                },

                _ => (),
            },
            _ => (),
        }

        actions
    }
}
