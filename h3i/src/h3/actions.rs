use std::collections::BTreeMap;

use qlog::events::h3::H3FrameCreated;
use qlog::events::h3::H3Owner;
use qlog::events::h3::H3StreamTypeSet;
use qlog::events::h3::Http3Frame;
use qlog::events::quic::QuicFrame;
use qlog::events::Event;
use qlog::events::EventData;
use qlog::events::ExData;
use quiche::h3::frame::Frame;
use quiche::h3::NameValue;
use serde_json::json;

use crate::dummy_packet_with_stream_frame;
use crate::encode_header_block;

pub const HTTP3_CONTROL_STREAM_TYPE_ID: u64 = 0x0;
pub const HTTP3_PUSH_STREAM_TYPE_ID: u64 = 0x1;
pub const QPACK_ENCODER_STREAM_TYPE_ID: u64 = 0x2;
pub const QPACK_DECODER_STREAM_TYPE_ID: u64 = 0x3;

#[derive(Debug)]
pub enum Action {
    SendFrame {
        stream_id: u64,
        fin_stream: bool,
        frame: Frame,
    },

    SendHeadersFrame {
        stream_id: u64,
        fin_stream: bool,
        headers: Vec<quiche::h3::Header>,
        frame: Frame,
    },

    StreamBytes {
        stream_id: u64,
        fin_stream: bool,
        bytes: Vec<u8>,
    },

    OpenUniStream {
        stream_id: u64,
        fin_stream: bool,
        stream_type: u64,
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

            Action::OpenUniStream {
                stream_id,
                fin_stream,
                stream_type,
            } => {
                let ty = match *stream_type {
                    HTTP3_CONTROL_STREAM_TYPE_ID =>
                        qlog::events::h3::H3StreamType::Control,
                    HTTP3_PUSH_STREAM_TYPE_ID =>
                        qlog::events::h3::H3StreamType::Push,
                    QPACK_ENCODER_STREAM_TYPE_ID =>
                        qlog::events::h3::H3StreamType::QpackEncode,
                    QPACK_DECODER_STREAM_TYPE_ID =>
                        qlog::events::h3::H3StreamType::QpackDecode,

                    _ => qlog::events::h3::H3StreamType::Unknown,
                };
                let ty_val =
                    if matches!(ty, qlog::events::h3::H3StreamType::Unknown) {
                        Some(*stream_type)
                    } else {
                        None
                    };

                let stream_ev = EventData::H3StreamTypeSet(H3StreamTypeSet {
                    owner: Some(H3Owner::Local),
                    stream_id: *stream_id,
                    stream_type: ty,
                    stream_type_value: ty_val,
                    associated_push_id: None,
                });
                let mut ex = BTreeMap::new();

                if *fin_stream {
                    ex.insert("fin_stream".to_string(), json!(true));
                }

                vec![(stream_ev, ex)]
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

            EventData::H3FrameCreated(fc) => {
                let stream_id = fc.stream_id;
                let fin_stream = event
                    .ex_data
                    .get("fin_stream")
                    .unwrap_or(&serde_json::Value::Null)
                    .as_bool()
                    .unwrap_or_default();

                match &fc.frame {
                    Http3Frame::Settings { settings } => {
                        let mut raw_settings = vec![];
                        // This is ugly but it reflects ambiguity in the qlog
                        // specs.
                        for s in settings {
                            match s.name.as_str() {
                                "MAX_FIELD_SECTION_SIZE" =>
                                    raw_settings.push((0x6, s.value)),
                                "QPACK_MAX_TABLE_CAPACITY" =>
                                    raw_settings.push((0x1, s.value)),
                                "QPACK_BLOCKED_STREAMS" =>
                                    raw_settings.push((0x7, s.value)),
                                "SETTINGS_ENABLE_CONNECT_PROTOCOL" =>
                                    raw_settings.push((0x8, s.value)),
                                "H3_DATAGRAM" =>
                                    raw_settings.push((0x33, s.value)),

                                _ =>
                                    if let Ok(ty) = s.name.parse::<u64>() {
                                        raw_settings.push((ty, s.value));
                                    },
                            }
                        }
                        actions.push(Action::SendFrame {
                            stream_id,
                            fin_stream,
                            frame: Frame::Settings {
                                max_field_section_size: None,
                                qpack_max_table_capacity: None,
                                qpack_blocked_streams: None,
                                connect_protocol_enabled: None,
                                h3_datagram: None,
                                grease: None,
                                raw: Some(raw_settings),
                            },
                        })
                    },

                    Http3Frame::Headers { headers } => {
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
                            stream_id,
                            fin_stream,
                            headers: hdrs,
                            frame: Frame::Headers { header_block },
                        });
                    },

                    Http3Frame::Goaway { id } => {
                        actions.push(Action::SendFrame {
                            stream_id,
                            fin_stream,
                            frame: Frame::GoAway { id: *id },
                        });
                    },

                    _ => unimplemented!(),
                }
            },
            _ => (),
        }

        actions
    }
}
