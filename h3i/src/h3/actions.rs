use crate::quiche;
use std::collections::BTreeMap;

use foundations::telemetry::log;
use qlog::events::h3::H3FrameCreated;
use qlog::events::h3::H3Owner;
use qlog::events::h3::H3StreamTypeSet;
use qlog::events::h3::Http3Frame;
use qlog::events::quic::PacketSent;
use qlog::events::quic::QuicFrame;
use qlog::events::Event;
use qlog::events::EventData;
use qlog::events::ExData;
use quiche::h3::frame::Frame;
use quiche::h3::NameValue;
use serde_json::json;

use smallvec::smallvec;

use crate::encode_header_block;
use crate::fake_packet_sent;
use crate::fake_packet_with_stream_fin;

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
        error_code: u64,
    },

    StopSending {
        stream_id: u64,
        error_code: u64,
    },
}

impl Action {
    pub fn execute(&self, conn: &mut quiche::Connection) {
        match self {
            Action::SendFrame {
                stream_id,
                fin_stream,
                frame,
            } => {
                log::debug!("frame tx id={} frame={:?}", stream_id, frame);

                // TODO: make serialization smarter
                let mut d = [42; 9999];
                let mut b = octets::OctetsMut::with_slice(&mut d);

                if let Some(s) = conn.qlog_streamer() {
                    for (ev, ex) in self.to_qlog() {
                        // skip dummy packet
                        if matches!(ev, EventData::PacketSent(..)) {
                            continue;
                        }

                        s.add_event_data_ex_now(ev, ex).ok();
                    }
                }
                let len = frame.to_bytes(&mut b).unwrap();
                conn.stream_send(*stream_id, &d[..len], *fin_stream)
                    .unwrap();
            },

            Action::SendHeadersFrame {
                stream_id,
                fin_stream,
                headers,
                frame,
            } => {
                log::debug!(
                    "headers frame tx stream={} hdrs={:?}",
                    stream_id,
                    headers
                );

                // TODO: make serialization smarter
                let mut d = [42; 9999];
                let mut b = octets::OctetsMut::with_slice(&mut d);

                if let Some(s) = conn.qlog_streamer() {
                    for (ev, ex) in self.to_qlog() {
                        // skip dummy packet
                        if matches!(ev, EventData::PacketSent(..)) {
                            continue;
                        }

                        s.add_event_data_ex_now(ev, ex).ok();
                    }
                }
                let len = frame.to_bytes(&mut b).unwrap();
                conn.stream_send(*stream_id, &d[..len], *fin_stream)
                    .unwrap();
            },

            Action::OpenUniStream {
                stream_id,
                fin_stream,
                stream_type,
            } => {
                log::debug!(
                    "open uni stream_id={} ty={} fin={}",
                    stream_id,
                    stream_type,
                    fin_stream
                );

                let mut d = [42; 8];
                let mut b = octets::OctetsMut::with_slice(&mut d);
                b.put_varint(*stream_type).unwrap();
                let off = b.off();

                conn.stream_send(*stream_id, &d[..off], *fin_stream)
                    .unwrap();
            },

            Action::StreamBytes {
                stream_id,
                bytes,
                fin_stream,
            } => {
                log::debug!(
                    "stream bytes tx id={} len={} fin={}",
                    stream_id,
                    bytes.len(),
                    fin_stream
                );
                conn.stream_send(*stream_id, bytes, *fin_stream).unwrap();
            },

            Action::ResetStream {
                stream_id,
                error_code,
            } => {
                log::debug!(
                    "reset_stream stream_id={} error_code={}",
                    stream_id,
                    error_code
                );
                if let Err(e) = conn.stream_shutdown(
                    *stream_id,
                    quiche::Shutdown::Write,
                    *error_code,
                ) {
                    log::error!("can't send reset_stream: {}", e);
                }
            },

            Action::StopSending {
                stream_id,
                error_code,
            } => {
                log::debug!(
                    "stop_sending stream id={} error_code={}",
                    stream_id,
                    error_code
                );

                if let Err(e) = conn.stream_shutdown(
                    *stream_id,
                    quiche::Shutdown::Read,
                    *error_code,
                ) {
                    log::error!("can't send stop_sending: {}", e);
                }
            },
        }
    }

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
                    HTTP3_CONTROL_STREAM_TYPE_ID => {
                        qlog::events::h3::H3StreamType::Control
                    },
                    HTTP3_PUSH_STREAM_TYPE_ID => {
                        qlog::events::h3::H3StreamType::Push
                    },
                    QPACK_ENCODER_STREAM_TYPE_ID => {
                        qlog::events::h3::H3StreamType::QpackEncode
                    },
                    QPACK_DECODER_STREAM_TYPE_ID => {
                        qlog::events::h3::H3StreamType::QpackDecode
                    },

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
                    fake_packet_with_stream_fin(*stream_id, *fin_stream)
                {
                    vec![(dummy, BTreeMap::new())]
                } else {
                    vec![]
                }
            },

            Action::ResetStream {
                stream_id,
                error_code,
            } => {
                let ev =
                    fake_packet_sent(Some(smallvec![QuicFrame::ResetStream {
                        stream_id: *stream_id,
                        error_code: *error_code,
                        final_size: 0
                    }]));
                vec![(ev, BTreeMap::new())]
            },

            Action::StopSending {
                stream_id,
                error_code,
            } => {
                let ev =
                    fake_packet_sent(Some(smallvec![QuicFrame::StopSending {
                        stream_id: *stream_id,
                        error_code: *error_code,
                    }]));
                vec![(ev, BTreeMap::new())]
            },
        }
    }

    pub fn from_qlog(event: &Event) -> Vec<Self> {
        let mut actions = vec![];
        match &event.data {
            EventData::PacketSent(ps) => {
                let packet_actions = Self::from_qlog_packet(ps);
                actions.extend(packet_actions);
            },

            EventData::H3FrameCreated(fc) => {
                let frame_actions = Self::from_qlog_frame(fc, &event.ex_data);
                actions.extend(frame_actions);
            },

            EventData::H3StreamTypeSet(st) => {
                let stream_actions =
                    Self::from_qlog_stream_type_set(st, &event.ex_data);
                actions.extend(stream_actions);
            },

            _ => (),
        }

        actions
    }

    fn from_qlog_packet(ps: &PacketSent) -> Vec<Action> {
        let mut actions = vec![];
        if let Some(frames) = &ps.frames {
            for frame in frames {
                match &frame {
                    // TODO add these
                    QuicFrame::ResetStream {
                        stream_id,
                        error_code,
                        ..
                    } => actions.push(Action::ResetStream {
                        stream_id: *stream_id,
                        error_code: *error_code,
                    }),

                    QuicFrame::StopSending {
                        stream_id,
                        error_code,
                        ..
                    } => actions.push(Action::StopSending {
                        stream_id: *stream_id,
                        error_code: *error_code,
                    }),

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

        actions
    }

    fn from_qlog_frame(fc: &H3FrameCreated, ex_data: &ExData) -> Vec<Action> {
        let mut actions = vec![];
        let stream_id = fc.stream_id;
        let fin_stream = ex_data
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
                        "MAX_FIELD_SECTION_SIZE" => {
                            raw_settings.push((0x6, s.value))
                        },
                        "QPACK_MAX_TABLE_CAPACITY" => {
                            raw_settings.push((0x1, s.value))
                        },
                        "QPACK_BLOCKED_STREAMS" => {
                            raw_settings.push((0x7, s.value))
                        },
                        "SETTINGS_ENABLE_CONNECT_PROTOCOL" => {
                            raw_settings.push((0x8, s.value))
                        },
                        "H3_DATAGRAM" => raw_settings.push((0x33, s.value)),

                        _ => {
                            if let Ok(ty) = s.name.parse::<u64>() {
                                raw_settings.push((ty, s.value));
                            }
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

        actions
    }

    fn from_qlog_stream_type_set(
        st: &H3StreamTypeSet, ex_data: &ExData,
    ) -> Vec<Action> {
        let mut actions = vec![];
        let fin_stream = parse_ex_data(ex_data);
        let stream_type = match st.stream_type {
            qlog::events::h3::H3StreamType::Control => Some(0x0),
            qlog::events::h3::H3StreamType::Push => Some(0x1),
            qlog::events::h3::H3StreamType::QpackEncode => Some(0x2),
            qlog::events::h3::H3StreamType::QpackDecode => Some(0x3),
            qlog::events::h3::H3StreamType::Reserved
            | qlog::events::h3::H3StreamType::Unknown => st.stream_type_value,
            _ => None,
        };

        if let Some(ty) = stream_type {
            actions.push(Action::OpenUniStream {
                stream_id: st.stream_id,
                fin_stream,
                stream_type: ty,
            })
        }

        actions
    }
}

fn parse_ex_data(ex_data: &ExData) -> bool {
    ex_data
        .get("fin_stream")
        .unwrap_or(&serde_json::Value::Null)
        .as_bool()
        .unwrap_or_default()
}
