use tokio_quiche::quiche;

use qlog::events::quic::PacketHeader;
use qlog::events::quic::PacketSent;
use qlog::events::quic::PacketType;
use qlog::events::quic::QuicFrame;
use qlog::events::EventData;
use quiche::h3::NameValue;

use smallvec::smallvec;
use smallvec::SmallVec;

#[derive(Default)]
pub struct StreamIdAllocator {
    id: u64,
}

impl StreamIdAllocator {
    pub fn take_next_id(&mut self) -> u64 {
        let old = self.id;
        self.id += 4;

        old
    }

    pub fn peek_next_id(&mut self) -> u64 {
        self.id
    }
}

fn encode_header_block(
    headers: &[quiche::h3::Header],
) -> std::result::Result<Vec<u8>, String> {
    let mut encoder = quiche::h3::qpack::Encoder::new();

    let headers_len = headers
        .iter()
        .fold(0, |acc, h| acc + h.value().len() + h.name().len() + 32);

    let mut header_block = vec![0; headers_len];
    let len = encoder
        .encode(headers, &mut header_block)
        .map_err(|_| "Internal Error")?;

    header_block.truncate(len);

    Ok(header_block)
}

fn fake_packet_header() -> PacketHeader {
    PacketHeader {
        packet_type: PacketType::OneRtt,
        packet_number: None,
        flags: None,
        token: None,
        length: None,
        version: None,
        scil: None,
        dcil: None,
        scid: None,
        dcid: None,
    }
}

fn fake_packet_with_stream_fin(stream_id: u64, fin: bool) -> Option<EventData> {
    if !fin {
        return None;
    }

    let frames = Some(smallvec![QuicFrame::Stream {
        stream_id,
        offset: 0,
        length: 0,
        fin: Some(fin),
        raw: None
    }]);

    Some(fake_packet_sent(frames))
}

pub fn fake_packet_sent(frames: Option<SmallVec<[QuicFrame; 1]>>) -> EventData {
    EventData::PacketSent(PacketSent {
        header: fake_packet_header(),
        is_coalesced: None,
        retry_token: None,
        stateless_reset_token: None,
        supported_versions: None,
        raw: None,
        datagram_id: None,
        trigger: None,
        send_at_time: None,
        frames,
    })
}

pub mod client;
pub mod config;
pub mod h3;
mod tlv;

#[cfg(test)]
mod tests {
    use tokio_quiche::quiche::h3::frame::Frame;
    use tokio_quiche::quiche::h3::Header;

    use crate::{h3::actions::Action, *};

    // TODO: spin up a server. This assumes something's listening on 8085
    #[tokio::test]
    async fn test_wait() -> std::io::Result<()> {
        let config = config::AppConfig {
            host_port: "127.0.0.1:8085".to_owned(),
            connect_to: None,
            source_port: 0,
            verify_peer: true,
            qlog_input: None,
            seperate_qlog_output: false,
            log_verbosity: None,
        };

        let headers = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":authority", b"127.0.0.1:8085"),
            Header::new(b":path", b"/"),
            Header::new(b":scheme", b"https"),
            Header::new(b"test", b"header"),
        ];
        let headers1 = headers.clone();
        let header_block = encode_header_block(&headers).unwrap();
        let header_block1 = encode_header_block(&headers).unwrap();

        let actions = vec![
            Action::SendHeadersFrame {
                stream_id: 0,
                fin_stream: false,
                headers,
                frame: Frame::Headers { header_block },
            },
            Action::SendHeadersFrame {
                stream_id: 4,
                fin_stream: false,
                headers: headers1,
                frame: Frame::Headers {
                    header_block: header_block1,
                },
            },
        ];

        let frame_rx = client::connect(&config, actions).await;
        let received_frames = frame_rx.unwrap().await.unwrap();

        for id in [0, 4] {
            let frames = received_frames.get(id).unwrap();
            assert!(frames.iter().any(|frame| {
                if let Frame::Headers { .. } = frame {
                    true
                } else {
                    false
                }
            }));
        }

        println!("stream_map: {:?}", received_frames);

        Ok(())
    }
}
