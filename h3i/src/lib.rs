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
pub mod tq_client;
