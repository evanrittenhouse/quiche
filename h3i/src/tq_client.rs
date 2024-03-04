// TODO: QLOGDIR/SSLKEYLOGFILE support in tokio-quiche
//      - FLPROTO-2329
// TODO: get rid of unwrap()s, coerce ClientError to something that TQ can speak
// TODO: do we have to support QUIC frames/arbitrary binary/DGRAMs in response as well?
// TODO: extract QuicConnection creation into a separate function, converting between quiche
// and TQ config
// TODO: smarter config creation
// TODO: need a better way of determining if we should send the map back to the user
// TODO: Need to move away from the single-flush assumption (may need to rethink how StreamMap is populated and sent)
//   - Left out because that's how h3i currently functions, though it should definitely be extended
// TODO: would be cool to add ability to write to a pcap, maybe by spinning off a tcpdump process?

use crate::quiche;

use async_trait::async_trait;
use buffer_pool::ConsumeBuffer;
use buffer_pool::Pool;
use buffer_pool::Pooled;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use tokio::sync::oneshot;
use tokio_quiche::http3::driver::H3ConnectionError;
use tokio_quiche::BoxError;
use tokio_quiche::QuicResult;

use foundations::telemetry::log;
use qlog::events::h3::H3FrameParsed;
use qlog::events::h3::Http3Frame;
use qlog::events::EventData;
use tokio_quiche::quic::connection::ApplicationOverQuic;
use tokio_quiche::quiche::Config as QConfig;
use tokio_quiche::settings::MtuConfig;
use tokio_quiche::Config;

use crate::config::AppConfig;
use crate::h3::actions::Action;

use crate::tlv::VarintTlv;
use quiche::h3::frame::Frame;
use quiche::h3::NameValue;

const MAX_DATAGRAM_SIZE: usize = 1350;
const DATAGRAM_POOL_SIZE: usize = 64 * 1024;
const POOL_SIZE: usize = 16 * 1024;
const POOL_SHARDS: usize = 8;
pub const MAX_POOL_BUF_SIZE: usize = 64 * 1024;

/// A generic buffer pool used to pass data around.
pub static BUF_POOL: Pool<POOL_SHARDS, ConsumeBuffer> =
    Pool::<POOL_SHARDS, _>::new(POOL_SIZE, MAX_POOL_BUF_SIZE);
/// A datagram pool shared for both UDP streams, and incoming QUIC packets.
pub static DATAGRAM_POOL: Pool<POOL_SHARDS, ConsumeBuffer> =
    Pool::<POOL_SHARDS, _>::new(DATAGRAM_POOL_SIZE, MAX_DATAGRAM_SIZE);

#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    HttpFail,
    Other(String),
}

/// Connect to the socket.
pub async fn tq_connect(
    args: &AppConfig, frame_actions: Vec<Action>,
) -> std::result::Result<oneshot::Receiver<StreamMap>, ClientError> {
    let mut quiche_config = QConfig::new(1).unwrap();
    quiche_config.verify_peer(args.verify_peer);
    quiche_config.set_application_protos(&[b"h3"]).unwrap();
    quiche_config.set_max_idle_timeout(5000);
    quiche_config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    quiche_config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    quiche_config.set_initial_max_data(10_000_000);
    quiche_config.set_initial_max_stream_data_bidi_local(1_000_000);
    quiche_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    quiche_config.set_initial_max_stream_data_uni(1_000_000);
    quiche_config.set_initial_max_streams_bidi(100);
    quiche_config.set_initial_max_streams_uni(100);
    quiche_config.set_disable_active_migration(true);
    quiche_config.set_active_connection_id_limit(0);
    let config = Config {
        quiche_config,
        disable_client_ip_validation: true,
        mtu: MtuConfig {
            size: 1200,
            gso: false,
        },
        // qlog_dir: std::env::var_os("QLOGDIR").map_or(None, |s| Some(s.into())),
        qlog_dir: None,
        check_udp_drop: false,
        check_rx_delay: false,
        pacing_offload: false,
        enable_expensive_packet_count_metrics: false,
        has_gro: false,
        capture_quiche_logs: false,
    };

    log::info!("made config");

    let connect_url = args.host_port.split(':').next().unwrap();

    // Resolve server address.
    let peer_addr = if let Some(addr) = &args.connect_to {
        addr.parse().expect("--connect-to is expected to be a string containing an IPv4 or IPv6 address with a port. E.g. 192.0.2.0:443")
    } else {
        let x = format!("https://{}", args.host_port);
        url::Url::parse(&x)
            .unwrap()
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap()
    };

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => format!("0.0.0.0:{}", args.source_port),
        std::net::SocketAddr::V6(_) => format!("[::]:{}", args.source_port),
    };

    // TODO: get rid of unwrap()s, coerce ClientError to something that TQ can
    // speak
    let socket = tokio::net::UdpSocket::bind(bind_addr).await.unwrap();
    socket.connect(peer_addr).await.unwrap();

    log::info!("connected to socket");

    log::debug!(
        "creating quic connection";
        "local_addr"=>socket.local_addr().unwrap(),
        "peer_addr"=>socket.peer_addr().unwrap(),
    );

    let (h3i, stream_map_rx) = H3iDriver::new(frame_actions);
    let _ = tokio_quiche::quic::connect_with_config(
        socket,
        Some(connect_url),
        config,
        h3i,
    )
    .await
    .unwrap();

    log::info!("now what?");

    Ok(stream_map_rx)
}

pub struct H3iDriver {
    buffer: Pooled<ConsumeBuffer>,
    actions: Vec<Action>,
    actions_executed: usize,
    stream_map: Option<StreamMap>,
    /// Sends the [StreamMap] back to the user on completion.
    stream_map_tx: Option<oneshot::Sender<StreamMap>>,
}

impl H3iDriver {
    fn new(actions: Vec<Action>) -> (Self, oneshot::Receiver<StreamMap>) {
        let (stream_map_tx, stream_map_rx) = oneshot::channel();
        (
            Self {
                buffer: BUF_POOL.get_with(|d| d.expand(MAX_POOL_BUF_SIZE)),
                actions,
                actions_executed: 0,
                stream_map: Some(StreamMap::new()),
                stream_map_tx: Some(stream_map_tx),
            },
            stream_map_rx,
        )
    }

    /// If the [StreamMap] has been sent back to the user.
    fn sent_map(&self) -> bool {
        self.stream_map.is_none() || self.stream_map_tx.is_none()
    }

    // TODO: needed?
    fn stream_map_mut(&mut self) -> Result<&mut StreamMap, BoxError> {
        self.stream_map
            .as_mut()
            .ok_or(Box::new(quiche::Error::Done))
    }
}

#[async_trait]
impl ApplicationOverQuic for H3iDriver {
    fn on_conn_established(
        &mut self, qconn: &mut quiche::Connection,
    ) -> QuicResult<()> {
        log::info!("connection established");
        Ok(())
    }

    fn should_act(&self) -> bool {
        true
    }

    fn process_reads(
        &mut self, qconn: &mut quiche::Connection,
    ) -> QuicResult<()> {
        if self.sent_map() {
            // If we've already sent the StreamMap to the user, we can skip all the work here
            return Ok(());
        }

        let stream_map = self.stream_map.as_mut().unwrap();

        for stream in qconn.readable() {
            // TODO: ignoring control streams
            if stream % 4 != 0 {
                continue;
            }

            let mut d = [42; 16000];

            match qconn.stream_recv(stream, &mut d) {
                Ok((len, _fin)) => {
                    log::trace!("read {} stream bytes", len);
                    let mut tlv = VarintTlv::with_slice(&d[..len]).unwrap();
                    loop {
                        let frame_ty = tlv
                            .ty()
                            .expect("not enough bytes to read frame type");
                        let frame_len = tlv
                            .len()
                            .expect("not enough bytes to read frame length");
                        log::debug!("tlv ty={frame_ty} len={frame_len}");
                        let frame_val = tlv
                            .val()
                            .expect("not enough bytes to read frame payload");

                        let frame = quiche::h3::frame::Frame::from_bytes(
                            frame_ty,
                            frame_len,
                            frame_val.buf(),
                        )
                        .unwrap();

                        stream_map.insert(&stream, frame.clone());

                        log::debug!("frame rx={frame:?} off={}", tlv.off());

                        match frame {
                            quiche::h3::frame::Frame::Headers {
                                header_block,
                            } => {
                                let mut qpack_decoder =
                                    quiche::h3::qpack::Decoder::new();
                                let headers = qpack_decoder
                                    .decode(&header_block, u64::MAX)
                                    .unwrap();
                                log::trace!("hdrs={:?}", headers);

                                let qlog_headers = headers
                                    .iter()
                                    .map(|h| qlog::events::h3::HttpHeader {
                                        name: String::from_utf8_lossy(h.name())
                                            .into_owned(),
                                        value: String::from_utf8_lossy(h.value())
                                            .into_owned(),
                                    })
                                    .collect();

                                let frame = Http3Frame::Headers {
                                    headers: qlog_headers,
                                };

                                if let Some(s) = qconn.qlog_streamer() {
                                    let ev_data =
                                        EventData::H3FrameParsed(H3FrameParsed {
                                            stream_id: 0,
                                            length: None,
                                            frame,
                                            raw: None,
                                        });

                                    s.add_event_data_now(ev_data).ok();
                                }
                            },

                            _ => {
                                if let Some(s) = qconn.qlog_streamer() {
                                    let ev_data =
                                        EventData::H3FrameParsed(H3FrameParsed {
                                            stream_id: 0,
                                            length: None,
                                            frame: frame.to_qlog(),
                                            raw: None,
                                        });

                                    s.add_event_data_now(ev_data).ok();
                                }
                            },
                        }

                        if tlv.off() == len {
                            log::trace!("read all buffer");
                            break;
                        }

                        tlv.reset();
                    }
                },

                Err(e) => log::error!("stream read error: {e}"),
            }
        }

        if stream_map.is_full() {
            let _ = self
                .stream_map_tx
                .take()
                .unwrap()
                .send(self.stream_map.take().unwrap());
        }

        Ok(())
    }

    fn process_writes(
        &mut self, qconn: &mut quiche::Connection, fresh: Option<u64>,
    ) -> QuicResult<()> {
        if self.actions_executed == self.actions.len() {
            return Ok(());
        };

        if self.sent_map() {
            return Ok(());
        }

        let stream_map = self.stream_map.as_mut().unwrap();

        // TODO: skipping is currently unnecessary sine we'll only flush once. if we want to stay
        // with single flushes, we an drop it, if we want to do multi-flushes (will require changes
        // in h3i core) we'll have to skip up to the next flush action
        //
        // If we receive a Wait, we should break out of process_writes and wait in wait_for_data
        for action in self.actions.iter().skip(self.actions_executed) {
            match action {
                Action::SendFrame { stream_id, .. }
                | Action::StreamBytes { stream_id, .. }
                | Action::ResetStream { stream_id, .. }
                | Action::StopSending { stream_id, .. }
                | Action::OpenUniStream { stream_id, .. }
                | Action::SendHeadersFrame { stream_id, .. } => {
                    stream_map.initialize_stream(stream_id)
                },
            }
            action.execute(qconn);
            self.actions_executed += 1;
        }

        Ok(())
    }

    async fn wait_for_data(
        &mut self, qconn: &mut quiche::Connection,
    ) -> QuicResult<()> {
        // TODO: have to kill the tasks gracefully
        // It seems that in binary mode, leaving the tasks up will make the program hang since
        // tokio won't close if there are running tasks?
        if self.sent_map() || qconn.is_closed() {
            // TODO: cleanly cancel the tasks
            return Err(Box::new(H3ConnectionError::ServerWentAway));
        } else {
            Ok(())
        }
    }

    fn buffer(&mut self) -> &mut Pooled<ConsumeBuffer> {
        &mut self.buffer
    }
}

// This may not have to be a separate struct at all, if we populate it in the awaited task
/// Tracks the streams initialized by sending frames and the frames received over those streams in
/// response.
///
/// TODO: this may have to support QUIC frames as well, e.g. CONNECTION-CLOSE
#[derive(Clone, Debug)]
pub struct StreamMap {
    inner: HashMap<u64, Vec<Frame>>,
}

impl StreamMap {
    fn new() -> Self {
        Self {
            inner: HashMap::default(),
        }
    }

    pub fn get(&self, stream_id: u64) -> Option<&Vec<Frame>> {
        self.inner.get(&stream_id)
    }

    // TODO: doesn't handle server-initialized streams, combine insert and initialize
    fn initialize_stream(&mut self, stream_id: &u64) {
        self.inner.insert(*stream_id, vec![]);
    }

    fn insert(&mut self, stream_id: &u64, frame: Frame) {
        self.inner
            .get_mut(stream_id)
            .expect(&format!("Stream {stream_id} was never initialized"))
            .push(frame)
    }

    fn is_full(&self) -> bool {
        self.inner.values().all(|v| !v.is_empty())
    }
}
