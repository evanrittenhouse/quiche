use crate::quiche;

use async_trait::async_trait;
use buffer_pool::ConsumeBuffer;
use buffer_pool::Pool;
use buffer_pool::Pooled;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::sync::OnceLock;
use std::task::Poll;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_quiche::http3::driver::H3ConnectionError;
use tokio_quiche::{BoxError, QuicResult};

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

// TODO: QLOGDIR/SSLKEYLOGFILE support in tokio-quiche
//      - SSLKEYLOGFILE: FLPROTO-2329
//      - QLOGDIR: CLIENT-9692
// TODO: do we have to support QUIC frames/arbitrary binary/DGRAMs in response as well?
// TODO: Need to move away from the single-flush assumption (may need to rethink how StreamMap is populated and sent)
//   - Left out because that's how h3i currently functions, though it should definitely be extended
// TODO: would be cool to add ability to write to a PCAP
// TODO: we are forced to wait for the 5s Quiche idle timeout to pass before the connetion closes
//       since we're no longer just awaiting a single send. We should mimic something like
//       H3Driver's QuicCommand to get around that
// TODO: get rid of pools, use a single buffer in TQ?

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
pub async fn connect(
    args: &AppConfig, frame_actions: Vec<Action>,
) -> std::result::Result<FrameRx, ClientError> {
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
    quiche_config.verify_peer(false);

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
        capture_quiche_logs: true,
    };

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

    let socket = tokio::net::UdpSocket::bind(bind_addr).await.unwrap();
    socket.connect(peer_addr).await.unwrap();
    log::info!("connected to socket");

    let local = socket.local_addr().unwrap();
    let peer = socket.peer_addr().unwrap();
    let (h3i, frame_rx) = H3iDriver::new(frame_actions);
    let _ = tokio_quiche::quic::connect_with_config(
        socket,
        Some(connect_url),
        config,
        h3i,
    )
    .await
    .unwrap();
    log::debug!(
        "quic connection created";
        "local_addr"=>local,
        "peer_addr"=>peer
    );

    Ok(stream_map_rx)
}

pub struct H3iDriver {
    buffer: Pooled<ConsumeBuffer>,
    actions: Vec<Action>,
    actions_executed: usize,
    /// Sends [StreamedFrame]s to the user-facing [FrameRx].
    frame_tx: mpsc::UnboundedSender<StreamedFrame>,
    /// The minimum time at which the next action should fire.  
    next_fire_time: Instant,
    /// If the [quiche::Connection] is established
    qconn_established: bool,
}

impl H3iDriver {
    fn new(actions: Vec<Action>) -> (Self, FrameRx) {
        let (frame_tx, frame_rx) = mpsc::unbounded_channel();
        let (conn_close_tx, conn_close_rx) = mpsc::unbounded_channel();

        let frame_rx = FrameRx::new(frame_rx, conn_close_rx);

        (
            Self {
                buffer: BUF_POOL.get_with(|d| d.expand(MAX_POOL_BUF_SIZE)),
                actions,
                actions_executed: 0,
                frame_tx,
                next_fire_time: Instant::now(),
                qconn_established: false,
                conn_close_tx,
            },
            frame_rx,
        )
    }

    /// If all actions have been completed.
    fn actions_complete(&self) -> bool {
        self.actions_executed == self.actions.len()
    }

    /// If the next action should fire.
    fn should_fire(&self) -> bool {
        Instant::now() >= self.next_fire_time
    }
}

#[async_trait]
impl ApplicationOverQuic for H3iDriver {
    fn on_conn_established(
        &mut self, _qconn: &mut quiche::Connection,
    ) -> QuicResult<()> {
        log::trace!("H3iDriver connection established");
        self.qconn_established = true;
        Ok(())
    }

    fn should_act(&self) -> bool {
        self.qconn_established
    }

    fn process_reads(
        &mut self, qconn: &mut quiche::Connection,
    ) -> QuicResult<()> {
        log::trace!("process_reads");

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

                        // Send the frame back to the user-facing receiver.
                        let _ = self
                            .frame_tx
                            .send(StreamedFrame::new(frame.clone(), stream));

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

        Ok(())
    }

    fn process_writes(
        &mut self, qconn: &mut quiche::Connection, _fresh: Option<u64>,
    ) -> QuicResult<()> {
        log::trace!("process_writes");

        // TODO: skipping is currently unnecessary sine we'll only flush once. if we want to stay
        // with single flushes, we an drop it, if we want to do multi-flushes (will require changes
        // in h3i core) we'll have to skip up to the next flush action
        for action in &self.actions[self.actions_executed..] {
            let should_fire = self.should_fire();

            match action {
                Action::SendFrame { .. }
                | Action::StreamBytes { .. }
                | Action::ResetStream { .. }
                | Action::StopSending { .. }
                | Action::OpenUniStream { .. }
                | Action::SendHeadersFrame { .. } => {
                    if should_fire {
                        // Reset the fire time such that the next action will still fire.
                        self.next_fire_time = Instant::now();

                        log::trace!("firing action: {:?}", action);

                        action.execute(qconn);
                        self.actions_executed += 1;
                    } else {
                        break;
                    }
                },
                Action::Wait { duration } => {
                    self.next_fire_time = Instant::now() + *duration;
                    self.actions_executed += 1;

                    log::trace!("firing wait: {:?}", duration);

                    break;
                },
            }
        }

        Ok(())
    }

    fn on_conn_closed(&mut self) -> QuicResult<()> {
        if self.actions_complete() {
            self.conn_close_tx
                .send(())
                .map_err(|e| Box::new(e) as BoxError)
        } else {
            log::error!("connection closed without all actions getting sent");
            // TODO: real error :)
            Err(Box::new(H3ConnectionError::ServerWentAway))
        }
    }

    async fn wait_for_data(
        &mut self, qconn: &mut quiche::Connection,
    ) -> QuicResult<()> {
        // Necessary for killing tasks when running in binary mode, since the Tokio runtime
        // will stay alive so long as the tokio-quiche IoWorker/InboundPacketRouter lives.
        //
        // We can't just insta-return Ok(()) because that will starve the packet receipt arm in the
        // IoWorker select! loop.
        if Instant::now() < self.next_fire_time {
            // We must have queued a Wait action, so let the timer expire
            tokio::time::sleep_until(self.next_fire_time).await;
            log::trace!("releasing Wait timer");
            Ok(())
        } else {
            Err(std::future::poll_fn(|_| {
                if qconn.is_closed() && self.actions_complete() {
                    // TODO: real error :)
                    return Poll::Ready(Box::new(
                        H3ConnectionError::ServerWentAway,
                    ));
                } else {
                    return Poll::Pending;
                }
            })
            .await)
        }
    }

    fn buffer(&mut self) -> &mut Pooled<ConsumeBuffer> {
        &mut self.buffer
    }
}
