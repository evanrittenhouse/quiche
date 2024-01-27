use std::net::ToSocketAddrs;

use qlog::events::h3::H3FrameParsed;
use qlog::events::h3::Http3Frame;
use qlog::events::EventData;

use crate::config::AppConfig;
use crate::h3::actions::Action;
use crate::tlv::VarintTlv;

use quiche::h3::NameValue;

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    HttpFail,
    Other(String),
}

pub fn connect(
    args: &AppConfig, frame_actions: &[Action],
) -> std::result::Result<(), ClientError> {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    // let output_sink =
    // Rc::new(RefCell::new(output_sink)) as Rc<RefCell<dyn FnMut(_)>>;

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // We'll only connect to one server.
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

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(1).unwrap();

    // if let Some(ref trust_origin_ca_pem) = args.trust_origin_ca_pem {
    //    config
    //        .load_verify_locations_from_file(trust_origin_ca_pem)
    //        .map_err(|e| {
    //            ClientError::Other(format!(
    //                "error loading origin CA file : {}",
    //                e
    //            ))
    //        })?;
    //} else {
    config.verify_peer(args.verify_peer);
    //}
    config.set_application_protos(&[b"h3"]).unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.set_active_connection_id_limit(0);

    // config.set_max_connection_window(conn_args.max_window);
    // config.set_max_stream_window(conn_args.max_stream_window);

    let mut keylog = None;

    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();

        keylog = Some(file);

        config.log_keys();
    }

    config.grease(false);

    let mut app_proto_selected = false;

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut scid);

    let scid = quiche::ConnectionId::from_ref(&scid);

    let local_addr = socket.local_addr().unwrap();

    // Create a QUIC connection and initiate handshake.
    let mut conn = quiche::connect(
        Some(connect_url),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )
    .unwrap();

    if let Some(keylog) = &mut keylog {
        if let Ok(keylog) = keylog.try_clone() {
            conn.set_keylog(Box::new(keylog));
        }
    }

    if let Some(dir) = std::env::var_os("QLOGDIR") {
        let id = format!("{scid:?}");
        let writer = make_qlog_writer(&dir, "client", &id);

        conn.set_qlog(
            std::boxed::Box::new(writer),
            "h3i-client qlog".to_string(),
            format!("{} id={}", "quiche-client qlog", id),
        );
    }

    println!(
        "connecting to {:} from {:} with scid {:?}",
        peer_addr,
        socket.local_addr().unwrap(),
        scid,
    );

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            println!(
                "{} -> {}: send() would block",
                socket.local_addr().unwrap(),
                send_info.to
            );
            continue;
        }

        return Err(ClientError::Other(format!("send() failed: {e:?}")));
    }

    // println!("written {}", write);

    let app_data_start = std::time::Instant::now();

    let mut action_iter = frame_actions.iter();

    loop {
        if !conn.is_in_early_data() || app_proto_selected {
            poll.poll(&mut events, conn.timeout()).unwrap();
        }

        // If the event loop reported no events, it means that the timeout
        // has expired, so handle it without attempting to read packets. We
        // will then proceed with the send loop.
        if events.is_empty() {
            // println!("timed out");

            conn.on_timeout();
        }

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        for event in &events {
            let socket = match event.token() {
                mio::Token(0) => &socket,

                // mio::Token(1) => migrate_socket.as_ref().unwrap(),
                _ => unreachable!(),
            };

            let local_addr = socket.local_addr().unwrap();
            'read: loop {
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read on this socket.
                        // Process subsequent events.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            // println!("{}: recv() would block", local_addr);
                            break 'read;
                        }

                        return Err(ClientError::Other(format!(
                            "{local_addr}: recv() failed: {e:?}"
                        )));
                    },
                };

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                // Process potentially coalesced packets.
                let _read = match conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        println!("{}: recv failed: {:?}", local_addr, e);
                        continue 'read;
                    },
                };

                // println!("{}: processed {} bytes", local_addr, read);
            }
        }

        // println!("done reading");

        if conn.is_closed() {
            println!(
                "connection closed with error={:?}, {:?} {:?}",
                conn.peer_error(),
                conn.stats(),
                conn.path_stats().collect::<Vec<quiche::PathStats>>()
            );

            if !conn.is_established() {
                println!(
                    "connection timed out after {:?}",
                    app_data_start.elapsed(),
                );

                return Err(ClientError::HandshakeFail);
            }

            break;
        }

        // Create a new application protocol session once the QUIC connection is
        // established.
        if (conn.is_established() || conn.is_in_early_data()) &&
            //(!args.perform_migration || migrated) &&
            !app_proto_selected
        {
            app_proto_selected = true;
        }

        if app_proto_selected {
            send_actions(&mut action_iter, &mut conn);

            parse_streams(&mut conn);
        }

        // Provides as many CIDs as possible.
        while conn.scids_left() > 0 {
            let (scid, reset_token) = generate_cid_and_reset_token();

            if conn.new_scid(&scid, reset_token, false).is_err() {
                break;
            }
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        let sockets = vec![&socket];

        for socket in sockets {
            let local_addr = socket.local_addr().unwrap();

            for peer_addr in conn.paths_iter(local_addr) {
                loop {
                    let (write, send_info) = match conn.send_on_path(
                        &mut out,
                        Some(local_addr),
                        Some(peer_addr),
                    ) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            // println!(
                            // "{} -> {}: done writing",
                            // local_addr,
                            // peer_addr
                            // );
                            break;
                        },

                        Err(e) => {
                            println!(
                                "{} -> {}: send failed: {:?}",
                                local_addr, peer_addr, e
                            );

                            conn.close(false, 0x1, b"fail").ok();
                            break;
                        },
                    };

                    if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            println!(
                                "{} -> {}: send() would block",
                                local_addr, send_info.to
                            );
                            break;
                        }

                        return Err(ClientError::Other(format!(
                            "{} -> {}: send() failed: {:?}",
                            local_addr, send_info.to, e
                        )));
                    }

                    // println!(
                    // "{} -> {}: written {}",
                    // local_addr, send_info.to, write
                    // );
                }
            }
        }

        if conn.is_closed() {
            println!(
                "connection closed, {:?} {:?}",
                conn.stats(),
                conn.path_stats().collect::<Vec<quiche::PathStats>>()
            );

            if !conn.is_established() {
                println!(
                    "connection timed out after {:?}",
                    app_data_start.elapsed(),
                );

                return Err(ClientError::HandshakeFail);
            }

            break;
        }
    }

    Ok(())
}

/// Generate a new pair of Source Connection ID and reset token.
pub fn generate_cid_and_reset_token() -> (quiche::ConnectionId<'static>, u128) {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut scid);
    let scid = scid.to_vec().into();
    let mut reset_token = [0; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut reset_token);
    let reset_token = u128::from_be_bytes(reset_token);
    (scid, reset_token)
}

/// Makes a buffered writer for a qlog.
pub fn make_qlog_writer(
    dir: &std::ffi::OsStr, role: &str, id: &str,
) -> std::io::BufWriter<std::fs::File> {
    let mut path = std::path::PathBuf::from(dir);
    let filename = format!("{role}-{id}.sqlog");
    path.push(filename);

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),

        Err(e) => panic!(
            "Error creating qlog file attempted path was {:?}: {}",
            path, e
        ),
    }
}

fn send_actions<'a, I>(iter: &mut I, conn: &mut quiche::Connection)
where
    I: Iterator<Item = &'a Action>,
{
    // Send actions
    for action in iter {
        match action {
            Action::SendFrame {
                stream_id,
                fin_stream,
                frame,
            } => {
                println!("frame tx id={} frame={:?}", stream_id, frame);

                // TODO: make serialization smarter
                let mut d = [42; 9999];
                let mut b = octets::OctetsMut::with_slice(&mut d);

                if let Some(s) = conn.qlog_streamer() {
                    for (ev, ex) in action.to_qlog() {
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
                println!(
                    "headers frame tx stream={} hdrs={:?}",
                    stream_id, headers
                );

                // TODO: make serialization smarter
                let mut d = [42; 9999];
                let mut b = octets::OctetsMut::with_slice(&mut d);

                if let Some(s) = conn.qlog_streamer() {
                    for (ev, ex) in action.to_qlog() {
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
                println!(
                    "open uni stream_id={} ty={} fin={}",
                    stream_id, stream_type, fin_stream
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
                println!(
                    "stream bytes tx id={} len={} fin={}",
                    stream_id,
                    bytes.len(),
                    fin_stream
                );
                conn.stream_send(*stream_id, bytes, *fin_stream).unwrap();
            },

            Action::ResetStream {
                stream_id,
                transport,
                error_code,
            } => {
                println!(
                    "reset_stream stream_id={} transport={} error_code={}",
                    stream_id, transport, error_code
                );
                if let Err(e) = conn.stream_shutdown(
                    *stream_id,
                    quiche::Shutdown::Write,
                    *error_code,
                ) {
                    println!("can't send reset_stream: {}", e);
                }
            },

            Action::StopSending {
                stream_id,
                transport,
                error_code,
            } => {
                println!(
                    "stop_sending stream id={} transport={} error_code={}",
                    stream_id, transport, error_code
                );

                if let Err(e) = conn.stream_shutdown(
                    *stream_id,
                    quiche::Shutdown::Read,
                    *error_code,
                ) {
                    println!("can't send stop_sending: {}", e);
                }
            },
        }
    }
}

fn parse_streams(conn: &mut quiche::Connection) {
    for stream in conn.readable() {
        // TODO: ignoring control streams
        if stream % 4 != 0 {
            continue;
        }

        let mut d = [42; 16000];

        match conn.stream_recv(stream, &mut d) {
            Ok((len, _fin)) => {
                println!("read {} stream bytes", len);
                let mut tlv = VarintTlv::with_slice(&d[..len]).unwrap();
                loop {
                    // TODO:
                    let frame_ty =
                        tlv.ty().expect("not enough bytes to read frame type");
                    let frame_len =
                        tlv.len().expect("not enough bytes to read frame length");
                    println!("tlv ty={frame_ty} len={frame_len}");
                    let frame_val = tlv
                        .val()
                        .expect("not enough bytes to read frame payload");

                    let frame = quiche::h3::frame::Frame::from_bytes(
                        frame_ty,
                        frame_len,
                        frame_val.buf(),
                    )
                    .unwrap();

                    println!("frame rx={frame:?} off={}", tlv.off());

                    match frame {
                        quiche::h3::frame::Frame::Headers { header_block } => {
                            let mut qpack_decoder =
                                quiche::h3::qpack::Decoder::new();
                            let headers = qpack_decoder
                                .decode(&header_block, u64::MAX)
                                .unwrap();
                            println!("hdrs={:?}", headers);

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

                            if let Some(s) = conn.qlog_streamer() {
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

                        _ =>
                            if let Some(s) = conn.qlog_streamer() {
                                let ev_data =
                                    EventData::H3FrameParsed(H3FrameParsed {
                                        stream_id: 0,
                                        length: None,
                                        frame: frame.to_qlog(),
                                        raw: None,
                                    });

                                s.add_event_data_now(ev_data).ok();
                            },
                    }

                    if tlv.off() == len {
                        println!("read all buffer");
                        break;
                    }

                    tlv.reset();
                }
            },

            Err(e) => println!("stream read error: {e}"),
        }
    }
}
