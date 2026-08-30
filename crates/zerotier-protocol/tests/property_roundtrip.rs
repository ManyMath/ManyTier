use zerotier_crypto::identity::{Address, Identity, PublicKey};
use zerotier_protocol::inet_address::InetAddress;
use zerotier_protocol::verb::Verb;
use zerotier_protocol::verbs::ack::AckPayload;
use zerotier_protocol::verbs::error::{ErrorCode, ErrorPayload};
use zerotier_protocol::verbs::frame::{ExtFramePayload, FramePayload};
use zerotier_protocol::verbs::hello::HelloPayload;
use zerotier_protocol::verbs::multicast::{
    MulticastFramePayload, MulticastGatherPayload, MulticastGroup, MulticastLikePayload,
};
use zerotier_protocol::verbs::network_config::{
    CertificateOfMembership, ComQualifier, NetworkConfigPayload, NetworkConfigRequestPayload,
    NetworkCredentialsPayload,
};
use zerotier_protocol::verbs::nop::NopPayload;
use zerotier_protocol::verbs::ok::{OkPayload, OkSubPayload};
use zerotier_protocol::verbs::path_negotiation::PathNegotiationRequestPayload;
use zerotier_protocol::verbs::push_direct::{DirectPath, PushDirectPathsPayload};
use zerotier_protocol::verbs::qos::{QosMeasurementPayload, QosRecord};
use zerotier_protocol::verbs::remote_trace::RemoteTracePayload;
use zerotier_protocol::verbs::rendezvous::RendezvousPayload;
use zerotier_protocol::verbs::user_message::UserMessagePayload;
use zerotier_protocol::verbs::whois::{WhoisRequest, WhoisResponse};

fn make_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 32) as u8);
    }
    out
}

fn address_from_seed(seed: u64) -> [u8; 5] {
    let mut addr = [0u8; 5];
    addr.copy_from_slice(&make_bytes(seed, 5));
    if addr == [0; 5] || addr == [0xff; 5] {
        addr[4] ^= 0x42;
    }
    addr
}

fn identity_from_seed(seed: u64) -> Identity {
    let address = Address::new(address_from_seed(seed)).unwrap();
    let pk_bytes: [u8; 64] = make_bytes(seed ^ 0xabc, 64).try_into().unwrap();
    Identity {
        address,
        public_key: PublicKey::from_bytes(&pk_bytes).unwrap(),
        secret: None,
    }
}

fn inet_address_from_seed(seed: u64) -> InetAddress {
    match seed % 3 {
        0 => InetAddress::Null,
        1 => {
            let ip: [u8; 4] = make_bytes(seed, 4).try_into().unwrap();
            InetAddress::V4 {
                ip,
                port: (seed as u16).wrapping_mul(17),
            }
        }
        _ => {
            let ip: [u8; 16] = make_bytes(seed, 16).try_into().unwrap();
            InetAddress::V6 {
                ip,
                port: (seed as u16).wrapping_mul(29),
            }
        }
    }
}

fn com_from_seed(seed: u64) -> CertificateOfMembership {
    let qualifiers: Vec<ComQualifier> = (0..(seed as usize % 4))
        .map(|index| ComQualifier {
            id: index as u64,
            value: seed.wrapping_add(index as u64),
            max_delta: seed.rotate_left(index as u32),
        })
        .collect();
    let issued_to = if let Some(q) = qualifiers.iter().find(|q| q.id == 2) {
        let bytes = q.value.to_be_bytes();
        [bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
    } else {
        [0u8; 5]
    };
    let signature: [u8; 96] = make_bytes(seed ^ 0x5555, 96).try_into().unwrap();
    CertificateOfMembership {
        qualifiers,
        issued_to,
        signer_address: address_from_seed(seed ^ 0x7777),
        signature,
    }
}

#[test]
fn protocol_roundtrips_cover_all_payload_codecs() {
    for seed in 0..32u64 {
        let payload = make_bytes(seed ^ 0x99, (seed as usize * 17) % 96);
        let identity = identity_from_seed(seed);
        let identities = [identity_from_seed(seed), identity_from_seed(seed + 1)];
        let inet_address = inet_address_from_seed(seed);

        let error = ErrorPayload {
            in_re_verb: Verb::Whois,
            in_re_packet_id: seed,
            error_code: match seed % 5 {
                0 => ErrorCode::None,
                1 => ErrorCode::InvalidRequest,
                2 => ErrorCode::BadProtocolVersion,
                3 => ErrorCode::ObjectNotFound,
                _ => ErrorCode::NetworkAuthenticationRequired,
            },
            payload: payload.clone(),
        };
        let mut error_buf = vec![0u8; 256];
        let error_len = error.serialize(&mut error_buf);
        let error_parsed = ErrorPayload::deserialize(&error_buf[..error_len]).unwrap();
        assert_eq!(error_parsed.in_re_packet_id, error.in_re_packet_id);
        assert_eq!(error_parsed.error_code, error.error_code);
        assert_eq!(error_parsed.payload, error.payload);

        let hello = HelloPayload {
            protocol_version: 13,
            major_version: 1,
            minor_version: 14,
            revision: 2,
            timestamp: seed,
            identity: identity_from_seed(seed),
            dest_address: inet_address.clone(),
            planet_world_id: seed ^ 0x1234,
            planet_world_timestamp: seed ^ 0x4321,
            moon_records: vec![(seed, seed + 1), (seed + 2, seed + 3)],
        };
        let mut hello_buf = vec![0u8; 1024];
        let hello_len = hello.serialize(&mut hello_buf).unwrap();
        let (hello_parsed, consumed) = HelloPayload::deserialize(&hello_buf[..hello_len]).unwrap();
        assert_eq!(consumed, hello_len);
        assert_eq!(hello_parsed.identity.address, hello.identity.address);
        assert_eq!(hello_parsed.identity.public_key, hello.identity.public_key);
        assert_eq!(hello_parsed.dest_address, hello.dest_address);
        assert_eq!(hello_parsed.moon_records, hello.moon_records);

        let frame = FramePayload {
            network_id: seed,
            ethertype: seed as u16,
            payload: &payload,
        };
        let mut frame_buf = vec![0u8; 64 + payload.len()];
        let frame_len = frame.serialize(&mut frame_buf);
        let frame_parsed = FramePayload::parse(&frame_buf[..frame_len]).unwrap();
        assert_eq!(frame_parsed.network_id, frame.network_id);
        assert_eq!(frame_parsed.ethertype, frame.ethertype);
        assert_eq!(frame_parsed.payload, payload.as_slice());

        let ext = ExtFramePayload {
            network_id: seed,
            flags: (seed & 0xff) as u8,
            dest_mac: make_bytes(seed, 6).try_into().unwrap(),
            src_mac: make_bytes(seed ^ 1, 6).try_into().unwrap(),
            ethertype: (seed >> 8) as u16,
            payload: &payload,
        };
        let mut ext_buf = vec![0u8; 64 + payload.len()];
        let ext_len = ext.serialize(&mut ext_buf);
        let ext_parsed = ExtFramePayload::parse(&ext_buf[..ext_len]).unwrap();
        assert_eq!(ext_parsed.network_id, ext.network_id);
        assert_eq!(ext_parsed.dest_mac, ext.dest_mac);
        assert_eq!(ext_parsed.src_mac, ext.src_mac);
        assert_eq!(ext_parsed.payload, payload.as_slice());

        let groups = vec![
            MulticastGroup {
                network_id: seed,
                mac: make_bytes(seed, 6).try_into().unwrap(),
                adi: seed as u32,
            },
            MulticastGroup {
                network_id: seed + 1,
                mac: make_bytes(seed + 1, 6).try_into().unwrap(),
                adi: (seed + 1) as u32,
            },
        ];
        let like = MulticastLikePayload {
            groups: groups.clone(),
        };
        let mut like_buf = vec![0u8; 64];
        let like_len = like.serialize(&mut like_buf);
        let like_parsed = MulticastLikePayload::deserialize(&like_buf[..like_len]).unwrap();
        assert_eq!(like_parsed.groups, groups);

        let gather = MulticastGatherPayload {
            network_id: seed,
            flags: (seed & 0xff) as u8,
            mac: make_bytes(seed ^ 2, 6).try_into().unwrap(),
            adi: seed as u32,
            gather_limit: seed as u32 + 1,
            com: if payload.is_empty() {
                None
            } else {
                Some(payload.clone())
            },
        };
        let mut gather_buf = vec![0u8; 512];
        let gather_len = gather.serialize(&mut gather_buf);
        let gather_parsed = MulticastGatherPayload::deserialize(&gather_buf[..gather_len]).unwrap();
        assert_eq!(gather_parsed, gather);

        let multicast_frame = MulticastFramePayload {
            network_id: seed,
            flags: 0x06,
            gather_limit: Some(seed as u32),
            source_mac: Some(make_bytes(seed ^ 3, 6).try_into().unwrap()),
            dest_mac: make_bytes(seed ^ 4, 6).try_into().unwrap(),
            adi: seed as u32,
            ethertype: seed as u16,
            payload: &payload,
        };
        let mut multicast_frame_buf = vec![0u8; 256];
        let multicast_frame_len = multicast_frame.serialize(&mut multicast_frame_buf);
        let multicast_frame_parsed =
            MulticastFramePayload::parse(&multicast_frame_buf[..multicast_frame_len]).unwrap();
        assert_eq!(
            multicast_frame_parsed.network_id,
            multicast_frame.network_id
        );
        assert_eq!(
            multicast_frame_parsed.gather_limit,
            multicast_frame.gather_limit
        );
        assert_eq!(
            multicast_frame_parsed.source_mac,
            multicast_frame.source_mac
        );
        assert_eq!(multicast_frame_parsed.payload, payload.as_slice());

        let request = NetworkConfigRequestPayload {
            network_id: seed,
            dict_data: payload.clone(),
        };
        let mut request_buf = vec![0u8; 256];
        let request_len = request.serialize(&mut request_buf);
        let request_parsed =
            NetworkConfigRequestPayload::deserialize(&request_buf[..request_len]).unwrap();
        assert_eq!(request_parsed, request);

        let config = NetworkConfigPayload {
            network_id: seed,
            dict_data: payload.clone(),
            flags: Some(0),
            config_update_id: Some(seed ^ 0x0102_0304_0506_0708),
            total_length: Some(payload.len() as u32 + 4096),
            chunk_index: Some(seed as u32),
            signature_type: Some(1),
            signature: Some(make_bytes(seed ^ 5, 96)),
        };
        let mut config_buf = vec![0u8; 512];
        let config_len = config.serialize(&mut config_buf);
        let config_parsed = NetworkConfigPayload::deserialize(&config_buf[..config_len]).unwrap();
        assert_eq!(config_parsed, config);

        let credentials = NetworkCredentialsPayload {
            capabilities_raw: vec![1, 2, 3, seed as u8],
            tags_raw: vec![4, 5, 6, seed.rotate_left(3) as u8],
            revocations_raw: vec![7, seed as u8],
            coo_raw: vec![8, 9, seed.rotate_right(2) as u8],
            com: Some(com_from_seed(seed)),
        };
        let mut credentials_buf = vec![0u8; 1024];
        let credentials_len = credentials.serialize(&mut credentials_buf);
        let credentials_parsed =
            NetworkCredentialsPayload::deserialize(&credentials_buf[..credentials_len]).unwrap();
        assert_eq!(
            credentials_parsed.capabilities_raw,
            credentials.capabilities_raw
        );
        assert_eq!(credentials_parsed.tags_raw, credentials.tags_raw);
        assert_eq!(
            credentials_parsed.revocations_raw,
            credentials.revocations_raw
        );
        assert_eq!(credentials_parsed.coo_raw, credentials.coo_raw);
        assert_eq!(credentials_parsed.com, credentials.com);

        let ok_generic = OkPayload {
            in_re_verb: Verb::NetworkConfig,
            in_re_packet_id: seed,
            sub_payload: OkSubPayload::Generic {
                data: payload.clone(),
            },
        };
        let mut ok_generic_buf = vec![0u8; 256];
        let ok_generic_len = ok_generic.serialize(&mut ok_generic_buf).unwrap();
        let ok_generic_parsed = OkPayload::deserialize(&ok_generic_buf[..ok_generic_len]).unwrap();
        match ok_generic_parsed.sub_payload {
            OkSubPayload::Generic { data } => assert_eq!(data, payload),
            _ => panic!("expected OK generic payload"),
        }

        let ok_whois = OkPayload {
            in_re_verb: Verb::Whois,
            in_re_packet_id: seed + 7,
            sub_payload: OkSubPayload::Whois {
                identities: vec![identity_from_seed(seed), identity_from_seed(seed + 1)],
            },
        };
        let mut ok_whois_buf = vec![0u8; 512];
        let ok_whois_len = ok_whois.serialize(&mut ok_whois_buf).unwrap();
        let ok_whois_parsed = OkPayload::deserialize(&ok_whois_buf[..ok_whois_len]).unwrap();
        match ok_whois_parsed.sub_payload {
            OkSubPayload::Whois { identities: parsed } => {
                assert_eq!(parsed.len(), identities.len());
                for (lhs, rhs) in parsed.iter().zip(identities.iter()) {
                    assert_eq!(lhs.address, rhs.address);
                    assert_eq!(lhs.public_key, rhs.public_key);
                }
            }
            _ => panic!("expected OK WHOIS payload"),
        }

        let push_direct = PushDirectPathsPayload {
            paths: vec![
                DirectPath {
                    flags: seed as u8,
                    address: inet_address.clone(),
                },
                DirectPath {
                    flags: (seed as u8).wrapping_add(1),
                    address: inet_address_from_seed(seed + 1),
                },
            ],
        };
        let mut push_direct_buf = vec![0u8; 512];
        let push_direct_len = push_direct.serialize(&mut push_direct_buf);
        let push_direct_parsed =
            PushDirectPathsPayload::deserialize(&push_direct_buf[..push_direct_len]).unwrap();
        assert_eq!(push_direct_parsed, push_direct);

        let rendezvous = RendezvousPayload {
            flags: (seed & 0xff) as u8,
            peer_address: address_from_seed(seed + 5),
            address: inet_address.clone(),
        };
        let mut rendezvous_buf = vec![0u8; 64];
        let rendezvous_len = rendezvous.serialize(&mut rendezvous_buf);
        let rendezvous_parsed =
            RendezvousPayload::deserialize(&rendezvous_buf[..rendezvous_len]).unwrap();
        assert_eq!(rendezvous_parsed, rendezvous);

        let whois_request = WhoisRequest {
            addresses: vec![address_from_seed(seed), address_from_seed(seed + 1)],
        };
        let mut whois_request_buf = vec![0u8; 64];
        let whois_request_len = whois_request.serialize(&mut whois_request_buf);
        let whois_request_parsed =
            WhoisRequest::deserialize(&whois_request_buf[..whois_request_len]).unwrap();
        assert_eq!(whois_request_parsed.addresses, whois_request.addresses);

        let whois_response = WhoisResponse {
            identities: vec![identity, identity_from_seed(seed + 9)],
        };
        let mut whois_response_buf = vec![0u8; 512];
        let whois_response_len = whois_response.serialize(&mut whois_response_buf);
        let whois_response_parsed =
            WhoisResponse::deserialize(&whois_response_buf[..whois_response_len]).unwrap();
        assert_eq!(
            whois_response_parsed.identities.len(),
            whois_response.identities.len()
        );

        // NOP: empty payload roundtrip
        let nop = NopPayload;
        let mut nop_buf = [0u8; 64];
        let nop_len = nop.serialize(&mut nop_buf);
        assert_eq!(nop_len, 0);
        let nop_parsed = NopPayload::deserialize(&nop_buf[..nop_len]).unwrap();
        assert_eq!(nop_parsed, nop);

        // ACK: 4-byte u32 roundtrip
        let ack = AckPayload {
            bytes_acked: seed as u32,
        };
        let mut ack_buf = [0u8; 64];
        let ack_len = ack.serialize(&mut ack_buf);
        assert_eq!(ack_len, 4);
        let ack_parsed = AckPayload::deserialize(&ack_buf[..ack_len]).unwrap();
        assert_eq!(ack_parsed, ack);

        // QosMeasurement: repeated 10-byte record roundtrip
        let qos_records: Vec<QosRecord> = (0..(seed as usize % 5))
            .map(|i| QosRecord {
                packet_id: seed.wrapping_add(i as u64),
                sojourn_time: (seed as u16).wrapping_add(i as u16),
            })
            .collect();
        let qos = QosMeasurementPayload {
            records: qos_records,
        };
        let mut qos_buf = [0u8; 256];
        let qos_len = qos.serialize(&mut qos_buf);
        assert_eq!(qos_len, qos.records.len() * 10);
        let qos_parsed = QosMeasurementPayload::deserialize(&qos_buf[..qos_len]).unwrap();
        assert_eq!(qos_parsed, qos);

        // UserMessage: 8-byte type_id + variable data roundtrip
        let user_msg = UserMessagePayload {
            type_id: seed ^ 0xCAFE,
            data: make_bytes(seed ^ 0xBEEF, (seed as usize % 32) + 1),
        };
        let mut user_msg_buf = [0u8; 256];
        let user_msg_len = user_msg.serialize(&mut user_msg_buf);
        assert_eq!(user_msg_len, 8 + user_msg.data.len());
        let user_msg_parsed =
            UserMessagePayload::deserialize(&user_msg_buf[..user_msg_len]).unwrap();
        assert_eq!(user_msg_parsed, user_msg);

        // RemoteTrace: variable-length opaque bytes roundtrip
        let remote_trace = RemoteTracePayload {
            data: make_bytes(seed ^ 0xDEAD, (seed as usize % 48) + 1),
        };
        let mut remote_trace_buf = [0u8; 256];
        let remote_trace_len = remote_trace.serialize(&mut remote_trace_buf);
        assert_eq!(remote_trace_len, remote_trace.data.len());
        let remote_trace_parsed =
            RemoteTracePayload::deserialize(&remote_trace_buf[..remote_trace_len]).unwrap();
        assert_eq!(remote_trace_parsed, remote_trace);

        // PathNegotiationRequest: 2-byte i16 roundtrip
        let path_neg = PathNegotiationRequestPayload {
            utility: (seed as i16).wrapping_mul(7),
        };
        let mut path_neg_buf = [0u8; 64];
        let path_neg_len = path_neg.serialize(&mut path_neg_buf);
        assert_eq!(path_neg_len, 2);
        let path_neg_parsed =
            PathNegotiationRequestPayload::deserialize(&path_neg_buf[..path_neg_len]).unwrap();
        assert_eq!(path_neg_parsed, path_neg);
    }
}
