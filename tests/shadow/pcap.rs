use std::fs::File;
use std::io;
use std::path::Path;

use etherparse::{SlicedPacket, TransportSlice};
use pcap_file::pcap::PcapReader;
use pcap_file::DataLink;
use zerotier_protocol::header::PacketHeader;
use zerotier_protocol::verb::Verb;
use zerotier_protocol::verbs::hello::HelloPayload;
use zerotier_protocol::verbs::network_config::{
    NetworkConfigPayload, NetworkConfigRequestPayload, NetworkCredentialsPayload,
};
use zerotier_protocol::verbs::ok::{OkPayload, OkSubPayload};
use zerotier_protocol::verbs::whois::WhoisRequest;
use zerotier_protocol::{is_fragment, FragmentHeader};

const ZT_PORT: u16 = 9993;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedPayload {
    Hello {
        protocol_version: u8,
        major_version: u8,
        minor_version: u8,
        revision: u16,
        identity: String,
        destination: String,
    },
    OkHello {
        in_re_verb: String,
        protocol_version: u8,
        major_version: u8,
        minor_version: u8,
        revision: u16,
    },
    OkWhois {
        in_re_verb: String,
        identities: Vec<String>,
    },
    OkGeneric {
        in_re_verb: String,
        bytes: usize,
    },
    Whois {
        addresses: Vec<String>,
    },
    NetworkConfigRequest {
        network_id: u64,
        dict_data: Vec<u8>,
    },
    NetworkConfig {
        network_id: u64,
        dict_data: Vec<u8>,
        chunk_index: Option<u32>,
        total_length: Option<u32>,
    },
    NetworkCredentials {
        signer: Option<String>,
        qualifier_ids: Vec<u64>,
        qualifier_values: Vec<u64>,
    },
    Fragment {
        packet_id: u64,
        destination: String,
        fragment_number: u8,
        total_fragments: u8,
        hops: u8,
        payload_len: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedPacket {
    pub host: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub direction: PacketDirection,
    pub sequence: usize,
    pub packet_id: u64,
    pub source: [u8; 5],
    pub destination: [u8; 5],
    pub cipher_suite: u8,
    pub verb: Option<Verb>,
    pub verb_name: String,
    pub raw_payload: Vec<u8>,
    pub decoded_payload: Option<DecodedPayload>,
}

pub fn parse_host_pcaps(
    host: &str,
    pcap_paths: &[impl AsRef<Path>],
) -> io::Result<Vec<CapturedPacket>> {
    let mut packets = Vec::new();
    for pcap_path in pcap_paths {
        let file = File::open(pcap_path.as_ref())?;
        let mut reader = PcapReader::new(file)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        let datalink = reader.header().datalink;
        while let Some(packet) = reader.next_packet() {
            let packet = packet
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            let sliced = match datalink {
                DataLink::ETHERNET => SlicedPacket::from_ethernet(packet.data.as_ref()),
                DataLink::RAW => SlicedPacket::from_ip(packet.data.as_ref()),
                DataLink::LINUX_SLL => SlicedPacket::from_linux_sll(packet.data.as_ref()),
                _ => continue,
            };
            let sliced = match sliced {
                Ok(sliced) => sliced,
                Err(_) => continue,
            };
            let Some(TransportSlice::Udp(udp)) = sliced.transport else {
                continue;
            };

            let source_port = udp.source_port();
            let destination_port = udp.destination_port();
            if source_port != ZT_PORT && destination_port != ZT_PORT {
                continue;
            }

            let udp_payload = udp.payload();
            let raw_payload = udp_payload.to_vec();
            let direction = if destination_port == ZT_PORT {
                PacketDirection::Inbound
            } else {
                PacketDirection::Outbound
            };

            if is_fragment(udp_payload) {
                let Some(header) = FragmentHeader::from_bytes(udp_payload) else {
                    continue;
                };
                let packet_id = header.packet_id_u64();
                let destination = header.dest;

                packets.push(CapturedPacket {
                    host: host.to_string(),
                    source_port,
                    destination_port,
                    direction,
                    sequence: packets.len(),
                    packet_id,
                    source: [0; 5],
                    destination,
                    cipher_suite: 0,
                    verb: None,
                    verb_name: "Fragment".to_string(),
                    raw_payload: raw_payload.clone(),
                    decoded_payload: Some(DecodedPayload::Fragment {
                        packet_id,
                        destination: format_address(&destination),
                        fragment_number: header.fragment_number(),
                        total_fragments: header.total_fragments(),
                        hops: header.hops,
                        payload_len: raw_payload.len().saturating_sub(16),
                    }),
                });
                continue;
            }

            let Some(header) = PacketHeader::from_bytes(udp_payload) else {
                continue;
            };

            let verb = Verb::from_byte(header.verb);
            let verb_name = verb
                .map(verb_name)
                .map(str::to_string)
                .unwrap_or_else(|| format!("Unknown({:#04x})", header.verb_id()));
            let payload_bytes = raw_payload.get(28..).unwrap_or(&[]).to_vec();

            packets.push(CapturedPacket {
                host: host.to_string(),
                source_port,
                destination_port,
                direction,
                sequence: packets.len(),
                packet_id: header.packet_id(),
                source: header.source_address(),
                destination: header.dest_address(),
                cipher_suite: header.cipher_suite(),
                verb,
                verb_name,
                raw_payload,
                decoded_payload: decode_payload(verb, &payload_bytes),
            });
        }
    }

    Ok(packets)
}

fn decode_payload(verb: Option<Verb>, payload: &[u8]) -> Option<DecodedPayload> {
    match verb? {
        Verb::Hello => {
            HelloPayload::deserialize(payload)
                .ok()
                .map(|(hello, _)| DecodedPayload::Hello {
                    protocol_version: hello.protocol_version,
                    major_version: hello.major_version,
                    minor_version: hello.minor_version,
                    revision: hello.revision,
                    identity: hello.identity.address.to_hex(),
                    destination: format!("{:?}", hello.dest_address),
                })
        }
        Verb::Ok => OkPayload::deserialize(payload)
            .ok()
            .map(|ok| match ok.sub_payload {
                OkSubPayload::Hello {
                    protocol_version,
                    major_version,
                    minor_version,
                    revision,
                    ..
                } => DecodedPayload::OkHello {
                    in_re_verb: verb_name(ok.in_re_verb).to_string(),
                    protocol_version,
                    major_version,
                    minor_version,
                    revision,
                },
                OkSubPayload::Whois { identities } => DecodedPayload::OkWhois {
                    in_re_verb: verb_name(ok.in_re_verb).to_string(),
                    identities: identities
                        .iter()
                        .map(|identity| identity.address.to_hex())
                        .collect(),
                },
                OkSubPayload::Generic { data } => DecodedPayload::OkGeneric {
                    in_re_verb: verb_name(ok.in_re_verb).to_string(),
                    bytes: data.len(),
                },
            }),
        Verb::Whois => WhoisRequest::deserialize(payload)
            .ok()
            .map(|whois| DecodedPayload::Whois {
                addresses: whois.addresses.iter().map(format_address).collect(),
            }),
        Verb::NetworkConfigRequest => {
            NetworkConfigRequestPayload::deserialize(payload)
                .ok()
                .map(|request| DecodedPayload::NetworkConfigRequest {
                    network_id: request.network_id,
                    dict_data: request.dict_data,
                })
        }
        Verb::NetworkConfig => NetworkConfigPayload::deserialize(payload)
            .ok()
            .map(|config| DecodedPayload::NetworkConfig {
                network_id: config.network_id,
                dict_data: config.dict_data,
                chunk_index: config.chunk_index,
                total_length: config.total_length,
            }),
        Verb::NetworkCredentials => {
            NetworkCredentialsPayload::deserialize(payload)
                .ok()
                .map(|credentials| {
                    let signer = credentials
                        .com()
                        .map(|com| format_address(&com.signer_address));
                    let qualifier_ids = credentials
                        .com()
                        .map(|com| {
                            com.qualifiers
                                .iter()
                                .map(|qualifier| qualifier.id)
                                .collect()
                        })
                        .unwrap_or_default();
                    let qualifier_values = credentials
                        .com()
                        .map(|com| {
                            com.qualifiers
                                .iter()
                                .filter(|qualifier| qualifier.id != 0)
                                .map(|qualifier| qualifier.value)
                                .collect()
                        })
                        .unwrap_or_default();
                    DecodedPayload::NetworkCredentials {
                        signer,
                        qualifier_ids,
                        qualifier_values,
                    }
                })
        }
        _ => None,
    }
}

pub fn verb_name(verb: Verb) -> &'static str {
    match verb {
        Verb::Nop => "Nop",
        Verb::Hello => "Hello",
        Verb::Error => "Error",
        Verb::Ok => "Ok",
        Verb::Whois => "Whois",
        Verb::Rendezvous => "Rendezvous",
        Verb::Frame => "Frame",
        Verb::ExtFrame => "ExtFrame",
        Verb::Echo => "Echo",
        Verb::MulticastLike => "MulticastLike",
        Verb::NetworkCredentials => "NetworkCredentials",
        Verb::NetworkConfigRequest => "NetworkConfigRequest",
        Verb::NetworkConfig => "NetworkConfig",
        Verb::MulticastGather => "MulticastGather",
        Verb::MulticastFrame => "MulticastFrame",
        Verb::PushDirectPaths => "PushDirectPaths",
        Verb::Ack => "Ack",
        Verb::QosMeasurement => "QosMeasurement",
        Verb::UserMessage => "UserMessage",
        Verb::RemoteTrace => "RemoteTrace",
        Verb::PathNegotiationRequest => "PathNegotiationRequest",
    }
}

pub fn format_address(address: &[u8; 5]) -> String {
    address.iter().map(|byte| format!("{byte:02x}")).collect()
}
