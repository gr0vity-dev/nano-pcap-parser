use super::channel_buffers::{Channel, ChannelBuffers, DeserializationError};
use chrono::{DateTime, TimeZone, Utc};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    Packet,
};
use rsnano_messages::Message;
use serde_derive::Serialize;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

#[derive(Serialize)]
pub struct Entry {
    packet: usize,
    date: DateTime<Utc>,
    source: SocketAddr,
    destination: SocketAddr,
    message: Message,
}

#[derive(Default)]
pub(crate) struct PacketStatistics {
    pub total_packets: usize,
    pub total_tcp_packets: usize,
    pub nano_tcp_packets: usize,
    pub unknown_tcp_packets: usize,
    pub messages_parsed: usize,
    pub header_deserialization_failed: usize,
    pub message_deserialization_failed: usize,
}

pub(crate) struct PacketProcessor {
    pub statistics: PacketStatistics,
    channels: ChannelBuffers,
    last_packet: DateTime<Utc>,
    last_channel: Option<Channel>,
}

impl PacketProcessor {
    pub(crate) fn new() -> Self {
        Self {
            statistics: PacketStatistics::default(),
            channels: ChannelBuffers::new(),
            last_packet: DateTime::default(),
            last_channel: None,
        }
    }

    pub(crate) fn add_packet(&mut self, packet: &pcap::Packet) -> bool {
        self.statistics.total_packets += 1;
        if let Some(ethernet) = EthernetPacket::new(packet.data) {
            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            let channel = into_channel_v4(&ipv4, &tcp);
                            self.add_tcp_packet(channel, packet, tcp.payload());
                            return true;
                        }
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                        if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                            let channel = into_channel_v6(&ipv6, &tcp);
                            self.add_tcp_packet(channel, packet, tcp.payload());
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }

        false
    }

    fn add_tcp_packet(&mut self, channel: Channel, packet: &pcap::Packet, data: &[u8]) {
        self.statistics.total_tcp_packets += 1;
        self.last_packet = get_timestamp(&packet);
        if self.channels.add_bytes(&channel, data) {
            self.statistics.nano_tcp_packets += 1;
        } else {
            self.statistics.unknown_tcp_packets += 1;
        }
        self.last_channel = Some(channel);
    }

    pub(crate) fn parse_message(&mut self) -> Option<Entry> {
        let Some(channel) = self.last_channel.as_ref() else {
            return None;
        };

        match self.channels.pop_message(channel) {
            Ok(None) => None,
            Ok(Some(message)) => {
                self.statistics.messages_parsed += 1;
                Some(Entry {
                    packet: self.statistics.total_packets,
                    date: self.last_packet,
                    source: channel.source,
                    destination: channel.destination,
                    message,
                })
            }
            Err(DeserializationError::InvalidHeader) => {
                self.statistics.header_deserialization_failed += 1;
                None
            }
            Err(DeserializationError::InvalidMessage) => {
                self.statistics.message_deserialization_failed += 1;
                None
            }
        }
    }
}

fn into_channel_v4(ipv4: &Ipv4Packet, tcp: &TcpPacket) -> Channel {
    Channel {
        source: SocketAddr::V4(SocketAddrV4::new(ipv4.get_source(), tcp.get_source())),
        destination: SocketAddr::V4(SocketAddrV4::new(
            ipv4.get_destination(),
            tcp.get_destination(),
        )),
    }
}

fn into_channel_v6(ipv6: &Ipv6Packet, tcp: &TcpPacket) -> Channel {
    Channel {
        source: SocketAddr::V6(SocketAddrV6::new(ipv6.get_source(), tcp.get_source(), 0, 0)),
        destination: SocketAddr::V6(SocketAddrV6::new(
            ipv6.get_destination(),
            tcp.get_destination(),
            0,
            0,
        )),
    }
}

fn get_timestamp(packet: &pcap::Packet) -> DateTime<Utc> {
    Utc.timestamp_opt(
        packet.header.ts.tv_sec,
        packet.header.ts.tv_usec as u32 * 1000,
    )
    .unwrap()
}
