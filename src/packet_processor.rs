use super::channel_buffers::{Channel, ChannelBuffers, DeserializationError};
use chrono::{DateTime, Utc};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    tcp::TcpPacket,
    Packet,
};
use rsnano_messages::Message;
use serde_derive::Serialize;
use std::net::{SocketAddr, SocketAddrV4};

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
    pub packet_count: usize,
    pub messages_parsed_count: usize,
    pub header_deserialization_failed_count: usize,
    pub message_deserialization_failed_count: usize,
    pub tcp_count: usize,
}

pub(crate) struct PacketProcessor {
    pub statistics: PacketStatistics,
    channels: ChannelBuffers,
}

impl PacketProcessor {
    pub(crate) fn new() -> Self {
        Self {
            statistics: PacketStatistics::default(),
            channels: ChannelBuffers::new(),
        }
    }

    pub(crate) fn add_packet(&mut self, data: &[u8]) -> Option<Channel> {
        self.statistics.packet_count += 1;
        if let Some(ethernet) = EthernetPacket::new(data) {
            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            let channel = into_channel(&ipv4, &tcp);

                            self.statistics.tcp_count += 1;
                            self.channels.add_bytes(&channel, tcp.payload());
                            return Some(channel);
                        }
                    }
                }
                _ => {}
            }
        }

        None
    }

    pub(crate) fn parse_message(
        &mut self,
        channel: &Channel,
        timestamp: DateTime<Utc>,
    ) -> Option<Entry> {
        match self.channels.pop_message(channel) {
            Ok(None) => None,
            Ok(Some(message)) => {
                self.statistics.messages_parsed_count += 1;
                Some(Entry {
                    packet: self.statistics.packet_count,
                    date: timestamp,
                    source: channel.source,
                    destination: channel.destination,
                    message,
                })
            }
            Err(DeserializationError::InvalidHeader) => {
                self.statistics.header_deserialization_failed_count += 1;
                None
            }
            Err(DeserializationError::InvalidMessage) => {
                self.statistics.message_deserialization_failed_count += 1;
                None
            }
        }
    }

    pub(crate) fn should_indicate_progress(&self) -> bool {
        self.statistics.packet_count % 10000 == 0
    }
}

fn into_channel(ipv4: &Ipv4Packet, tcp: &TcpPacket) -> Channel {
    Channel {
        source: SocketAddr::V4(SocketAddrV4::new(ipv4.get_source(), tcp.get_source())),
        destination: SocketAddr::V4(SocketAddrV4::new(
            ipv4.get_destination(),
            tcp.get_destination(),
        )),
    }
}
