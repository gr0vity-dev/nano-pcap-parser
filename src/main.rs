mod channel_buffers;

use channel_buffers::{Channel, ChannelBuffers, DeserializationError};
use chrono::{DateTime, TimeZone, Utc};
use pcap::Capture;
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    tcp::TcpPacket,
    Packet,
};
use rsnano_messages::Message;
use serde_derive::Serialize;
use std::{
    env,
    fs::File,
    io::{BufWriter, Write},
    net::{SocketAddr, SocketAddrV4},
};

fn main() {
    let pcap_file = get_pcap_file_from_args();
    let mut capture = Capture::from_file(pcap_file).expect("Failed to open pcap file");
    let out_file = File::create("output.json").expect("could not create output.json");
    let mut writer = BufWriter::new(out_file);
    let mut packet_processor = PacketProcessor::new();

    while let Ok(packet) = capture.next() {
        if packet_processor.statistics.packet_count % 10000 == 0 {
            print!(".");
            let _ = std::io::stdout().flush();
        }
        packet_processor.statistics.packet_count += 1;
        if let Some(ethernet) = EthernetPacket::new(packet.data) {
            match ethernet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            let channel = into_channel(&ipv4, &tcp);

                            packet_processor.add_tcp_packet(&channel, tcp.payload());

                            while let Some(entry) =
                                packet_processor.process_packet(&channel, &packet)
                            {
                                serde_json::to_writer(&mut writer, &entry)
                                    .expect("could not serialize");
                                write!(writer, "\n").unwrap();
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    packet_processor.statistics.print_summary();
}

fn get_pcap_file_from_args() -> String {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <pcap file>", args[0]);
        std::process::exit(1);
    }
    args[1].clone()
}

pub(crate) struct PacketProcessor {
    statistics: PacketStatistics,
    channels: ChannelBuffers,
}

impl PacketProcessor {
    pub(crate) fn new() -> Self {
        Self {
            statistics: PacketStatistics::new(),
            channels: ChannelBuffers::new(),
        }
    }

    pub(crate) fn add_tcp_packet(&mut self, channel: &Channel, payload: &[u8]) {
        self.statistics.tcp_count += 1;
        self.channels.add_bytes(&channel, payload);
    }

    fn process_packet(&mut self, channel: &Channel, packet: &pcap::Packet) -> Option<Entry> {
        match self.channels.pop_message(channel) {
            Ok(None) => None,
            Ok(Some(message)) => {
                self.statistics.messages_parsed_count += 1;
                Some(Entry {
                    packet: self.statistics.packet_count,
                    date: Utc
                        .timestamp_opt(
                            packet.header.ts.tv_sec,
                            packet.header.ts.tv_usec as u32 * 1000,
                        )
                        .unwrap(),
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
}

#[derive(Serialize)]
pub struct Entry {
    packet: usize,
    date: DateTime<Utc>,
    source: SocketAddr,
    destination: SocketAddr,
    message: Message,
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

struct PacketStatistics {
    packet_count: usize,
    messages_parsed_count: usize,
    header_deserialization_failed_count: usize,
    message_deserialization_failed_count: usize,
    tcp_count: usize,
}

impl PacketStatistics {
    fn new() -> PacketStatistics {
        PacketStatistics {
            packet_count: 0,
            messages_parsed_count: 0,
            header_deserialization_failed_count: 0,
            message_deserialization_failed_count: 0,
            tcp_count: 0,
        }
    }

    fn print_summary(&self) {
        println!();
        println!("packet_count {}", self.packet_count);
        println!("tcp_count {}", self.tcp_count);
        println!("messages_parsed_count {}", self.messages_parsed_count);
        println!(
            "header_deserialization_failed_count {}",
            self.header_deserialization_failed_count
        );
        println!(
            "message_deserialization_failed_count {}",
            self.message_deserialization_failed_count
        );
        println!("Processing complete. Data written to output.csv");
    }
}
