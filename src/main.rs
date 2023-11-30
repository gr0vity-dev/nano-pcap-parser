extern crate chrono;
extern crate pnet;

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
    let mut capture = open_pcap_file(&pcap_file);
    let out_file = File::create("output.json").expect("could not create output.json");
    let mut writer = BufWriter::new(out_file);
    let mut statistics = PacketStatistics::new();
    let mut channels = ChannelBuffers::new();

    while let Ok(packet) = capture.next() {
        process_packet(&packet, &mut channels, &mut writer, &mut statistics);
    }

    statistics.print_summary();
}

fn get_pcap_file_from_args() -> String {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <pcap file>", args[0]);
        std::process::exit(1);
    }
    args[1].clone()
}

fn open_pcap_file(filename: &str) -> Capture<pcap::Offline> {
    Capture::from_file(filename).expect("Failed to open pcap file")
}

#[derive(Serialize)]
pub struct Entry {
    packet: usize,
    date: DateTime<Utc>,
    source: SocketAddr,
    destination: SocketAddr,
    message: Message,
}

fn process_packet(
    packet: &pcap::Packet,
    channels: &mut ChannelBuffers,
    writer: &mut BufWriter<File>,
    statistics: &mut PacketStatistics,
) {
    if statistics.packet_count % 10000 == 0 {
        print!(".");
        let _ = std::io::stdout().flush();
    }
    statistics.packet_count += 1;
    if let Some(ethernet) = EthernetPacket::new(packet.data) {
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                process_ipv4_packet(&ethernet, packet, channels, writer, statistics)
            }
            _ => {}
        }
    }
}

fn process_ipv4_packet(
    ethernet: &EthernetPacket,
    packet: &pcap::Packet,
    channels: &mut ChannelBuffers,
    writer: &mut BufWriter<File>,
    statistics: &mut PacketStatistics,
) {
    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
            statistics.tcp_count += 1;
            process_tcp_packet(&ipv4, &tcp, packet, channels, writer, statistics);
        }
    }
}

fn process_tcp_packet(
    ipv4: &Ipv4Packet,
    tcp: &TcpPacket,
    packet: &pcap::Packet,
    channels: &mut ChannelBuffers,
    writer: &mut BufWriter<File>,
    statistics: &mut PacketStatistics,
) {
    let raw_payload = tcp.payload();
    let channel = Channel {
        source: SocketAddr::V4(SocketAddrV4::new(ipv4.get_source(), tcp.get_source())),
        destination: SocketAddr::V4(SocketAddrV4::new(
            ipv4.get_destination(),
            tcp.get_destination(),
        )),
    };

    channels.add_bytes(&channel, raw_payload);

    loop {
        match channels.pop_message(&channel) {
            Ok(None) => {
                break;
            }
            Ok(Some(message)) => {
                statistics.messages_parsed_count += 1;
                let entry = Entry {
                    packet: statistics.packet_count,
                    date: Utc
                        .timestamp_opt(
                            packet.header.ts.tv_sec,
                            packet.header.ts.tv_usec as u32 * 1000,
                        )
                        .unwrap(),
                    source: channel.source,
                    destination: channel.destination,
                    message,
                };
                serde_json::to_writer(&mut *writer, &entry).expect("could not serialize");
                write!(writer, "\n").unwrap();
            }
            Err(DeserializationError::InvalidHeader) => {
                statistics.header_deserialization_failed_count += 1
            }
            Err(DeserializationError::InvalidMessage) => {
                statistics.message_deserialization_failed_count += 1
            }
        }
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
