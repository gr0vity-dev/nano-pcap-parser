extern crate pnet;
extern crate csv;
extern crate chrono;

use chrono::{TimeZone, Utc};
use pnet::packet::{ethernet::{EthernetPacket, EtherTypes}, ipv4::Ipv4Packet, tcp::TcpPacket, Packet};
use csv::Writer;
use pcap::Capture;
use rsnano_messages::{Message, MessageHeader};
use std::env;

fn main() {
    let pcap_file = get_pcap_file_from_args();
    let mut capture = open_pcap_file(&pcap_file);
    let mut writer = create_csv_writer("output.csv");

    let mut statistics = PacketStatistics::new();

    while let Ok(packet) = capture.next() {
        process_packet(&packet, &mut writer, &mut statistics);
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


fn create_csv_writer(filename: &str) -> Writer<std::fs::File> {
    let mut writer = csv::Writer::from_path(filename).unwrap();
    writer.write_record(&["Frame Number", "Source IP", "Destination IP", "Source Port", "Destination Port", "Timestamp", "Message Content"]).unwrap();
    writer
}

fn process_packet(packet: &pcap::Packet, writer: &mut Writer<std::fs::File>, statistics: &mut PacketStatistics) {
    statistics.packet_count += 1;
    if let Some(ethernet) = EthernetPacket::new(packet.data) {
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => process_ipv4_packet(&ethernet, packet, writer, statistics),
            _ => {}
        }
    }
}

fn process_ipv4_packet(ethernet: &EthernetPacket, packet: &pcap::Packet, writer: &mut Writer<std::fs::File>, statistics: &mut PacketStatistics) {
    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
            statistics.tcp_count += 1;
            process_tcp_packet(&ipv4, &tcp, packet, writer, statistics); 
        }
    }
}


fn process_tcp_packet(ipv4: &Ipv4Packet, tcp: &TcpPacket, packet: &pcap::Packet, writer: &mut Writer<std::fs::File>, statistics: &mut PacketStatistics) {
    let raw_payload = tcp.payload();
    let timestamp = format_timestamp(packet.header.ts.tv_sec, packet.header.ts.tv_usec);

    if raw_payload.len() >= MessageHeader::SERIALIZED_SIZE {
        let (header_bytes, message_bytes) = raw_payload.split_at(MessageHeader::SERIALIZED_SIZE);

        match MessageHeader::deserialize_slice(header_bytes) {
            Ok(header) => match Message::deserialize(message_bytes, &header, 0) {
                Some(message) => {
                    statistics.packet_parsed_count += 1;
                    // Inline write_packet_data logic here
                    writer.write_record(&[
                        statistics.packet_count.to_string(),
                        ipv4.get_source().to_string(),
                        ipv4.get_destination().to_string(),
                        tcp.get_source().to_string(),
                        tcp.get_destination().to_string(),
                        timestamp.to_string(),
                        format!("{:?}", message),
                    ]).unwrap();
                }
                None => statistics.message_deserialization_failed_count += 1,
            },
            Err(_) => statistics.header_deserialization_failed_count += 1,
        }
    }
}


fn format_timestamp(ts_sec: i64, ts_usec: i64) -> String {
    match Utc.timestamp_opt(ts_sec, ts_usec as u32 * 1000) { // Use timestamp_opt
        chrono::LocalResult::Single(timestamp) => {
            timestamp.format("%Y-%m-%d %H:%M:%S.%f").to_string()
        },
        _ => "Invalid Timestamp".to_string(),  // Handle invalid or ambiguous timestamps
    }
}


struct PacketStatistics {
    packet_count: usize,
    packet_parsed_count: usize,
    header_deserialization_failed_count: usize,
    message_deserialization_failed_count: usize,
    tcp_count: usize,
}

impl PacketStatistics {
    fn new() -> PacketStatistics {
        PacketStatistics {
            packet_count: 0,
            packet_parsed_count: 0,
            header_deserialization_failed_count: 0,
            message_deserialization_failed_count: 0,
            tcp_count: 0,
        }
    }

    fn print_summary(&self) {
        println!("packet_count {}", self.packet_count);
        println!("tcp_count {}", self.tcp_count);
        println!("packet_parsed_count {}", self.packet_parsed_count);
        println!("header_deserialization_failed_count {}", self.header_deserialization_failed_count);
        println!("message_deserialization_failed_count {}", self.message_deserialization_failed_count);
        println!("Processing complete. Data written to output.csv");
    }
}
