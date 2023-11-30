pub(crate) mod channel_buffers;
mod packet_processor;

use chrono::{DateTime, TimeZone, Utc};
use packet_processor::{PacketProcessor, PacketStatistics};
use pcap::Capture;
use std::{
    env,
    fs::File,
    io::{BufWriter, Write},
};

fn main() {
    let pcap_file = get_pcap_file_from_args();
    let mut capture = Capture::from_file(pcap_file).expect("Failed to open pcap file");
    let out_file = File::create("output.json").expect("could not create output.json");
    let mut writer = BufWriter::new(out_file);
    let mut packet_processor = PacketProcessor::new();

    while let Ok(packet) = capture.next() {
        if packet_processor.should_indicate_progress() {
            indicate_progress()
        }

        if let Some(channel) = packet_processor.add_packet(packet.data) {
            let timestamp = get_timestamp(&packet);

            while let Some(entry) = packet_processor.parse_message(&channel, timestamp) {
                serde_json::to_writer(&mut writer, &entry).expect("could not serialize");
                write!(writer, "\n").unwrap();
            }
        }
    }

    print_summary(&packet_processor.statistics);
}

fn get_pcap_file_from_args() -> String {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <pcap file>", args[0]);
        std::process::exit(1);
    }
    args[1].clone()
}

fn get_timestamp(packet: &pcap::Packet) -> DateTime<Utc> {
    Utc.timestamp_opt(
        packet.header.ts.tv_sec,
        packet.header.ts.tv_usec as u32 * 1000,
    )
    .unwrap()
}

fn indicate_progress() {
    print!(".");
    let _ = std::io::stdout().flush();
}

fn print_summary(stats: &PacketStatistics) {
    println!();
    println!("packet_count {}", stats.packet_count);
    println!("tcp_count {}", stats.tcp_count);
    println!("messages_parsed_count {}", stats.messages_parsed_count);
    println!(
        "header_deserialization_failed_count {}",
        stats.header_deserialization_failed_count
    );
    println!(
        "message_deserialization_failed_count {}",
        stats.message_deserialization_failed_count
    );
    println!("Processing complete. Data written to output.csv");
}
