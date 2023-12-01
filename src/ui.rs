use crate::packet_processor::PacketStatistics;
use std::io::Write;

pub(crate) fn print_usage(program: &str) {
    eprintln!("Usage: {program} <pcap file>");
}

pub(crate) fn indicate_progress(stats: &PacketStatistics) {
    if stats.total_packets % 10000 == 0 {
        print!(".");
        let _ = std::io::stdout().flush();
    }
}

pub(crate) fn print_summary(stats: &PacketStatistics) {
    println!();
    println!();
    println!("total packets:\t\t\t{}", stats.total_packets);
    println!("TCP packets:\t\t\t{}", stats.total_tcp_packets);
    println!("nano TCP packets:\t\t{}", stats.nano_tcp_packets);
    println!("unknown TCP packets:\t\t{}", stats.unknown_tcp_packets);
    println!("nano messages:\t\t\t{}", stats.messages_parsed);
    println!(
        "header deserialization failed:\t{}",
        stats.header_deserialization_failed
    );
    println!(
        "message deserialization failed:\t{}",
        stats.message_deserialization_failed
    );
    println!();
    println!("Processing complete. Data written to output.csv");
}
