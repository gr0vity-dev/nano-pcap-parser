pub(crate) mod channel_buffers;
mod output_file_writer;
mod packet_processor;
mod ui;

use output_file_writer::OutputFileWriter;
use packet_processor::PacketProcessor;
use pcap::Capture;
use std::env;

fn main() {
    let pcap_file = get_pcap_file_from_args();
    let mut capture = Capture::from_file(pcap_file).expect("Failed to open pcap file");
    let mut out_file =
        OutputFileWriter::create("output.json").expect("could not create output.json");
    let mut packet_processor = PacketProcessor::new();

    while let Ok(packet) = capture.next() {
        ui::indicate_progress(&packet_processor.statistics);

        if packet_processor.add_packet(&packet) {
            while let Some(entry) = packet_processor.parse_message() {
                out_file.write(&entry);
            }
        }
    }

    ui::print_summary(&packet_processor.statistics);
}

fn get_pcap_file_from_args() -> String {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        ui::print_usage(&args[0]);
        std::process::exit(1);
    }
    args[1].clone()
}
