use std::{
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

use crate::packet_processor::Entry;

pub(crate) struct OutputFileWriter {
    buf_writer: BufWriter<File>,
}

impl OutputFileWriter {
    pub fn create(filepath: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = File::create(filepath)?;
        let buf_writer = BufWriter::new(file);
        Ok(Self { buf_writer })
    }

    pub fn write(&mut self, entry: &Entry) {
        serde_json::to_writer(&mut self.buf_writer, entry).expect("could not serialize");
        write!(&mut self.buf_writer, "\n").unwrap();
    }
}
