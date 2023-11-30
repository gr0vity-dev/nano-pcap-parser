use num_traits::FromPrimitive;
use rsnano_core::Networks;
use rsnano_messages::{Message, MessageHeader};
use std::{collections::HashMap, net::SocketAddr};

#[derive(Hash, PartialEq, Eq, Clone)]
pub(crate) struct Channel {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

pub enum DeserializationError {
    InvalidHeader,
    InvalidMessage,
}

/// Keeps track of sent bytes per channel
pub struct ChannelBuffers {
    channels: HashMap<Channel, Vec<u8>>,
}

impl ChannelBuffers {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
        }
    }

    pub fn add_bytes(&mut self, channel: &Channel, bytes: &[u8]) {
        let buffer = if let Some(buf) = self.channels.get_mut(channel) {
            Some(buf)
        } else if is_nano_message(bytes) {
            let buf = self.channels.entry(channel.clone()).or_default();
            buf.reserve(1024 * 64);
            Some(buf)
        } else {
            None
        };

        if let Some(buffer) = buffer {
            buffer.extend_from_slice(bytes);
        }
    }

    pub fn pop_message(
        &mut self,
        channel: &Channel,
    ) -> Result<Option<Message>, DeserializationError> {
        let Some(buffer) = self.channels.get_mut(channel) else {
            return Ok(None);
        };

        if buffer.len() < MessageHeader::SERIALIZED_SIZE {
            // incomplete header
            return Ok(None);
        }

        let Ok(header) =
            MessageHeader::deserialize_slice(&buffer[..MessageHeader::SERIALIZED_SIZE])
        else {
            self.channels.remove(channel);
            return Err(DeserializationError::InvalidHeader);
        };

        let message_len = MessageHeader::SERIALIZED_SIZE + header.payload_length();
        if buffer.len() < message_len {
            // not all bytes received yet!
            return Ok(None);
        }

        let message = Message::deserialize(
            &buffer[MessageHeader::SERIALIZED_SIZE..message_len],
            &header,
            0,
        );
        buffer.drain(..message_len);

        match message {
            Some(message) => Ok(Some(message)),
            None => Err(DeserializationError::InvalidMessage),
        }
    }
}

fn is_nano_message(bytes: &[u8]) -> bool {
    if bytes.len() < MessageHeader::SERIALIZED_SIZE {
        return false;
    }
    let network = Networks::from_u16(u16::from_be_bytes([bytes[0], bytes[1]]));
    let version_max = bytes[2];
    let version_using = bytes[3];
    let version_min = bytes[4];
    network.is_some() && version_max == 19 && version_using == 19 && version_min == 18
}
