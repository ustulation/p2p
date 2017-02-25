use NatError;
use bincode::{SizeLimit, deserialize_from, serialize_into};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use mio::{Evented, Poll, PollOpt, Ready, Token};
use mio::tcp::TcpStream;
use serde::de::Deserialize;
use serde::ser::Serialize;
use std::collections::VecDeque;
use std::io::{self, Cursor, ErrorKind, Read, Write};
use std::mem;
use std::net::SocketAddr;

const MAX_PAYLOAD_SIZE: usize = 1024;

pub struct Socket {
    inner: Option<SockInner>,
}

impl Socket {
    pub fn into_stream(self) -> ::Res<TcpStream> {
        let inner = self.inner.ok_or(NatError::UnregisteredSocket)?;
        Ok(inner.stream)
    }

    pub fn wrap(stream: TcpStream) -> Self {
        Socket {
            inner: Some(SockInner {
                stream: stream,
                read_buffer: Vec::new(),
                read_len: 0,
                write_queue: VecDeque::with_capacity(5),
                current_write: None,
            }),
        }
    }

    pub fn local_addr(&self) -> ::Res<SocketAddr> {
        let inner = self.inner.as_ref().ok_or(NatError::UnregisteredSocket)?;
        Ok(inner.stream.local_addr()?)
    }

    pub fn peer_addr(&self) -> ::Res<SocketAddr> {
        let inner = self.inner.as_ref().ok_or(NatError::UnregisteredSocket)?;
        Ok(inner.stream.peer_addr()?)
    }

    pub fn take_error(&self) -> ::Res<Option<io::Error>> {
        let inner = self.inner.as_ref().ok_or(NatError::UnregisteredSocket)?;
        Ok(inner.stream.take_error()?)
    }

    // Read message from the socket. Call this from inside the `ready` handler.
    //
    // Returns:
    //   - Ok(Some(data)): data has been successfuly read from the socket
    //   - Ok(None):       there is not enough data in the socket. Call `read`
    //                     again in the next invocation of the `ready` handler.
    //   - Err(error):     there was an error reading from the socket.
    pub fn read<T: Deserialize>(&mut self) -> ::Res<Option<T>> {
        let inner = self.inner.as_mut().ok_or(NatError::UnregisteredSocket)?;
        inner.read()
    }

    // Write a message to the socket.
    //
    // Returns:
    //   - Ok(true):   the message has been successfuly written.
    //   - Ok(false):  the message has been queued, but not yet fully written.
    //                 Write event is already scheduled for next time.
    //   - Err(error): there was an error while writing to the socket.
    pub fn write<T: Serialize>(&mut self,
                               poll: &Poll,
                               token: Token,
                               msg: Option<T>)
                               -> ::Res<bool> {
        let inner = self.inner.as_mut().ok_or(NatError::UnregisteredSocket)?;
        inner.write(poll, token, msg)
    }
}

impl Default for Socket {
    fn default() -> Self {
        Socket { inner: None }
    }
}

impl Evented for Socket {
    fn register(&self,
                poll: &Poll,
                token: Token,
                interest: Ready,
                opts: PollOpt)
                -> io::Result<()> {
        let inner = self.inner
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(ErrorKind::Other,
                               format!("{}", NatError::UnregisteredSocket))
            })?;
        inner.register(poll, token, interest, opts)
    }

    fn reregister(&self,
                  poll: &Poll,
                  token: Token,
                  interest: Ready,
                  opts: PollOpt)
                  -> io::Result<()> {
        let inner = self.inner
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(ErrorKind::Other,
                               format!("{}", NatError::UnregisteredSocket))
            })?;
        inner.reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        let inner = self.inner
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(ErrorKind::Other,
                               format!("{}", NatError::UnregisteredSocket))
            })?;
        inner.deregister(poll)
    }
}

struct SockInner {
    stream: TcpStream,
    read_buffer: Vec<u8>,
    read_len: usize,
    write_queue: VecDeque<Vec<u8>>,
    current_write: Option<Vec<u8>>,
}

impl SockInner {
    // Read message from the socket. Call this from inside the `ready` handler.
    //
    // Returns:
    //   - Ok(Some(data)): data has been successfuly read from the socket
    //   - Ok(None):       there is not enough data in the socket. Call `read`
    //                     again in the next invocation of the `ready` handler.
    //   - Err(error):     there was an error reading from the socket.
    fn read<T: Deserialize>(&mut self) -> ::Res<Option<T>> {
        if let Some(message) = self.read_from_buffer()? {
            return Ok(Some(message));
        }

        // the mio reading window is max at 64k (64 * 1024)
        let mut buffer = [0; 65536];
        let mut is_something_read = false;

        loop {
            match self.stream.read(&mut buffer) {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        if is_something_read {
                            match self.read_from_buffer() {
                                r @ Ok(Some(_)) | r @ Err(_) => return r,
                                Ok(None) => return Err(NatError::ZeroByteRead),
                            }
                        } else {
                            return Err(NatError::ZeroByteRead);
                        }
                    }
                    self.read_buffer.extend_from_slice(&buffer[0..bytes_read]);
                    is_something_read = true;
                }
                Err(error) => {
                    return if error.kind() == ErrorKind::WouldBlock ||
                              error.kind() == ErrorKind::Interrupted {
                        if is_something_read {
                            self.read_from_buffer()
                        } else {
                            Ok(None)
                        }
                    } else {
                        Err(From::from(error))
                    }
                }
            }
        }
    }

    fn read_from_buffer<T: Deserialize>(&mut self) -> ::Res<Option<T>> {
        let u32_size = mem::size_of::<u32>();

        if self.read_len == 0 {
            if self.read_buffer.len() < u32_size {
                return Ok(None);
            }

            self.read_len = Cursor::new(&self.read_buffer).read_u32::<LittleEndian>()? as usize;

            if self.read_len > MAX_PAYLOAD_SIZE {
                return Err(NatError::PayloadSizeProhibitive);
            }

            self.read_buffer = self.read_buffer[u32_size..].to_owned();
        }

        if self.read_len > self.read_buffer.len() {
            return Ok(None);
        }

        let result = deserialize_from(&mut Cursor::new(&self.read_buffer), SizeLimit::Infinite)?;

        self.read_buffer = self.read_buffer[self.read_len..].to_owned();
        self.read_len = 0;

        Ok(Some(result))
    }

    // Write a message to the socket.
    //
    // Returns:
    //   - Ok(true):   the message has been successfuly written.
    //   - Ok(false):  the message has been queued, but not yet fully written.
    //                 Write event is already scheduled for next time.
    //   - Err(error): there was an error while writing to the socket.
    fn write<T: Serialize>(&mut self, poll: &Poll, token: Token, msg: Option<T>) -> ::Res<bool> {
        if let Some(msg) = msg {
            let mut data = Cursor::new(Vec::with_capacity(mem::size_of::<u32>()));

            let _ = data.write_u32::<LittleEndian>(0);

            serialize_into(&mut data, &msg, SizeLimit::Infinite)?;

            let len = data.position() - mem::size_of::<u32>() as u64;
            data.set_position(0);
            data.write_u32::<LittleEndian>(len as u32)?;

            self.write_queue.push_back(data.into_inner());
        }

        if self.current_write.is_none() {
            let data = match self.write_queue.pop_front() {
                Some(data) => data,
                None => return Ok(true),
            };
            self.current_write = Some(data);
        }

        if let Some(data) = self.current_write.take() {
            match self.stream.write(&data) {
                Ok(bytes_txd) => {
                    if bytes_txd < data.len() {
                        self.current_write = Some(data[bytes_txd..].to_owned());
                    }
                }
                Err(error) => {
                    if error.kind() == ErrorKind::WouldBlock ||
                       error.kind() == ErrorKind::Interrupted {
                        self.current_write = Some(data);
                    } else {
                        return Err(From::from(error));
                    }
                }
            }
        }

        let done = self.current_write.is_none() && self.write_queue.is_empty();

        let event_set = if done {
            Ready::error() | Ready::hup() | Ready::readable()
        } else {
            Ready::error() | Ready::hup() | Ready::readable() | Ready::writable()
        };

        poll.reregister(self, token, event_set, PollOpt::edge())?;

        Ok(done)
    }
}

impl Evented for SockInner {
    fn register(&self,
                poll: &Poll,
                token: Token,
                interest: Ready,
                opts: PollOpt)
                -> io::Result<()> {
        self.stream.register(poll, token, interest, opts)
    }

    fn reregister(&self,
                  poll: &Poll,
                  token: Token,
                  interest: Ready,
                  opts: PollOpt)
                  -> io::Result<()> {
        self.stream.reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        self.stream.deregister(poll)
    }
}
