//! WebSocket frame parsing and the post-101 relay loop.
use std::io::{self, BufReader};

use super::*;
use crate::http::net::Stream;

#[derive(Clone)]
pub struct WsMsg {
    pub id: usize,
    pub url: String,
    pub to_server: bool,
    pub opcode: u8,
    pub data: Vec<u8>,
    pub time: String,
}

/// Pops complete WebSocket frames (opcode, unmasked payload) off the front of `buf`.
pub fn ws_frames(buf: &mut Vec<u8>) -> Vec<(u8, Vec<u8>)> {
    let mut out = vec![];
    loop {
        if buf.len() < 2 {
            break;
        }
        let (op, masked, l7) = (buf[0] & 0x0f, buf[1] & 0x80 != 0, (buf[1] & 0x7f) as usize);
        let (len, mut i) = match l7 {
            126 if buf.len() >= 4 => (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4),
            127 if buf.len() >= 10 => (
                u64::from_be_bytes(buf[2..10].try_into().unwrap()) as usize,
                10,
            ),
            126 | 127 => break,
            n => (n, 2),
        };
        let key = if masked {
            if buf.len() < i + 4 {
                break;
            }
            i += 4;
            Some([buf[i - 4], buf[i - 3], buf[i - 2], buf[i - 1]])
        } else {
            None
        };
        if buf.len() < i + len {
            break;
        }
        let mut data = buf[i..i + len].to_vec();
        if let Some(k) = key {
            data.iter_mut()
                .enumerate()
                .for_each(|(j, b)| *b ^= k[j % 4]);
        }
        buf.drain(..i + len);
        out.push((op, data));
    }
    out
}

/// Shuttles bytes both ways after a 101, logging every frame to the WebSockets history.
pub(crate) fn relay_ws<S: Stream>(
    client: &mut BufReader<S>,
    mut up: BufReader<Box<dyn Stream>>,
    state: &State,
    url: &str,
) -> io::Result<()> {
    use std::io::Read;
    let tick = Some(std::time::Duration::from_millis(30));
    client.get_ref().set_timeout(tick);
    up.get_ref().set_timeout(tick);
    let mut bufs = [Vec::new(), Vec::new()];
    let mut tmp = vec![0u8; 16 * 1024];
    loop {
        for to_server in [true, false] {
            let n = if to_server {
                client.read(&mut tmp)
            } else {
                up.read(&mut tmp)
            };
            let n = match n {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => return Ok(()),
            };
            if to_server {
                up.get_mut().write_all(&tmp[..n])?;
                up.get_mut().flush()?;
            } else {
                client.get_mut().write_all(&tmp[..n])?;
                client.get_mut().flush()?;
            }
            let buf = &mut bufs[to_server as usize];
            buf.extend_from_slice(&tmp[..n]);
            let frames = ws_frames(buf);
            if !frames.is_empty() {
                let mut s = state.lock().unwrap();
                for (opcode, data) in frames {
                    let id = s.ws.len() + 1;
                    s.ws.push(WsMsg {
                        id,
                        url: url.into(),
                        to_server,
                        opcode,
                        data,
                        time: now(),
                    });
                }
                s.repaint();
            }
        }
    }
}
