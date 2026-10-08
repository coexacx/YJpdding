use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug)]
pub struct Packet<'a> {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub protocol: u8,
    pub sequence: u32,
    pub syn: bool,
    pub ack: bool,
    pub payload: &'a [u8],
    pub ip_length: usize,
}
#[derive(Debug, PartialEq)]
pub enum DecodeError {
    Unsupported,
    Truncated,
    Fragmented,
    Malformed,
}
fn u16be(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

pub fn decode(link: i32, data: &[u8]) -> Result<Packet<'_>, DecodeError> {
    let (mut offset, mut kind) = match link {
        1 => {
            if data.len() < 14 {
                return Err(DecodeError::Truncated);
            }
            (14, u16be(data, 12))
        }
        113 => {
            if data.len() < 16 {
                return Err(DecodeError::Truncated);
            }
            (16, u16be(data, 14))
        }
        276 => {
            if data.len() < 20 {
                return Err(DecodeError::Truncated);
            }
            (20, u16be(data, 0))
        }
        12 | 101 => {
            if data.is_empty() {
                return Err(DecodeError::Truncated);
            }
            (0, if data[0] >> 4 == 6 { 0x86dd } else { 0x0800 })
        }
        228 => (0, 0x0800),
        229 => (0, 0x86dd),
        0 | 108 => {
            if data.len() < 5 {
                return Err(DecodeError::Truncated);
            }
            (4, if data[4] >> 4 == 6 { 0x86dd } else { 0x0800 })
        }
        _ => return Err(DecodeError::Unsupported),
    };
    for _ in 0..4 {
        if kind == 0x8100 || kind == 0x88a8 {
            if data.len() < offset + 4 {
                return Err(DecodeError::Truncated);
            }
            kind = u16be(data, offset + 2);
            offset += 4;
        } else {
            break;
        }
    }
    let b = &data[offset..];
    let (source, destination, mut proto, mut pos, total) = match kind {
        0x0800 => {
            if b.len() < 20 {
                return Err(DecodeError::Truncated);
            }
            let header = (b[0] & 15) as usize * 4;
            let total = u16be(b, 2) as usize;
            if b[0] >> 4 != 4 || header < 20 || total < header {
                return Err(DecodeError::Malformed);
            }
            if total > b.len() {
                return Err(DecodeError::Truncated);
            }
            if u16be(b, 6) & 0x3fff != 0 {
                return Err(DecodeError::Fragmented);
            }
            (
                IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15])),
                IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19])),
                b[9],
                header,
                total,
            )
        }
        0x86dd => {
            if b.len() < 40 {
                return Err(DecodeError::Truncated);
            }
            if b[0] >> 4 != 6 {
                return Err(DecodeError::Malformed);
            }
            let total = 40 + u16be(b, 4) as usize;
            if total > b.len() {
                return Err(DecodeError::Truncated);
            }
            (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).unwrap())),
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).unwrap())),
                b[6],
                40,
                total,
            )
        }
        _ => return Err(DecodeError::Unsupported),
    };
    if kind == 0x86dd {
        for _ in 0..12 {
            if !matches!(proto, 0 | 43 | 44 | 51 | 60) {
                break;
            }
            if pos + 2 > total {
                return Err(DecodeError::Truncated);
            }
            let size = match proto {
                44 => {
                    if pos + 8 > total {
                        return Err(DecodeError::Truncated);
                    }
                    if u16be(b, pos + 2) & 0xfff9 != 0 {
                        return Err(DecodeError::Fragmented);
                    }
                    8
                }
                51 => (b[pos + 1] as usize + 2) * 4,
                _ => (b[pos + 1] as usize + 1) * 8,
            };
            proto = b[pos];
            pos += size;
            if pos > total {
                return Err(DecodeError::Truncated);
            }
        }
    }
    let t = &b[pos..total];
    match proto {
        6 => {
            if t.len() < 20 {
                return Err(DecodeError::Truncated);
            }
            let header = (t[12] >> 4) as usize * 4;
            if header < 20 {
                return Err(DecodeError::Malformed);
            }
            if header > t.len() {
                return Err(DecodeError::Truncated);
            }
            Ok(Packet {
                source: SocketAddr::new(source, u16be(t, 0)),
                destination: SocketAddr::new(destination, u16be(t, 2)),
                protocol: 6,
                sequence: u32::from_be_bytes(t[4..8].try_into().unwrap()),
                syn: t[13] & 2 != 0,
                ack: t[13] & 16 != 0,
                payload: &t[header..],
                ip_length: total,
            })
        }
        17 => {
            if t.len() < 8 {
                return Err(DecodeError::Truncated);
            }
            let length = u16be(t, 4) as usize;
            if length < 8 {
                return Err(DecodeError::Malformed);
            }
            if length > t.len() {
                return Err(DecodeError::Truncated);
            }
            Ok(Packet {
                source: SocketAddr::new(source, u16be(t, 0)),
                destination: SocketAddr::new(destination, u16be(t, 2)),
                protocol: 17,
                sequence: 0,
                syn: false,
                ack: false,
                payload: &t[8..length],
                ip_length: total,
            })
        }
        _ => Err(DecodeError::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn short_packets_never_panic() {
        for n in 0..100 {
            for link in [1, 113, 276, 101, 0, 228, 229] {
                let _ = decode(link, &vec![0; n]);
            }
        }
    }
    #[test]
    fn arbitrary_packets_never_panic() {
        use rand::{RngCore, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for n in 0..10000 {
            let mut data = vec![0; n % 512];
            rng.fill_bytes(&mut data);
            for link in [1, 113, 276, 101, 0, 228, 229] {
                let _ = decode(link, &data);
            }
        }
    }
    #[test]
    fn ipv6_udp_and_fragment() {
        let mut p = vec![0; 52];
        p[0] = 0x60;
        p[5] = 12;
        p[6] = 17;
        p[23] = 1;
        p[39] = 2;
        p[40..42].copy_from_slice(&5000u16.to_be_bytes());
        p[42..44].copy_from_slice(&443u16.to_be_bytes());
        p[45] = 12;
        assert_eq!(decode(101, &p).unwrap().payload.len(), 4);
        p[6] = 44;
        p[40] = 17;
        p[43] = 1;
        assert_eq!(decode(101, &p).unwrap_err(), DecodeError::Fragmented);
    }
}
