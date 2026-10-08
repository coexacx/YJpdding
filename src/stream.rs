use serde::Serialize;
use std::collections::BTreeMap;

const MAX_PENDING: usize = 2 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;

#[derive(Default, Debug, Serialize)]
pub struct Tls {
    pub record_lengths: Vec<usize>,
    pub encrypted_lengths: Vec<usize>,
    pub client_hellos: usize,
    pub server_hellos: usize,
    pub tls13: bool,
    pub invalid: bool,
    pub record_limit: bool,
    pub incomplete_record_bytes: usize,
    #[serde(skip)]
    buffer: Vec<u8>,
    #[serde(skip)]
    handshake: Vec<u8>,
    #[serde(skip)]
    ccs: bool,
}
impl Tls {
    pub fn feed(&mut self, data: &[u8]) {
        if self.invalid || self.record_limit {
            return;
        }
        self.buffer.extend_from_slice(data);
        let mut consumed = 0;
        while self.buffer.len() - consumed >= 5 {
            let b = &self.buffer[consumed..];
            let size = u16::from_be_bytes([b[3], b[4]]) as usize;
            if !(20..=24).contains(&b[0]) || b[1] != 3 || b[2] > 4 || size > 18432 {
                self.invalid = true;
                break;
            }
            if b.len() < size + 5 {
                break;
            }
            if self.record_lengths.len() >= MAX_RECORDS {
                self.record_limit = true;
                break;
            }
            self.record_lengths.push(size);
            match b[0] {
                20 => self.ccs = true,
                22 if !self.ccs => {
                    if self.handshake.len() + size > 1024 * 1024 {
                        self.invalid = true;
                        break;
                    }
                    self.handshake.extend_from_slice(&b[5..5 + size]);
                }
                23 => self.encrypted_lengths.push(size),
                _ => {}
            }
            consumed += size + 5;
        }
        self.buffer.drain(..consumed);
        if self.invalid || self.record_limit {
            self.buffer.clear();
            self.handshake.clear();
        }
        self.incomplete_record_bytes = self.buffer.len();
        let mut n = 0;
        while self.handshake.len() - n >= 4 {
            let b = &self.handshake[n..];
            let length = ((b[1] as usize) << 16) | ((b[2] as usize) << 8) | b[3] as usize;
            if length > 1024 * 1024 {
                self.invalid = true;
                break;
            }
            if b.len() < length + 4 {
                break;
            }
            if b[0] == 1 {
                self.client_hellos += 1;
            }
            if b[0] == 2 {
                self.server_hellos += 1;
                self.tls13 |= server_hello_tls13(&b[4..4 + length]);
            }
            n += 4 + length;
        }
        self.handshake.drain(..n);
    }
}
fn server_hello_tls13(b: &[u8]) -> bool {
    if b.len() < 38 {
        return false;
    }
    let mut pos = 35 + b[34] as usize + 3; // legacy version + random + session id + cipher + compression
    if pos + 2 > b.len() {
        return false;
    }
    let end = pos + 2 + u16::from_be_bytes([b[pos], b[pos + 1]]) as usize;
    pos += 2;
    if end > b.len() {
        return false;
    }
    while pos + 4 <= end {
        let ty = u16::from_be_bytes([b[pos], b[pos + 1]]);
        let len = u16::from_be_bytes([b[pos + 2], b[pos + 3]]) as usize;
        pos += 4;
        if pos + len > end {
            return false;
        }
        if ty == 43 && len == 2 && b[pos..pos + 2] == [3, 4] {
            return true;
        }
        pos += len;
    }
    false
}

#[derive(Default, Debug, Serialize)]
pub struct Stream {
    pub syn_seen: bool,
    pub midstream: bool,
    pub unique_bytes: u64,
    pub duplicate_bytes: u64,
    pub reordered_segments: u64,
    pub gap_bytes: u64,
    pub pending_bytes: usize,
    pub overlap_conflicts: u64,
    pub resource_limited: bool,
    pub tls: Tls,
    #[serde(skip)]
    base: Option<u32>,
    #[serde(skip)]
    next: u32,
    #[serde(skip)]
    pending: BTreeMap<u32, Vec<u8>>,
}
impl Stream {
    pub fn buffered_bytes(&self) -> usize {
        self.pending_bytes + self.tls.buffer.len() + self.tls.handshake.len()
    }
    pub fn syn_sequence(&self) -> Option<u32> {
        if self.syn_seen {
            self.base.map(|v| v.wrapping_sub(1))
        } else {
            None
        }
    }
    pub fn feed(&mut self, seq: u32, syn: bool, payload: &[u8]) {
        if self.resource_limited {
            return;
        }
        if syn {
            self.syn_seen = true;
            if self.base.is_none() {
                self.base = Some(seq.wrapping_add(1));
            }
        }
        if payload.is_empty() {
            return;
        }
        let seq = seq.wrapping_add(u32::from(syn));
        if self.base.is_none() {
            self.base = Some(seq);
            self.midstream = true;
        }
        let mut offset = seq.wrapping_sub(self.base.unwrap());
        // Captures are bounded to <2 GiB; negative signed offsets predate our base.
        let mut bytes = payload;
        if (offset as i32) < 0 {
            let skip = (0u32.wrapping_sub(offset) as usize).min(bytes.len());
            self.duplicate_bytes += skip as u64;
            bytes = &bytes[skip..];
            offset = offset.wrapping_add(skip as u32);
            if bytes.is_empty() {
                return;
            }
        }
        if offset < self.next {
            let skip = ((self.next - offset) as usize).min(bytes.len());
            self.duplicate_bytes += skip as u64;
            bytes = &bytes[skip..];
            offset += skip as u32;
            if bytes.is_empty() {
                return;
            }
        }
        if offset > self.next {
            self.reordered_segments += 1;
        }
        if let Some(old) = self.pending.get(&offset) {
            let overlap = old.len().min(bytes.len());
            if old[..overlap] != bytes[..overlap] {
                self.overlap_conflicts += 1;
            }
            if old.len() >= bytes.len() {
                self.duplicate_bytes += bytes.len() as u64;
                return;
            }
        }
        // Compare all pending overlap regions before deterministic first-start draining.
        for (&start, old) in self
            .pending
            .range(..offset.saturating_add(bytes.len() as u32))
        {
            let begin = start.max(offset);
            let end = (start as usize + old.len()).min(offset as usize + bytes.len());
            if end > begin as usize
                && old[(begin - start) as usize..end - start as usize]
                    != bytes[(begin - offset) as usize..end - offset as usize]
            {
                self.overlap_conflicts += 1;
            }
        }
        let old = self.pending.insert(offset, bytes.to_vec());
        self.pending_bytes += bytes.len();
        if let Some(old) = old {
            self.pending_bytes -= old.len();
            self.duplicate_bytes += old.len() as u64;
        }
        while let Some((&start, _)) = self.pending.first_key_value() {
            if start > self.next {
                break;
            }
            let data = self.pending.remove(&start).unwrap();
            self.pending_bytes -= data.len();
            let trim = ((self.next - start) as usize).min(data.len());
            self.duplicate_bytes += trim as u64;
            let fresh = &data[trim..];
            self.unique_bytes += fresh.len() as u64;
            self.tls.feed(fresh);
            self.next = self.next.saturating_add(fresh.len() as u32);
        }
        if self.pending_bytes > MAX_PENDING {
            self.resource_limited = true;
            self.pending.clear();
            self.pending_bytes = 0;
        }
        self.gap_bytes = self
            .pending
            .first_key_value()
            .map(|(&start, _)| start.saturating_sub(self.next) as u64)
            .unwrap_or(0);
    }
    pub fn complete(&self) -> bool {
        self.syn_seen
            && !self.midstream
            && !self.resource_limited
            && self.pending_bytes == 0
            && self.overlap_conflicts == 0
            && !self.tls.invalid
            && !self.tls.record_limit
            && self.tls.incomplete_record_bytes == 0
            && self.tls.handshake.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(n: usize) -> Vec<u8> {
        let mut b = vec![23, 3, 3];
        b.extend_from_slice(&(n as u16).to_be_bytes());
        b.extend(vec![42; n]);
        b
    }
    #[test]
    fn reassemble_out_of_order_wrap_retransmit() {
        let data = record(80);
        let base = u32::MAX - 20;
        let mut s = Stream::default();
        s.feed(base.wrapping_sub(1), true, &[]);
        s.feed(base.wrapping_add(30), false, &data[30..]);
        s.feed(base, false, &data[..40]);
        s.feed(base, false, &data);
        assert_eq!(s.tls.record_lengths, vec![80]);
        assert_eq!(s.unique_bytes, 85);
        assert!(s.duplicate_bytes >= 85);
        assert!(s.complete());
    }
    #[test]
    fn several_records_and_partial_header() {
        let mut t = Tls::default();
        let data = [record(100), record(50)].concat();
        for b in data.chunks(3) {
            t.feed(b);
        }
        assert_eq!(t.record_lengths, vec![100, 50]);
        assert_eq!(t.incomplete_record_bytes, 0);
    }
    #[test]
    fn gap_not_fabricated() {
        let mut s = Stream::default();
        s.feed(10, true, &[]);
        s.feed(20, false, &record(100));
        assert!(!s.complete());
        assert_eq!(s.gap_bytes, 9);
        assert!(s.tls.record_lengths.is_empty());
    }
    #[test]
    fn tls13_serverhello() {
        let mut h = vec![3, 3];
        h.extend([0u8; 32]);
        h.push(0);
        h.extend([0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4]);
        assert!(server_hello_tls13(&h));
    }
    #[test]
    fn invalid_tls_and_large_lengths() {
        let mut t = Tls::default();
        t.feed(&[23, 3, 3, 255, 255]);
        assert!(t.invalid);
    }
}
