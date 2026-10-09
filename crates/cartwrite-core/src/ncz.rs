//! NCZ (compressed NCA, used inside NSZ/XCZ) support.
//!
//! Layout: the first 0x4000 bytes of the original (encrypted) NCA, then an `NCZSECTN`
//! table describing each section's crypto, an optional `NCZBLOCK` header, and finally the
//! zstd-compressed *plaintext* of the NCA from 0x4000 onward. Restoring the NCA means
//! decompressing and re-applying each section's AES-CTR.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

use crate::crypto::{Ctr, Key128};
use crate::error::{fmt_err, Error, Result};
use crate::nca::{NcaHeader, NcaSource, CRYPT_BKTR, CRYPT_CTR};
use crate::util::{read_at, read_vec_at, u32le, u64le};

pub const UNCOMPRESSED_HEADER: u64 = 0x4000;

#[derive(Clone, Debug)]
pub struct NczSection {
    pub offset: u64,
    pub size: u64,
    pub crypto_type: u64,
    pub key: Key128,
    pub counter: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub block_size: u64,
    pub decompressed_size: u64,
    pub compressed_sizes: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct NczInfo {
    pub sections: Vec<NczSection>,
    /// Absolute file offset of the compressed payload.
    pub data_start: u64,
    pub data_end: u64,
    pub block: Option<BlockInfo>,
}

impl NczInfo {
    pub fn parse(f: &mut File, base: u64, stored_size: u64) -> Result<Self> {
        let mut pos = base + UNCOMPRESSED_HEADER;
        let hdr = read_vec_at(f, pos, 16)?;
        if &hdr[..8] != b"NCZSECTN" {
            return fmt_err("missing NCZSECTN header");
        }
        let count = u64le(&hdr, 8) as usize;
        if count > 64 {
            return fmt_err("too many NCZ sections");
        }
        pos += 16;
        let table = read_vec_at(f, pos, count * 0x40)?;
        pos += (count * 0x40) as u64;
        let sections = (0..count)
            .map(|i| {
                let s = &table[i * 0x40..];
                NczSection {
                    offset: u64le(s, 0),
                    size: u64le(s, 8),
                    crypto_type: u64le(s, 0x10),
                    key: s[0x20..0x30].try_into().unwrap(),
                    counter: s[0x30..0x40].try_into().unwrap(),
                }
            })
            .collect();

        let mut magic = [0u8; 8];
        read_at(f, pos, &mut magic)?;
        let block = if &magic == b"NCZBLOCK" {
            let h = read_vec_at(f, pos, 0x18)?;
            let exp = h[0xB] as u32;
            let n = u32le(&h, 0xC) as usize;
            let decompressed_size = u64le(&h, 0x10);
            if !(1..=32).contains(&exp) || n > 1 << 24 {
                return fmt_err("bad NCZ block header");
            }
            let sizes = read_vec_at(f, pos + 0x18, n * 4)?;
            pos += 0x18 + (n * 4) as u64;
            Some(BlockInfo {
                block_size: 1u64 << exp,
                decompressed_size,
                compressed_sizes: (0..n).map(|i| u32le(&sizes, i * 4)).collect(),
            })
        } else {
            None
        };
        Ok(Self { sections, data_start: pos, data_end: base + stored_size, block })
    }

    /// Re-encrypts plaintext that starts at absolute NCA offset `offset`.
    pub fn reencrypt(&self, offset: u64, data: &mut [u8]) {
        let end = offset + data.len() as u64;
        for s in &self.sections {
            if s.crypto_type != CRYPT_CTR as u64 && s.crypto_type != CRYPT_BKTR as u64 {
                continue;
            }
            let lo = s.offset.max(offset);
            let hi = (s.offset + s.size).min(end);
            if lo >= hi {
                continue;
            }
            let nonce: [u8; 8] = s.counter[..8].try_into().unwrap();
            Ctr::new(&s.key, nonce).apply(lo, &mut data[(lo - offset) as usize..(hi - offset) as usize]);
        }
    }

    /// Streams the decompressed plaintext (NCA offsets 0x4000..nca_size) to `sink` in chunks.
    pub fn decompress(&self, f: &File, nca_size: u64, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let total = nca_size.saturating_sub(UNCOMPRESSED_HEADER);
        let mut file = f.try_clone()?;
        file.seek(SeekFrom::Start(self.data_start))?;
        let reader = BufReader::with_capacity(1 << 20, file.take(self.data_end.saturating_sub(self.data_start)));
        let mut produced = 0u64;
        match &self.block {
            None => {
                let mut dec = zstd::stream::read::Decoder::with_buffer(reader)?;
                let mut buf = vec![0u8; 4 << 20];
                while produced < total {
                    let want = ((total - produced) as usize).min(buf.len());
                    let n = dec.read(&mut buf[..want])?;
                    if n == 0 {
                        return fmt_err("NCZ stream ended early");
                    }
                    sink(&buf[..n])?;
                    produced += n as u64;
                }
            }
            Some(b) => {
                let mut reader = reader;
                let mut cbuf = Vec::new();
                for (i, &csize) in b.compressed_sizes.iter().enumerate() {
                    let this = if i + 1 == b.compressed_sizes.len() && b.decompressed_size % b.block_size != 0 {
                        b.decompressed_size % b.block_size
                    } else {
                        b.block_size
                    };
                    cbuf.resize(csize as usize, 0);
                    reader.read_exact(&mut cbuf)?;
                    if (csize as u64) < this {
                        let out = zstd::bulk::decompress(&cbuf, this as usize)
                            .map_err(|e| Error::Format(format!("NCZ block {i}: {e}")))?;
                        sink(&out)?;
                        produced += out.len() as u64;
                    } else {
                        sink(&cbuf)?;
                        produced += cbuf.len() as u64;
                    }
                }
            }
        }
        if produced < total {
            return fmt_err("NCZ decompressed size is smaller than the NCA");
        }
        Ok(())
    }
}

/// An NCZ fully decompressed into memory (only used for small NCAs such as control data).
pub struct MemNcz {
    pub head: Vec<u8>,
    pub body: Vec<u8>,
}

impl MemNcz {
    pub fn load(f: &mut File, base: u64, stored_size: u64, nca_size: u64, limit: u64) -> Result<Self> {
        if nca_size > limit {
            return Err(Error::Unsupported("compressed NCA too large to inspect".into()));
        }
        let head = read_vec_at(f, base, UNCOMPRESSED_HEADER as usize)?;
        let info = NczInfo::parse(f, base, stored_size)?;
        let mut body = Vec::with_capacity(nca_size as usize);
        info.decompress(f, nca_size, &mut |chunk| {
            body.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(Self { head, body })
    }
}

impl NcaSource for MemNcz {
    fn read_plain(&mut self, header: &NcaHeader, key: &Key128, offset: u64, buf: &mut [u8]) -> Result<()> {
        let end = offset + buf.len() as u64;
        // Part inside the raw (still encrypted) header region.
        if offset < UNCOMPRESSED_HEADER {
            let hi = end.min(UNCOMPRESSED_HEADER);
            let aligned = offset & !0xF;
            let mut tmp = self.head[aligned as usize..hi as usize].to_vec();
            crate::nca::decrypt_in_place(header, key, aligned, &mut tmp)?;
            buf[..(hi - offset) as usize].copy_from_slice(&tmp[(offset - aligned) as usize..]);
        }
        if end > UNCOMPRESSED_HEADER {
            let lo = offset.max(UNCOMPRESSED_HEADER);
            let src = &self.body.get((lo - UNCOMPRESSED_HEADER) as usize..(end - UNCOMPRESSED_HEADER) as usize);
            let Some(src) = src else { return fmt_err("read past end of NCZ") };
            buf[(lo - offset) as usize..].copy_from_slice(src);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const KEY: Key128 = [0x42; 16];
    const NONCE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    /// Deterministic bytes, alternating compressible and incompressible 16 KiB runs.
    fn payload(len: usize) -> Vec<u8> {
        let mut x = 0x1234_5678u32;
        (0..len)
            .map(|i| {
                if (i / 0x4000) % 2 == 0 {
                    (i % 7) as u8
                } else {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                }
            })
            .collect()
    }

    /// Builds an NCZ for an "NCA" whose body after 0x4000 is one CTR section.
    /// Returns (ncz bytes, original encrypted NCA).
    fn make_ncz(plain_body: &[u8], block_exp: Option<u8>) -> (Vec<u8>, Vec<u8>) {
        let head: Vec<u8> = (0..UNCOMPRESSED_HEADER as usize).map(|i| (i * 31) as u8).collect();
        let mut enc_body = plain_body.to_vec();
        Ctr::new(&KEY, NONCE).apply(UNCOMPRESSED_HEADER, &mut enc_body);
        let original = [head.clone(), enc_body].concat();

        let mut ncz = head;
        ncz.extend_from_slice(b"NCZSECTN");
        ncz.extend_from_slice(&1u64.to_le_bytes());
        ncz.extend_from_slice(&UNCOMPRESSED_HEADER.to_le_bytes());
        ncz.extend_from_slice(&(plain_body.len() as u64).to_le_bytes());
        ncz.extend_from_slice(&(CRYPT_CTR as u64).to_le_bytes());
        ncz.extend_from_slice(&0u64.to_le_bytes());
        ncz.extend_from_slice(&KEY);
        ncz.extend_from_slice(&NONCE);
        ncz.extend_from_slice(&[0; 8]);
        match block_exp {
            None => ncz.extend_from_slice(&zstd::bulk::compress(plain_body, 3).unwrap()),
            Some(exp) => {
                let blocks: Vec<Vec<u8>> = plain_body
                    .chunks(1 << exp)
                    .map(|c| {
                        let z = zstd::bulk::compress(c, 3).unwrap();
                        if z.len() < c.len() {
                            z
                        } else {
                            c.to_vec()
                        }
                    })
                    .collect();
                ncz.extend_from_slice(b"NCZBLOCK");
                ncz.extend_from_slice(&[2, 1, 0, exp]);
                ncz.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
                ncz.extend_from_slice(&(plain_body.len() as u64).to_le_bytes());
                for b in &blocks {
                    ncz.extend_from_slice(&(b.len() as u32).to_le_bytes());
                }
                for b in &blocks {
                    ncz.extend_from_slice(b);
                }
            }
        }
        (ncz, original)
    }

    fn restore(ncz: &[u8], nca_size: u64, name: &str) -> Vec<u8> {
        let path = std::env::temp_dir().join(format!("cartwrite-test-{}-{name}.ncz", std::process::id()));
        File::create(&path).unwrap().write_all(ncz).unwrap();
        let mut f = File::open(&path).unwrap();
        let info = NczInfo::parse(&mut f, 0, ncz.len() as u64).unwrap();
        let mut out = ncz[..UNCOMPRESSED_HEADER as usize].to_vec();
        let mut pos = UNCOMPRESSED_HEADER;
        info.decompress(&f, nca_size, &mut |chunk| {
            let mut c = chunk.to_vec();
            info.reencrypt(pos, &mut c);
            pos += c.len() as u64;
            out.extend_from_slice(&c);
            Ok(())
        })
        .unwrap();
        drop(f);
        let _ = std::fs::remove_file(&path);
        out
    }

    #[test]
    fn stream_ncz_roundtrip() {
        let (ncz, original) = make_ncz(&payload(0x13_000), None);
        assert_eq!(restore(&ncz, original.len() as u64, "stream"), original);
    }

    #[test]
    fn block_ncz_roundtrip() {
        // 0x13000 isn't a multiple of the 16 KiB block size, so the last block is partial,
        // and the random runs exercise the stored-uncompressed block path.
        let (ncz, original) = make_ncz(&payload(0x13_000), Some(14));
        assert_eq!(restore(&ncz, original.len() as u64, "block"), original);
    }
}
