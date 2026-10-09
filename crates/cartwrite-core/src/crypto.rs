//! AES primitives in the flavours the Switch uses: ECB for key wrapping,
//! XTS with a big-endian sector tweak for NCA headers, and CTR for section data.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

pub type Key128 = [u8; 16];

pub fn ecb_decrypt(key: &Key128, data: &mut [u8]) {
    let c = Aes128::new(GenericArray::from_slice(key));
    for chunk in data.as_chunks_mut::<16>().0 {
        c.decrypt_block(GenericArray::from_mut_slice(chunk));
    }
}

pub fn ecb_encrypt(key: &Key128, data: &mut [u8]) {
    let c = Aes128::new(GenericArray::from_slice(key));
    for chunk in data.as_chunks_mut::<16>().0 {
        c.encrypt_block(GenericArray::from_mut_slice(chunk));
    }
}

pub fn ecb_decrypt_key(key: &Key128, src: &Key128) -> Key128 {
    let mut out = *src;
    ecb_decrypt(key, &mut out);
    out
}

/// AES-128-XTS using Nintendo's big-endian sector number tweak.
pub struct Xts {
    k1: Aes128,
    k2: Aes128,
}

impl Xts {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            k1: Aes128::new(GenericArray::from_slice(&key[..16])),
            k2: Aes128::new(GenericArray::from_slice(&key[16..])),
        }
    }

    pub fn decrypt(&self, data: &mut [u8], first_sector: u64, sector_size: usize) {
        self.process(data, first_sector, sector_size, false)
    }

    pub fn encrypt(&self, data: &mut [u8], first_sector: u64, sector_size: usize) {
        self.process(data, first_sector, sector_size, true)
    }

    fn process(&self, data: &mut [u8], first_sector: u64, sector_size: usize, encrypt: bool) {
        for (i, sector) in data.chunks_mut(sector_size).enumerate() {
            let mut tweak = ((first_sector + i as u64) as u128).to_be_bytes();
            self.k2.encrypt_block(GenericArray::from_mut_slice(&mut tweak));
            for block in sector.as_chunks_mut::<16>().0 {
                xor16(block, &tweak);
                let b = GenericArray::from_mut_slice(block);
                if encrypt {
                    self.k1.encrypt_block(b);
                } else {
                    self.k1.decrypt_block(b);
                }
                xor16(block, &tweak);
                gf_double(&mut tweak);
            }
        }
    }
}

fn xor16(a: &mut [u8], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

fn gf_double(t: &mut [u8; 16]) {
    let mut carry = 0u8;
    for b in t.iter_mut() {
        let next = *b >> 7;
        *b = (*b << 1) | carry;
        carry = next;
    }
    if carry != 0 {
        t[0] ^= 0x87;
    }
}

/// AES-128-CTR where the counter is `nonce (8 bytes) || (offset / 16) as big-endian u64`.
#[derive(Clone)]
pub struct Ctr {
    cipher: Aes128,
    nonce: [u8; 8],
}

impl Ctr {
    pub fn new(key: &Key128, nonce: [u8; 8]) -> Self {
        Self { cipher: Aes128::new(GenericArray::from_slice(key)), nonce }
    }

    /// XORs the keystream for absolute byte `offset` into `data` (encrypt == decrypt).
    pub fn apply(&self, offset: u64, data: &mut [u8]) {
        const BATCH: usize = 256;
        let mut blocks = [GenericArray::<u8, aes::cipher::consts::U16>::default(); BATCH];
        let mut pos = 0usize;
        let mut off = offset;
        while pos < data.len() {
            let block_idx = off / 16;
            let skip = (off % 16) as usize;
            let remaining = data.len() - pos;
            let nblocks = (skip + remaining).div_ceil(16).min(BATCH);
            for (i, b) in blocks[..nblocks].iter_mut().enumerate() {
                b[..8].copy_from_slice(&self.nonce);
                b[8..].copy_from_slice(&(block_idx + i as u64).to_be_bytes());
            }
            self.cipher.encrypt_blocks(&mut blocks[..nblocks]);
            let n = (nblocks * 16 - skip).min(remaining);
            for i in 0..n {
                let k = skip + i;
                data[pos + i] ^= blocks[k / 16][k % 16];
            }
            pos += n;
            off += n as u64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xts_roundtrip() {
        let key = [7u8; 32];
        let xts = Xts::new(&key);
        let orig: Vec<u8> = (0..0xC00).map(|i| i as u8).collect();
        let mut buf = orig.clone();
        xts.encrypt(&mut buf, 0, 0x200);
        assert_ne!(buf, orig);
        xts.decrypt(&mut buf, 0, 0x200);
        assert_eq!(buf, orig);
    }

    #[test]
    fn ctr_unaligned_matches_aligned() {
        let ctr = Ctr::new(&[3u8; 16], [1, 2, 3, 4, 5, 6, 7, 8]);
        let mut whole = vec![0u8; 5000];
        ctr.apply(0x100, &mut whole);
        let mut part = vec![0u8; 4000];
        ctr.apply(0x100 + 777, &mut part);
        assert_eq!(&whole[777..4777], &part[..]);
    }
}
