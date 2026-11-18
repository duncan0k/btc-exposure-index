use std::io::{self, Read};

pub fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn bytes<const N: usize>(reader: &mut impl Read) -> io::Result<[u8; N]> {
    let mut data = [0; N];
    reader.read_exact(&mut data)?;
    Ok(data)
}

pub fn varint(reader: &mut impl Read) -> io::Result<u64> {
    let mut n = 0u64;
    loop {
        let b = bytes::<1>(reader)?[0];
        n = n.checked_mul(128).and_then(|v| v.checked_add(u64::from(b & 127)))
            .ok_or_else(|| invalid("VarInt overflow"))?;
        if b & 128 == 0 { return Ok(n); }
        n = n.checked_add(1).ok_or_else(|| invalid("VarInt overflow"))?;
    }
}

pub fn compact_size(reader: &mut impl Read) -> io::Result<u64> {
    let tag = bytes::<1>(reader)?[0];
    let (n, minimum) = match tag {
        253 => (u64::from(u16::from_le_bytes(bytes(reader)?)), 253),
        254 => (u64::from(u32::from_le_bytes(bytes(reader)?)), 65536),
        255 => (u64::from_le_bytes(bytes(reader)?), 4294967296),
        n => return Ok(u64::from(n)),
    };
    if n < minimum { return Err(invalid("noncanonical CompactSize")); }
    Ok(n)
}

pub fn decompress_amount(mut x: u64) -> io::Result<u64> {
    if x == 0 { return Ok(0); }
    x -= 1;
    let e = (x % 10) as u32;
    x /= 10;
    let n = if e < 9 {
        let d = x % 9 + 1;
        (x / 9).checked_mul(10).and_then(|v| v.checked_add(d))
    } else { x.checked_add(1) };
    n.and_then(|v| v.checked_mul(10u64.pow(e)))
        .ok_or_else(|| invalid("decompressed amount overflow"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Script {
    Raw(Vec<u8>),
    UncompressedP2pk { marker: u8, x: [u8; 32] },
    Oversized { hash: [u8; 32], prefix: [u8; 80] },
}

pub fn decompress_script(reader: &mut impl Read) -> io::Result<Script> {
    let size = varint(reader)?;
    let script = match size {
        0 => {
            let mut s = vec![0x76, 0xa9, 0x14];
            s.extend_from_slice(&bytes::<20>(reader)?);
            s.extend_from_slice(&[0x88, 0xac]);
            s
        }
        1 => {
            let mut s = vec![0xa9, 0x14];
            s.extend_from_slice(&bytes::<20>(reader)?);
            s.push(0x87);
            s
        }
        2 | 3 => {
            let mut s = vec![0x21, size as u8];
            s.extend_from_slice(&bytes::<32>(reader)?);
            s.push(0xac);
            s
        }
        4 | 5 => {
            let x = bytes::<32>(reader)?;
            return Ok(Script::UncompressedP2pk { marker: size as u8, x });
        }
        n => {
            let length = n - 6;
            if length > 10_000 {
                let prefix = bytes::<80>(reader)?;
                let hash = crate::sha256::digest_reader(&mut prefix.as_slice().chain(reader), length)?;
                return Ok(Script::Oversized { hash, prefix });
            }
            let mut s = vec![0; length as usize];
            reader.read_exact(&mut s)?;
            s
        }
    };
    Ok(Script::Raw(script))
}
