// Public-data validation only; this arithmetic is not constant-time.
type Field = [u64; 4];
const P: Field = [0xfffffffefffffc2f, u64::MAX, u64::MAX, u64::MAX];
const C: u64 = 0x1000003d1;

fn ge(a: Field, b: Field) -> bool { a.iter().rev().cmp(b.iter().rev()).is_ge() }

fn add_word(t: &mut [u64; 9], mut i: usize, mut value: u64) {
    while value != 0 {
        let (word, carry) = t[i].overflowing_add(value);
        t[i] = word;
        value = u64::from(carry);
        i += 1;
    }
}

fn reduce(mut t: [u64; 9]) -> Field {
    // Fold 2^256 into 2^32 + 977 until only four limbs remain.
    while t[4..].iter().any(|&v| v != 0) {
        for i in (4..9).rev() {
            let v = u128::from(t[i]) * u128::from(C);
            t[i] = 0;
            add_word(&mut t, i - 4, v as u64);
            add_word(&mut t, i - 3, (v >> 64) as u64);
        }
    }
    let mut a = [t[0], t[1], t[2], t[3]];
    if ge(a, P) {
        let mut borrow = false;
        for i in 0..4 {
            let (v, b1) = a[i].overflowing_sub(P[i]);
            let (v, b2) = v.overflowing_sub(u64::from(borrow));
            a[i] = v;
            borrow = b1 || b2;
        }
    }
    a
}

fn mul(a: Field, b: Field) -> Field {
    let mut t = [0; 9];
    for i in 0..4 {
        for j in 0..4 {
            let v = u128::from(a[i]) * u128::from(b[j]);
            add_word(&mut t, i + j, v as u64);
            add_word(&mut t, i + j + 1, (v >> 64) as u64);
        }
    }
    reduce(t)
}

fn decode(bytes: &[u8]) -> Option<Field> {
    if bytes.len() != 32 { return None; }
    let mut a = [0; 4];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        a[3 - i] = u64::from_be_bytes(chunk.try_into().ok()?);
    }
    if ge(a, P) { None } else { Some(a) }
}

fn rhs(x: Field) -> Field {
    let x3 = mul(mul(x, x), x);
    let mut t = [0; 9];
    t[..4].copy_from_slice(&x3);
    add_word(&mut t, 0, 7);
    reduce(t)
}

pub fn lift_x(bytes: &[u8]) -> bool {
    let Some(x) = decode(bytes) else { return false; };
    let c = rhs(x);
    let exponent: Field = [0xffffffffbfffff0c, u64::MAX, u64::MAX, 0x3fffffffffffffff];
    let mut y = [1, 0, 0, 0];
    for bit in (0..254).rev() {
        y = mul(y, y);
        if (exponent[bit / 64] >> (bit % 64)) & 1 != 0 { y = mul(y, c); }
    }
    mul(y, y) == c
}

pub fn pubkey(bytes: &[u8]) -> bool {
    match bytes {
        [2 | 3, x @ ..] if x.len() == 32 => lift_x(x),
        [4, xy @ ..] if xy.len() == 64 => {
            match (decode(&xy[..32]), decode(&xy[32..])) {
                (Some(x), Some(y)) => mul(y, y) == rhs(x),
                _ => false,
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    #[test]
    fn generator_and_multiples() {
        for (x, y) in [
            ("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
            ("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
            ("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"),
        ] {
            let x = unhex(x);
            assert!(lift_x(&x));
            for tag in [2, 3] { assert!(pubkey(&[vec![tag], x.clone()].concat())); }
            let mut raw = [vec![4], x, unhex(y)].concat();
            assert!(pubkey(&raw));
            raw[64] ^= 1;
            assert!(!pubkey(&raw));
        }
        assert!(!lift_x(&[0; 32]));
        assert!(!lift_x(&[255; 32]));
        assert!(decode(&unhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")).is_none());
        let minus_one = [P[0] - 1, P[1], P[2], P[3]];
        assert_eq!(mul(minus_one, minus_one), [1, 0, 0, 0]);
        assert_eq!(mul([0; 4], minus_one), [0; 4]);
    }
    #[test]
    fn modular_product_vectors() {
        // Expected products computed independently with integer modular arithmetic.
        for (a, b, expected) in [
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e", "0000000000000000000000000000000000000000000000000000000000000001"),
            ("8000000000000000000000000000000000000000000000000000000000000000", "8000000000000000000000000000000000000000000000000000000000000000", "400000000000000000000000000000000000000000000000400001e84003a334"),
            ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d", "0000000000000001000000000000000000000000000000000000000000000001", "fffffffffffffffdfffffffffffffffffffffffffffffffffffffffefffffc2d"),
            ("8accebe7ccb427d2dbc829f987344543fcf18a73184baddd93383dc666662e03", "85521966b3344ea6381cd1a3503d8b1b2dadec2b46a4b4f191076f5e1e68fb10", "d74ba63bf1ab85e8ad765b44dbe027e920d08270b4b62e676ae5e5697601cd00"),
            ("748e38a9f87ab9f28feb8a5b27a4470b4cf213464133b7068c2f6a55fa10dab8", "06cfe31508e46fbc02dcd6f18dd168ca44e38da8467d759320d37021cf282ded", "0ebd5dbadd25b27cf9dd6d4f799e72aaf496684b611b0c770779aa0da3912e0c"),
            ("3a448d5241aac64231d6bc8b2207ef8952f513567d19495c2a1a87620b271710", "d10e39886d684e61e1026df428b78df842d3b0354d2752e525c93fa57af9d7a3", "f9f641c0f9d6a2a57551ba414b96a55ccc1a9af60b868183d88ad83bdc27ab40"),
            ("24f6d0b831dde35191cdb2828af0351df50752b62632a1ef94064e85a7a3083e", "968bb1b0021c5cc7288f465cbfce60143e018acee5880af2cbfbd74b0efb1f3d", "fbfb01862cf0615b3672228f008a443bce64a2b8575675514c063737ea8c2727"),
            ("2ce8fe421aa4e91a449a5d838592a8e36d1cfbcc274f14857c5e7116341dcf5c", "6bbfbe4dde3aa1ecfaff6aaaf8608fd3f28a92fad403715500953f0d79341aa2", "88b645b5e5aee2dbaa3a3239b25ce435cddf2dab3c617c9a0ab934ef8295e2a2"),
        ] {
            assert_eq!(mul(decode(&unhex(a)).unwrap(), decode(&unhex(b)).unwrap()), decode(&unhex(expected)).unwrap());
        }
    }

}
