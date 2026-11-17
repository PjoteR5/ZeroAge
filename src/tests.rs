#[cfg(test)]
mod tests {
    use crate::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // --- Oficjalne wektory testowe (NIST) ---

    #[test]
    fn empty_string() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn two_blocks() {
        // 56 bajtów: padding nie mieści się w jednym bloku
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            hex(&sha256(msg)),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    #[ignore] // wolny w trybie debug; uruchom: cargo test -- --ignored
    fn million_a() {
        let msg = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha256(&msg)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    // --- Testy wewnętrznej funkcji pad ---

    #[test]
    fn padding_lengths() {
        // (długość wejścia, oczekiwana długość po paddingu)
        let cases = [(0, 64), (55, 64), (56, 128), (63, 128), (64, 128), (119, 128), (120, 192)];
        for (len, expected) in cases {
            let padded = pad(&vec![0u8; len]);
            assert_eq!(padded.len(), expected, "wejście o długości {len}");
        }
    }

    #[test]
    fn padding_structure() {
        let padded = pad(b"abc");
        assert_eq!(padded[3], 0x80);                         // bit "1" zaraz po danych
        assert!(padded[4..56].iter().all(|&b| b == 0));      // same zera
        assert_eq!(&padded[56..], &24u64.to_be_bytes());     // 3 bajty = 24 bity
    }

    // --- Porównanie z referencyjną implementacją ---

    #[test]
    fn matches_sha2_crate() {
        use sha2::{Digest, Sha256};
        for len in 0..300 {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let expected = Sha256::digest(&msg);
            assert_eq!(sha256(&msg)[..], expected[..], "długość {len}");
        }
    }
}