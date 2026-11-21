use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zkp_circuits::ecdsa_p256::{EcdsaSignature, Fr256, P256Point};
use zkp_core::field::Fp256;
use zkp_core::merkle::MerkleProof;
use zkp_core::protocol25::{MaskedRoundPoly, MaskedTranscript};

/// Koduje plaster bajtów do łańcucha szesnastkowego (małe litery hex).
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Dekoduje łańcuch szesnastkowy (z opcjonalnym prefiksem `0x`) do wektora bajtów.
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim();
    let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex_str.len() % 2 != 0 {
        return Err("Łańcuch szesnastkowy musi mieć parzystą liczbę znaków".to_string());
    }
    let mut out = Vec::with_capacity(hex_str.len() / 2);
    let raw = hex_str.as_bytes();
    for i in (0..raw.len()).step_by(2) {
        let hi = hex_nibble(raw[i])?;
        let lo = hex_nibble(raw[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("Nieprawidłowy znak hex: {}", b as char)),
    }
}

pub fn field_to_hex<T: CanonicalSerialize>(val: &T) -> Result<String, String> {
    let mut bytes = Vec::new();
    val.serialize_compressed(&mut bytes)
        .map_err(|e| format!("Błąd serializacji kanonicznej: {e}"))?;
    Ok(bytes_to_hex(&bytes))
}

pub fn hex_to_field<T: CanonicalDeserialize>(s: &str) -> Result<T, String> {
    let bytes = hex_to_bytes(s)?;
    T::deserialize_compressed(bytes.as_slice())
        .map_err(|e| format!("Błąd deserializacji kanonicznej: {e}"))
}

pub mod hex16 {
    use super::*;

    pub fn serialize<S: Serializer>(val: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&bytes_to_hex(val))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex_to_bytes(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Oczekiwano dokładnie 16 bajtów (32 znaki hex)"))
    }
}

pub mod hex32 {
    use super::*;

    pub fn serialize<S: Serializer>(val: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&bytes_to_hex(val))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex_to_bytes(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("Oczekiwano dokładnie 32 bajtów (64 znaki hex)"))
    }
}

pub mod fp256_vec {
    use super::*;

    pub fn serialize<S: Serializer>(vals: &[Fp256], serializer: S) -> Result<S::Ok, S::Error> {
        let hexes: Vec<String> = vals
            .iter()
            .map(field_to_hex)
            .collect::<Result<_, _>>()
            .map_err(serde::ser::Error::custom)?;
        hexes.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Fp256>, D::Error> {
        let hexes = Vec::<String>::deserialize(deserializer)?;
        hexes
            .iter()
            .map(|s| hex_to_field::<Fp256>(s))
            .collect::<Result<_, _>>()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
struct P256PointDto {
    x: String,
    y: String,
    infinity: bool,
}

pub mod p256_point {
    use super::*;

    pub fn serialize<S: Serializer>(pt: &P256Point, serializer: S) -> Result<S::Ok, S::Error> {
        let dto = P256PointDto {
            x: field_to_hex(&pt.x).map_err(serde::ser::Error::custom)?,
            y: field_to_hex(&pt.y).map_err(serde::ser::Error::custom)?,
            infinity: pt.infinity,
        };
        dto.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<P256Point, D::Error> {
        let dto = P256PointDto::deserialize(deserializer)?;
        let x = hex_to_field::<Fp256>(&dto.x).map_err(serde::de::Error::custom)?;
        let y = hex_to_field::<Fp256>(&dto.y).map_err(serde::de::Error::custom)?;
        Ok(P256Point {
            x,
            y,
            infinity: dto.infinity,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct EcdsaSignatureDto {
    r: String,
    s: String,
    #[serde(with = "p256_point")]
    r_point: P256Point,
}

pub mod ecdsa_sig {
    use super::*;

    pub fn serialize<S: Serializer>(sig: &EcdsaSignature, serializer: S) -> Result<S::Ok, S::Error> {
        let dto = EcdsaSignatureDto {
            r: field_to_hex(&sig.r).map_err(serde::ser::Error::custom)?,
            s: field_to_hex(&sig.s).map_err(serde::ser::Error::custom)?,
            r_point: sig.r_point,
        };
        dto.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EcdsaSignature, D::Error> {
        let dto = EcdsaSignatureDto::deserialize(deserializer)?;
        let r = hex_to_field::<Fr256>(&dto.r).map_err(serde::de::Error::custom)?;
        let s = hex_to_field::<Fr256>(&dto.s).map_err(serde::de::Error::custom)?;
        Ok(EcdsaSignature {
            r,
            s,
            r_point: dto.r_point,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct MaskedRoundPolyDto {
    eval_0: String,
    eval_1: String,
    eval_2: String,
}

#[derive(Serialize, Deserialize)]
struct MaskedTranscriptDto {
    rounds: Vec<MaskedRoundPolyDto>,
    masked_w_l: String,
    masked_w_r: String,
}

pub mod masked_transcript {
    use super::*;

    pub fn serialize<S: Serializer>(
        tr: &MaskedTranscript<Fp256>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let rounds = tr
            .rounds
            .iter()
            .map(|r| {
                Ok(MaskedRoundPolyDto {
                    eval_0: field_to_hex(&r.eval_0)?,
                    eval_1: field_to_hex(&r.eval_1)?,
                    eval_2: field_to_hex(&r.eval_2)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(serde::ser::Error::custom)?;

        let dto = MaskedTranscriptDto {
            rounds,
            masked_w_l: field_to_hex(&tr.masked_w_l).map_err(serde::ser::Error::custom)?,
            masked_w_r: field_to_hex(&tr.masked_w_r).map_err(serde::ser::Error::custom)?,
        };
        dto.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<MaskedTranscript<Fp256>, D::Error> {
        let dto = MaskedTranscriptDto::deserialize(deserializer)?;
        let rounds = dto
            .rounds
            .iter()
            .map(|r| {
                Ok(MaskedRoundPoly {
                    eval_0: hex_to_field::<Fp256>(&r.eval_0)?,
                    eval_1: hex_to_field::<Fp256>(&r.eval_1)?,
                    eval_2: hex_to_field::<Fp256>(&r.eval_2)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(serde::de::Error::custom)?;

        Ok(MaskedTranscript {
            rounds,
            masked_w_l: hex_to_field::<Fp256>(&dto.masked_w_l)
                .map_err(serde::de::Error::custom)?,
            masked_w_r: hex_to_field::<Fp256>(&dto.masked_w_r)
                .map_err(serde::de::Error::custom)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct LigeroOpeningDto {
    column_index: usize,
    #[serde(with = "fp256_vec")]
    column_values: Vec<Fp256>,
    merkle_path: Vec<String>,
}

pub mod ligero_openings {
    use super::*;

    pub fn serialize<S: Serializer>(
        openings: &[(usize, Vec<Fp256>, MerkleProof)],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let dtos: Vec<LigeroOpeningDto> = openings
            .iter()
            .map(|(idx, vals, proof)| LigeroOpeningDto {
                column_index: *idx,
                column_values: vals.clone(),
                merkle_path: proof.path.iter().map(|h| bytes_to_hex(h)).collect(),
            })
            .collect();
        dtos.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<(usize, Vec<Fp256>, MerkleProof)>, D::Error> {
        let dtos = Vec::<LigeroOpeningDto>::deserialize(deserializer)?;
        let mut out = Vec::with_capacity(dtos.len());
        for dto in dtos {
            let mut path = Vec::with_capacity(dto.merkle_path.len());
            for h in dto.merkle_path {
                let bytes = hex_to_bytes(&h).map_err(serde::de::Error::custom)?;
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    serde::de::Error::custom("Węzeł ścieżki Merkle'a musi mieć 32 bajty")
                })?;
                path.push(arr);
            }
            out.push((
                dto.column_index,
                dto.column_values,
                MerkleProof::new(dto.column_index, path),
            ));
        }
        Ok(out)
    }
}
