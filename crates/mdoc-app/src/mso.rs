//! Model danych poświadczenia **ISO 18013-5 MDOC (`MobileSecurityObject` – MSO)**,
//! deterministyczny koder **CBOR (RFC 8949)** oraz kompaktowy 183-bajtowy format (Algorytm 9)
//! zgodny z publikacją Frigo & shelat (*Anonymous Credentials from ECDSA*).

use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use zkp_circuits::ecdsa_p256::P256Point;
use zkp_circuits::sha256::sha256_digest;
use zkp_core::field::Fp256;

/// Pojedynczy atrybut podpisany przez Wystawcę (`IssuerSignedItem` w standardzie ISO 18013-5):
/// jego skrót `SHA-256(CBOR(IssuerSignedItem))` trafia do mapy `valueDigests` wewnątrz `MSO`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerSignedItem {
    /// Identyfikator skrótu w mapie `valueDigests` (np. `0` dla `birth_date`, `1` dla `age_over_18`)
    pub digest_id: u32,
    /// Losowa sól 16-bajtowa (`random`) uniemożliwiająca atak słownikowy na skrót SHA-256 atrybutu
    pub random_salt: [u8; 16],
    /// Nazwa atrybutu (np. `"birth_date"`, `"age_over_18"`, `"document_number"`)
    pub element_identifier: String,
    /// Wartość atrybutu zakodowana jako liczba całkowita (np. `dob_timestamp` lub `1`/`0`)
    pub element_value: u64,
}

impl IssuerSignedItem {
    /// Koduje strukturę `IssuerSignedItem` deterministycznie do formatu **CBOR (RFC 8949)**
    /// jako 4-elementową mapę: `{"digestID": u32, "random": bstr, "elementIdentifier": tstr, "elementValue": uint}`.
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(96);
        // Mapa CBOR o 4 parach klucz-wartość (Major Type 5: 0xa4)
        buf.push(0xa4);

        // 1. "digestID" -> uint
        cbor_encode_tstr(&mut buf, "digestID");
        cbor_encode_uint(&mut buf, self.digest_id as u64);

        // 2. "random" -> bstr(16)
        cbor_encode_tstr(&mut buf, "random");
        cbor_encode_bstr(&mut buf, &self.random_salt);

        // 3. "elementIdentifier" -> tstr
        cbor_encode_tstr(&mut buf, "elementIdentifier");
        cbor_encode_tstr(&mut buf, &self.element_identifier);

        // 4. "elementValue" -> uint
        cbor_encode_tstr(&mut buf, "elementValue");
        cbor_encode_uint(&mut buf, self.element_value);

        buf
    }

    /// Wylicza 32-bajtowy skrót `SHA-256` zakodowanego w CBOR elementu `IssuerSignedItem`.
    pub fn compute_sha256_digest(&self) -> [u8; 32] {
        let cbor = self.to_cbor_bytes();
        sha256_digest(&cbor)
    }

    /// Mapuje 32-bajtowy skrót `SHA-256` atrybutu na element ciała $\mathbb{F}_{p_{256}}$ (do wiązania w obwodzie ZKP).
    pub fn compute_digest_field_element(&self) -> Fp256 {
        let digest = self.compute_sha256_digest();
        Fp256::from_be_bytes_mod_order(&digest)
    }
}

/// Informacje o ważności czasowej poświadczenia (`validityInfo` w MSO).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidityInfo {
    pub signed: u64,
    pub valid_from: u64,
    pub valid_until: u64,
}

/// Informacje o kluczu publicznym urządzenia użytkownika (`deviceKeyInfo` w MSO)
/// związanym z Secure Elementem telefonu/portfela.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceKeyInfo {
    pub device_public_key: P256Point,
}

/// Główna struktura **Mobile Security Object (`MSO`)** podpisywana przez Wystawcę kluczem ECDSA P-256.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MobileSecurityObject {
    pub version: String,
    pub digest_algorithm: String,
    pub doc_type: String,
    /// Lista par `(digestID, SHA-256(CBOR(IssuerSignedItem)))`
    pub value_digests: Vec<(u32, [u8; 32])>,
    pub device_key_info: DeviceKeyInfo,
    pub validity_info: ValidityInfo,
    pub revocation_epoch: u64,
}

impl MobileSecurityObject {
    /// Koduje cały obiekt `MobileSecurityObject` deterministycznie do formatu **CBOR (RFC 8949)**.
    /// To dokładnie nad `SHA-256(mso.to_cbor_bytes())` Wystawca składa podpis `ECDSA P-256` (`COSE_Sign1`).
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        // Mapa CBOR o 7 parach klucz-wartość (0xa7)
        buf.push(0xa7);

        cbor_encode_tstr(&mut buf, "version");
        cbor_encode_tstr(&mut buf, &self.version);

        cbor_encode_tstr(&mut buf, "digestAlgorithm");
        cbor_encode_tstr(&mut buf, &self.digest_algorithm);

        cbor_encode_tstr(&mut buf, "docType");
        cbor_encode_tstr(&mut buf, self.doc_type_or_default());

        // valueDigests jako mapa CBOR: digestID -> 32-bajtowy bstr
        cbor_encode_tstr(&mut buf, "valueDigests");
        cbor_encode_map_header(&mut buf, self.value_digests.len());
        for (id, digest) in &self.value_digests {
            cbor_encode_uint(&mut buf, *id as u64);
            cbor_encode_bstr(&mut buf, digest);
        }

        // deviceKeyInfo: współrzędne (x, y) klucza P-256 urządzenia
        cbor_encode_tstr(&mut buf, "deviceKeyInfo");
        buf.push(0xa2);
        cbor_encode_tstr(&mut buf, "x");
        cbor_encode_bstr(&mut buf, &fp256_to_be_bytes(&self.device_key_info.device_public_key.x));
        cbor_encode_tstr(&mut buf, "y");
        cbor_encode_bstr(&mut buf, &fp256_to_be_bytes(&self.device_key_info.device_public_key.y));

        // validityInfo
        cbor_encode_tstr(&mut buf, "validityInfo");
        buf.push(0xa3);
        cbor_encode_tstr(&mut buf, "signed");
        cbor_encode_uint(&mut buf, self.validity_info.signed);
        cbor_encode_tstr(&mut buf, "validFrom");
        cbor_encode_uint(&mut buf, self.validity_info.valid_from);
        cbor_encode_tstr(&mut buf, "validUntil");
        cbor_encode_uint(&mut buf, self.validity_info.valid_until);

        // revocationEpoch
        cbor_encode_tstr(&mut buf, "revocationEpoch");
        cbor_encode_uint(&mut buf, self.revocation_epoch);

        buf
    }

    fn doc_type_or_default(&self) -> &str {
        if self.doc_type.is_empty() {
            "org.iso.18013.5.1.mDL"
        } else {
            &self.doc_type
        }
    }

    /// Oblicza 32-bajtowy skrót `SHA-256` nad kanoniczną reprezentacją CBOR obiektu `MSO`.
    pub fn compute_mso_sha256(&self) -> [u8; 32] {
        sha256_digest(&self.to_cbor_bytes())
    }

    /// Koduje kompaktowy **183-bajtowy format poświadczenia (Algorytm 9 z pracy Frigo & shelat)**,
    /// używany do szybkiego prototypowania obwodów SHA-256 (dokładnie 3 bloki 64-bajtowe po dopełnieniu).
    pub fn to_compact_183_bytes(&self, dob_timestamp: u64) -> [u8; 183] {
        let mut out = [0u8; 183];
        out[0] = 0x01; // Wersja formatu Alg. 9
        out[1..9].copy_from_slice(&dob_timestamp.to_be_bytes());
        out[9..17].copy_from_slice(&self.validity_info.valid_from.to_be_bytes());
        out[17..25].copy_from_slice(&self.validity_info.valid_until.to_be_bytes());
        out[25..33].copy_from_slice(&self.revocation_epoch.to_be_bytes());
        out[33..65].copy_from_slice(&fp256_to_be_bytes(&self.device_key_info.device_public_key.x));
        out[65..97].copy_from_slice(&fp256_to_be_bytes(&self.device_key_info.device_public_key.y));

        if let Some((_, first_digest)) = self.value_digests.first() {
            out[97..129].copy_from_slice(first_digest);
        }
        let doc_bytes = self.doc_type_or_default().as_bytes();
        let copy_len = doc_bytes.len().min(54);
        out[129..129 + copy_len].copy_from_slice(&doc_bytes[..copy_len]);
        out
    }

    /// Wyszukuje 32-bajtowy skrót SHA-256 w `valueDigests` dla podanego `digest_id`.
    pub fn find_digest(&self, digest_id: u32) -> Option<[u8; 32]> {
        self.value_digests
            .iter()
            .find(|(id, _)| *id == digest_id)
            .map(|(_, d)| *d)
    }
}

// ===========================================================================
// Deterministyczne funkcje pomocnicze kodera CBOR (RFC 8949)
// ===========================================================================

fn fp256_to_be_bytes(val: &Fp256) -> [u8; 32] {
    let bigint = val.into_bigint();
    let mut out = [0u8; 32];
    for (i, limb) in bigint.0.iter().rev().enumerate() {
        out[8 * i..8 * (i + 1)].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn cbor_encode_type_and_len(buf: &mut Vec<u8>, major_type: u8, val: u64) {
    let mt = major_type << 5;
    if val < 24 {
        buf.push(mt | (val as u8));
    } else if val <= u8::MAX as u64 {
        buf.push(mt | 24);
        buf.push(val as u8);
    } else if val <= u16::MAX as u64 {
        buf.push(mt | 25);
        buf.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= u32::MAX as u64 {
        buf.push(mt | 26);
        buf.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        buf.push(mt | 27);
        buf.extend_from_slice(&val.to_be_bytes());
    }
}

fn cbor_encode_uint(buf: &mut Vec<u8>, val: u64) {
    cbor_encode_type_and_len(buf, 0, val);
}

fn cbor_encode_bstr(buf: &mut Vec<u8>, bytes: &[u8]) {
    cbor_encode_type_and_len(buf, 2, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn cbor_encode_tstr(buf: &mut Vec<u8>, text: &str) {
    let bytes = text.as_bytes();
    cbor_encode_type_and_len(buf, 3, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn cbor_encode_map_header(buf: &mut Vec<u8>, len: usize) {
    cbor_encode_type_and_len(buf, 5, len as u64);
}
