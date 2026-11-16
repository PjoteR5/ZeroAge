//! Moduł **Wystawcy (`Issuer`)** zgodny ze standardem **ISO 18013-5 (mDL / MDOC)** oraz
//! architekturą z publikacji Frigo & shelat (*Anonymous Credentials from ECDSA*).
//!
//! Kluczowa zasada projektowa:
//! **Wystawca nie wykonuje żadnej kryptografii ZK** – weryfikuje atestację klucza urządzenia
//! $PK_d$, buduje strukturę `MobileSecurityObject` (`MSO`) w formacie **CBOR** ze skrótami
//! **SHA-256** (`valueDigests`), składa standardowy podpis **ECDSA P-256** (`COSE_Sign1`)
//! i publikuje swój klucz publiczny $PK_{II}$ oraz rejestr unieważnień.

use std::collections::BTreeSet;

use crate::mso::{DeviceKeyInfo, IssuerSignedItem, MobileSecurityObject, ValidityInfo};
use zkp_circuits::age_circuit::AGE_18_SECONDS;
use zkp_circuits::ecdsa_p256::{
    verify_ecdsa_message, verify_ecdsa_prehashed, EcdsaKeyPair, EcdsaSignature, P256Point,
};
use zkp_circuits::sha256::sha256_digest;

/// Dowód atestacji klucza prywatnego urządzenia (Secure Element Proof-of-Possession).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceKeyAttestation {
    pub device_public_key: P256Point,
    pub attestation_challenge: Vec<u8>,
    pub pop_signature: EcdsaSignature,
}

impl DeviceKeyAttestation {
    /// Tworzy nowe oświadczenie atestacyjne podpisane kluczem prywatnym urządzenia w Secure Elemencie.
    pub fn create(device_keypair: &EcdsaKeyPair, challenge: &[u8]) -> Self {
        let mut msg = Vec::with_capacity(24 + challenge.len());
        msg.extend_from_slice(b"ZeroAge-SE-Attestation:");
        msg.extend_from_slice(challenge);
        let pop_signature = device_keypair.sign_message(&msg);

        Self {
            device_public_key: device_keypair.public_key,
            attestation_challenge: challenge.to_vec(),
            pop_signature,
        }
    }

    /// Weryfikuje przez Wystawcę, że klucz publiczny $PK_d$ należy do krzywej NIST P-256
    /// oraz że urządzenie faktycznie dysponuje odpowiadającym mu kluczem prywatnym.
    pub fn verify(&self) -> bool {
        if self.device_public_key.infinity || !self.device_public_key.is_on_curve() {
            return false;
        }
        let mut msg = Vec::with_capacity(24 + self.attestation_challenge.len());
        msg.extend_from_slice(b"ZeroAge-SE-Attestation:");
        msg.extend_from_slice(&self.attestation_challenge);
        verify_ecdsa_message(&self.device_public_key, &msg, &self.pop_signature)
    }
}

/// Pełny pakiet poświadczenia MDOC wydawany na urządzenie użytkownika (portfel).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedMdocCredential {
    pub credential_id: u64,
    pub issuer_id: String,
    pub mso: MobileSecurityObject,
    pub mso_cbor_bytes: Vec<u8>,
    /// Podpis ECDSA P-256 (`r1, s1`) Wystawcy nad `SHA-256(mso_cbor_bytes)`
    pub issuer_signature: EcdsaSignature,
    /// Prywatne elementy atrybutów (`salt`, nazwa, wartość) przechowywane w portfelu użytkownika
    pub signed_items: Vec<IssuerSignedItem>,
    /// Klucz publiczny Wystawcy $PK_{II}$
    pub issuer_public_key: P256Point,
}

impl IssuedMdocCredential {
    /// Weryfikuje autentyczność podpisu ECDSA P-256 Wystawcy nad obiektem MSO oraz zgodność `valueDigests`.
    pub fn verify_issuer_integrity(&self) -> bool {
        let recomputed_cbor = self.mso.to_cbor_bytes();
        if recomputed_cbor != self.mso_cbor_bytes {
            return false;
        }
        let mso_hash = sha256_digest(&self.mso_cbor_bytes);
        if !verify_ecdsa_prehashed(&self.issuer_public_key, &mso_hash, &self.issuer_signature) {
            return false;
        }

        // Sprawdzenie każdego IssuerSignedItem względem mapy valueDigests w MSO
        for item in &self.signed_items {
            match self.mso.find_digest(item.digest_id) {
                Some(expected_digest) => {
                    if item.compute_sha256_digest() != expected_digest {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }

    /// Zwraca element `IssuerSignedItem` o podanym identyfikatorze (np. `"birth_date"`).
    pub fn find_item(&self, element_identifier: &str) -> Option<&IssuerSignedItem> {
        self.signed_items
            .iter()
            .find(|it| it.element_identifier == element_identifier)
    }
}

/// Publiczny rejestr zaufanych wystawców (`PK_II`) oraz aktywnych epok unieważnień,
/// wykorzystywany przez Weryfikatora (Relying Party).
#[derive(Clone, Debug, Default)]
pub struct TrustedIssuerRegistry {
    pub trusted_keys: Vec<(String, P256Point)>,
    pub active_revocation_epoch: u64,
    pub revoked_credential_ids: BTreeSet<u64>,
}

impl TrustedIssuerRegistry {
    pub fn new() -> Self {
        Self {
            trusted_keys: Vec::new(),
            active_revocation_epoch: 1,
            revoked_credential_ids: BTreeSet::new(),
        }
    }

    pub fn register_issuer(&mut self, issuer_id: &str, pk_ii: P256Point) {
        self.trusted_keys.push((issuer_id.to_string(), pk_ii));
    }

    pub fn is_trusted_key(&self, pk: &P256Point) -> bool {
        self.trusted_keys.iter().any(|(_, k)| k == pk)
    }
}

/// Węzeł Wystawcy (`StateIssuer`, np. państwowy urząd wydający mDowód / mDL).
pub struct StateIssuer {
    pub issuer_id: String,
    pub keypair: EcdsaKeyPair,
    pub active_revocation_epoch: u64,
    pub revoked_credential_ids: BTreeSet<u64>,
    next_credential_id: u64,
}

impl StateIssuer {
    /// Inicjalizuje nowego Wystawcę z deterministycznego lub losowego ziarna klucza P-256.
    pub fn new(issuer_id: &str, key_seed: &[u8]) -> Self {
        Self {
            issuer_id: issuer_id.to_string(),
            keypair: EcdsaKeyPair::from_seed(key_seed),
            active_revocation_epoch: 1,
            revoked_credential_ids: BTreeSet::new(),
            next_credential_id: 1,
        }
    }

    /// Zwraca publiczny klucz Wystawcy $PK_{II}$ na krzywej NIST P-256.
    pub fn public_key(&self) -> P256Point {
        self.keypair.public_key
    }

    /// Eksportuje aktualny stan zaufanego rejestru dla Weryfikatorów.
    pub fn export_registry(&self) -> TrustedIssuerRegistry {
        let mut reg = TrustedIssuerRegistry::new();
        reg.register_issuer(&self.issuer_id, self.keypair.public_key);
        reg.active_revocation_epoch = self.active_revocation_epoch;
        reg.revoked_credential_ids = self.revoked_credential_ids.clone();
        reg
    }

    /// Wydaje podpisane kluczem ECDSA P-256 poświadczenie MDOC/MSO po weryfikacji atestacji urządzenia.
    pub fn issue_credential(
        &mut self,
        holder_label: &str,
        dob_timestamp: u64,
        signed_at: u64,
        valid_from: u64,
        valid_until: u64,
        attestation: &DeviceKeyAttestation,
    ) -> Result<IssuedMdocCredential, &'static str> {
        if holder_label.trim().is_empty() {
            return Err("Brak identyfikatora podmiotu podczas weryfikacji tożsamości KYC");
        }
        if valid_until < valid_from {
            return Err("Nieprawidłowy okres ważności: valid_until < valid_from");
        }
        if !attestation.verify() {
            return Err("Weryfikacja atestacji klucza urządzenia PK_d (Secure Element) nie powiodła się");
        }

        let credential_id = self.next_credential_id;
        self.next_credential_id += 1;

        // Generujemy kryptograficzne sole `random` (16B) dla każdego atrybutu w MSO
        let salt_dob = self.derive_attribute_salt(credential_id, 0, holder_label);
        let salt_age_flag = self.derive_attribute_salt(credential_id, 1, holder_label);

        let is_over_18 = if signed_at >= dob_timestamp + AGE_18_SECONDS {
            1u64
        } else {
            0u64
        };

        let item_dob = IssuerSignedItem {
            digest_id: 0,
            random_salt: salt_dob,
            element_identifier: "birth_date".to_string(),
            element_value: dob_timestamp,
        };
        let item_age_over_18 = IssuerSignedItem {
            digest_id: 1,
            random_salt: salt_age_flag,
            element_identifier: "age_over_18".to_string(),
            element_value: is_over_18,
        };

        let value_digests = vec![
            (0, item_dob.compute_sha256_digest()),
            (1, item_age_over_18.compute_sha256_digest()),
        ];

        let mso = MobileSecurityObject {
            version: "1.0".to_string(),
            digest_algorithm: "SHA-256".to_string(),
            doc_type: "org.iso.18013.5.1.mDL".to_string(),
            value_digests,
            device_key_info: DeviceKeyInfo {
                device_public_key: attestation.device_public_key,
            },
            validity_info: ValidityInfo {
                signed: signed_at,
                valid_from,
                valid_until,
            },
            revocation_epoch: self.active_revocation_epoch,
        };

        let mso_cbor_bytes = mso.to_cbor_bytes();
        let mso_digest = sha256_digest(&mso_cbor_bytes);
        let issuer_signature = self.keypair.sign_prehashed(&mso_digest);

        Ok(IssuedMdocCredential {
            credential_id,
            issuer_id: self.issuer_id.clone(),
            mso,
            mso_cbor_bytes,
            issuer_signature,
            signed_items: vec![item_dob, item_age_over_18],
            issuer_public_key: self.keypair.public_key,
        })
    }

    /// Unieważnia poświadczenie o podanym `credential_id` i inkrementuje aktywną epokę odwołań.
    pub fn revoke_credential(&mut self, credential_id: u64) -> u64 {
        self.revoked_credential_ids.insert(credential_id);
        self.active_revocation_epoch += 1;
        self.active_revocation_epoch
    }

    fn derive_attribute_salt(&self, cred_id: u64, digest_id: u32, label: &str) -> [u8; 16] {
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(b"ZeroAge-Issuer-Attr-Salt:");
        seed.extend_from_slice(&cred_id.to_be_bytes());
        seed.extend_from_slice(&digest_id.to_be_bytes());
        seed.extend_from_slice(label.as_bytes());
        let hash = sha256_digest(&seed);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&hash[..16]);
        salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issuer_mints_valid_cbor_mso_and_verifies_ecdsa_p256() {
        let mut issuer = StateIssuer::new("PL-Gov-mObywatel-CA", b"issuer-secret-seed-01");
        let device_kp = EcdsaKeyPair::from_seed(b"user-phone-secure-element-01");

        let attestation = DeviceKeyAttestation::create(&device_kp, b"enroll-nonce-2026");
        assert!(attestation.verify());

        let t_now = 1_794_064_800u64;
        let dob = t_now - (21 * 365 + 5) * 86_400;
        let cred = issuer
            .issue_credential(
                "Jan Kowalski",
                dob,
                t_now,
                t_now - 3600,
                t_now + 86_400 * 365,
                &attestation,
            )
            .expect("Wydanie poświadczenia dla poprawnej atestacji musi się powieść");

        assert!(cred.verify_issuer_integrity());
        assert_eq!(cred.mso.digest_algorithm, "SHA-256");
        assert_eq!(cred.mso.value_digests.len(), 2);

        // Kompaktowy format 183-bajtowy (Alg. 9)
        let compact = cred.mso.to_compact_183_bytes(dob);
        assert_eq!(compact.len(), 183);
    }

    #[test]
    fn test_issuer_rejects_forged_device_attestation() {
        let mut issuer = StateIssuer::new("PL-Gov-mObywatel-CA", b"issuer-secret-seed-01");
        let real_device = EcdsaKeyPair::from_seed(b"real-device");
        let rogue_device = EcdsaKeyPair::from_seed(b"rogue-device");

        let mut bad_attestation = DeviceKeyAttestation::create(&rogue_device, b"challenge");
        // Podmieniamy klucz publiczny na cudzy bez ważnego podpisu PoP
        bad_attestation.device_public_key = real_device.public_key;

        let res = issuer.issue_credential(
            "Atakujący",
            1_000_000_000,
            1_794_064_800,
            1_794_000_000,
            1_800_000_000,
            &bad_attestation,
        );
        assert!(res.is_err());
    }
}
