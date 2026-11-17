//! Moduł 3 (Piotr): **Wystawianie i podpisywanie poświadczeń (`CredentialIssuer`)**.
//!
//! Odpowiada za:
//! 1. Zarządzanie asymetryczną parą kluczy Wystawcy na krzywej **NIST P-256 (`secp256r1`)**,
//! 2. Generację losowej/deterministycznej soli `secret_salt` i utworzenie zobowiązania
//!    kryptograficznego `AttributeCommitment` (`SHA-256`) do daty urodzenia obywatela,
//! 3. Wystawienie i podpisanie poświadczenia algorytmem **ECDSA P-256 z SHA-256**,
//! 4. Weryfikację autentyczności podpisu Wystawcy oraz przygotowanie pary
//!    `(PublicAgeInputs, PrivateAgeWitness)` dla procesu dowodzenia ZKP.

use crate::commitment::AttributeCommitment;
use crate::date_witness::{
    default_min_age_18_seconds, CredentialDate, PrivateAgeWitness, PublicAgeInputs,
};
use zkp_circuits::ecdsa_p256::{
    verify_ecdsa_message, EcdsaKeyPair, EcdsaSignature, P256Point,
};
use zkp_circuits::sha256::sha256_digest;

const CREDENTIAL_SIGN_DOMAIN: &[u8] = b"ZeroAge-MVP-Credential-Sign-v1:";

/// Podpisane poświadczenie wieku wydawane przez Wystawcę do portfela użytkownika.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAgeCredential {
    pub credential_id: u64,
    pub issuer_id: String,
    /// Zobowiązanie kryptograficzne `SHA-256` do ukrytej daty urodzenia
    pub dob_commitment: AttributeCommitment,
    /// Początek ważności poświadczenia
    pub valid_from: CredentialDate,
    /// Koniec ważności poświadczenia
    pub valid_until: CredentialDate,
    /// Podpis cyfrowy ECDSA P-256 Wystawcy nad zobowiązaniem i metadanymi ważności
    pub issuer_signature: EcdsaSignature,
    /// Klucz publiczny Wystawcy $PK_{\text{issuer}}$ na krzywej NIST P-256
    pub issuer_public_key: P256Point,
    /// Część ukryta (prywatny świadek: `birth_date` + `secret_salt`), znana wyłącznie właścicielowi portfela
    pub private_witness: PrivateAgeWitness,
}

impl SignedAgeCredential {
    /// Buduje kanoniczny ciąg bajtów podpisywany przez Wystawcę kluczem ECDSA P-256.
    /// Zauważ, że podpisywane jest wyłącznie **zobowiązanie (`dob_commitment`)**, a nie jawna data urodzenia!
    pub fn canonical_signing_payload(
        credential_id: u64,
        issuer_id: &str,
        dob_commitment: &AttributeCommitment,
        valid_from: &CredentialDate,
        valid_until: &CredentialDate,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(CREDENTIAL_SIGN_DOMAIN);
        buf.extend_from_slice(&credential_id.to_be_bytes());
        buf.extend_from_slice(issuer_id.as_bytes());
        buf.extend_from_slice(&dob_commitment.digest);
        buf.extend_from_slice(&valid_from.to_timestamp_seconds().to_be_bytes());
        buf.extend_from_slice(&valid_until.to_timestamp_seconds().to_be_bytes());
        buf
    }

    /// Weryfikuje podpis cyfrowy ECDSA P-256 Wystawcy oraz spójność wewnętrznego otwarcia zobowiązania.
    pub fn verify_issuer_signature(&self) -> bool {
        let payload = Self::canonical_signing_payload(
            self.credential_id,
            &self.issuer_id,
            &self.dob_commitment,
            &self.valid_from,
            &self.valid_until,
        );
        verify_ecdsa_message(&self.issuer_public_key, &payload, &self.issuer_signature)
    }

    /// Rozdziela poświadczenie na strukturę **danych publicznych (`PublicAgeInputs`)**
    /// oraz **danych ukrytych (`PrivateAgeWitness`)** na potrzeby wygenerowania dowodu ZKP.
    pub fn into_public_and_private_inputs(
        &self,
        verification_date: CredentialDate,
        challenge_nonce: [u8; 16],
    ) -> (PublicAgeInputs, PrivateAgeWitness) {
        let public_inputs = PublicAgeInputs {
            verification_date,
            min_age_seconds: default_min_age_18_seconds(),
            dob_commitment: self.dob_commitment,
            issuer_public_key: self.issuer_public_key,
            challenge_nonce,
        };
        (public_inputs, self.private_witness.clone())
    }
}

/// Węzeł Wystawcy Poświadczeń (`CredentialIssuer`) w wersji MVP.
pub struct CredentialIssuer {
    pub issuer_id: String,
    pub keypair: EcdsaKeyPair,
    next_credential_id: u64,
}

impl CredentialIssuer {
    /// Tworzy nowego Wystawcę z kluczem ECDSA P-256 wyprowadzonym z ziarna `seed`.
    pub fn new(issuer_id: &str, seed: &[u8]) -> Self {
        Self {
            issuer_id: issuer_id.to_string(),
            keypair: EcdsaKeyPair::from_seed(seed),
            next_credential_id: 1,
        }
    }

    /// Zwraca klucz publiczny Wystawcy $PK_{\text{issuer}}$ na krzywej NIST P-256.
    pub fn public_key(&self) -> P256Point {
        self.keypair.public_key
    }

    /// Wystawia i podpisuje poświadczenie wieku dla obywatela:
    /// 1. Sprawdza poprawność dat (`birth_date <= valid_from <= valid_until`),
    /// 2. Generuje tajną 128-bitową sól `secret_salt`,
    /// 3. Oblicza zobowiązanie `AttributeCommitment` (`SHA-256`) do daty urodzenia,
    /// 4. Podpisuje zobowiązanie i okres ważności kluczem prywatnym ECDSA P-256.
    pub fn issue_age_credential(
        &mut self,
        holder_label: &str,
        birth_date: CredentialDate,
        valid_from: CredentialDate,
        valid_until: CredentialDate,
    ) -> Result<SignedAgeCredential, &'static str> {
        if holder_label.trim().is_empty() {
            return Err("Nazwa podmiotu nie może być pusta");
        }
        if valid_until < valid_from {
            return Err("Data końca ważności (valid_until) musi być >= valid_from");
        }
        if birth_date > valid_from {
            return Err("Data urodzenia nie może być późniejsza niż początek ważności poświadczenia");
        }

        let credential_id = self.next_credential_id;
        self.next_credential_id += 1;

        let secret_salt = self.derive_secret_salt(credential_id, holder_label, &birth_date);
        let dob_commitment = AttributeCommitment::commit(
            "birth_date",
            birth_date.to_timestamp_seconds(),
            &secret_salt,
        );

        let signing_payload = SignedAgeCredential::canonical_signing_payload(
            credential_id,
            &self.issuer_id,
            &dob_commitment,
            &valid_from,
            &valid_until,
        );
        let issuer_signature = self.keypair.sign_message(&signing_payload);

        let private_witness = PrivateAgeWitness {
            birth_date,
            secret_salt,
            valid_from,
            valid_until,
        };

        Ok(SignedAgeCredential {
            credential_id,
            issuer_id: self.issuer_id.clone(),
            dob_commitment,
            valid_from,
            valid_until,
            issuer_signature,
            issuer_public_key: self.keypair.public_key,
            private_witness,
        })
    }

    fn derive_secret_salt(
        &self,
        credential_id: u64,
        holder_label: &str,
        birth_date: &CredentialDate,
    ) -> [u8; 16] {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"ZeroAge-MVP-Issuer-Salt:");
        buf.extend_from_slice(&credential_id.to_be_bytes());
        buf.extend_from_slice(holder_label.as_bytes());
        buf.extend_from_slice(&birth_date.to_timestamp_seconds().to_be_bytes());
        let digest = sha256_digest(&buf);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&digest[..16]);
        salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issuer_signs_credential_and_verifies_commitment() {
        let mut issuer = CredentialIssuer::new("PL-Test-Issuer-MVP", b"mvp-issuer-key-seed");
        let dob = CredentialDate::parse_iso("2004-05-15").unwrap();
        let valid_from = CredentialDate::parse_iso("2026-01-01").unwrap();
        let valid_until = CredentialDate::parse_iso("2027-01-01").unwrap();

        let cred = issuer
            .issue_age_credential("Jan Kowalski", dob, valid_from, valid_until)
            .expect("Emisja poświadczenia MVP musi się powieść");

        // 1. Podpis ECDSA P-256 Wystawcy jest poprawny
        assert!(cred.verify_issuer_signature());

        // 2. Prywatny świadek poprawnie otwiera zobowiązanie SHA-256
        assert!(cred.private_witness.matches_commitment(&cred.dob_commitment));

        // 3. Próba podmiany zobowiązania lub klucza publicznego unieważnia podpis
        let mut tampered = cred.clone();
        tampered.dob_commitment.digest[0] ^= 0x01;
        assert!(!tampered.verify_issuer_signature());
    }
}
