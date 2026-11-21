use serde::{Deserialize, Serialize};

use crate::commitment::AttributeCommitment;
use crate::date_witness::{
    CredentialDate, PrivateAgeWitness, PublicAgeInputs, IS_OVER18_ATTR_NAME,
};
use crate::revocation::RevocationRegistry;
use crate::serialization::{ecdsa_sig, p256_point};
use zkp_circuits::ecdsa_p256::{
    verify_ecdsa_message, EcdsaKeyPair, EcdsaSignature, P256Point,
};
use zkp_circuits::sha256::sha256_digest;

const CREDENTIAL_SIGN_DOMAIN: &[u8] = b"ZeroAge-MVP-Credential-Sign-v1:";

/// Podpisane poświadczenie pełnoletności (`is_over18`) wydawane przez Wystawcę do portfela użytkownika.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAgeCredential {
    pub credential_id: u64,
    pub issuer_id: String,
    /// Zobowiązanie kryptograficzne `SHA-256` do flagi `is_over18`
    pub is_over18_commitment: AttributeCommitment,
    /// Początek ważności poświadczenia
    pub valid_from: CredentialDate,
    /// Koniec ważności poświadczenia
    pub valid_until: CredentialDate,
    /// Podpis cyfrowy ECDSA P-256 Wystawcy nad zobowiązaniem flagi `is_over18` i metadanymi ważności
    #[serde(with = "ecdsa_sig")]
    pub issuer_signature: EcdsaSignature,
    /// Klucz publiczny Wystawcy $PK_{\text{issuer}}$ na krzywej NIST P-256
    #[serde(with = "p256_point")]
    pub issuer_public_key: P256Point,
    /// Część ukryta (prywatny świadek: `is_over18` + `secret_salt`), znana wyłącznie właścicielowi portfela
    pub private_witness: PrivateAgeWitness,
}

impl SignedAgeCredential {
    /// Buduje kanoniczny ciąg bajtów podpisywany przez Wystawcę kluczem ECDSA P-256.
    /// Podpisywane jest wyłącznie zobowiązanie `is_over18_commitment` oraz ramy ważności.
    pub fn canonical_signing_payload(
        credential_id: u64,
        issuer_id: &str,
        is_over18_commitment: &AttributeCommitment,
        valid_from: &CredentialDate,
        valid_until: &CredentialDate,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(CREDENTIAL_SIGN_DOMAIN);
        buf.extend_from_slice(&credential_id.to_be_bytes());
        buf.extend_from_slice(issuer_id.as_bytes());
        buf.extend_from_slice(&is_over18_commitment.digest);
        buf.extend_from_slice(&valid_from.to_timestamp_seconds().to_be_bytes());
        buf.extend_from_slice(&valid_until.to_timestamp_seconds().to_be_bytes());
        buf
    }

    /// Weryfikuje podpis cyfrowy ECDSA P-256 Wystawcy.
    pub fn verify_issuer_signature(&self) -> bool {
        let payload = Self::canonical_signing_payload(
            self.credential_id,
            &self.issuer_id,
            &self.is_over18_commitment,
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
            is_over18_commitment: self.is_over18_commitment,
            issuer_public_key: self.issuer_public_key,
            challenge_nonce,
        };
        (public_inputs, self.private_witness.clone())
    }

    /// Serializuje certyfikat do czytelnego JSON (do zapisu w portfelu użytkownika).
    pub fn to_json_pretty(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("Błąd serializacji poświadczenia do JSON: {e}"))
    }

    /// Odtwarza certyfikat z tekstu JSON.
    pub fn from_json_str(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("Błąd deserializacji poświadczenia z JSON: {e}"))
    }
}

/// Węzeł Wystawcy Poświadczeń (`CredentialIssuer`) wystawiający certyfikaty z flagą `is_over18`.
pub struct CredentialIssuer {
    pub issuer_id: String,
    pub keypair: EcdsaKeyPair,
    pub revocation_registry: RevocationRegistry,
    next_credential_id: u64,
}

impl CredentialIssuer {
    /// Tworzy nowego Wystawcę z kluczem ECDSA P-256 wyprowadzonym z ziarna `seed`.
    pub fn new(issuer_id: &str, seed: &[u8]) -> Self {
        Self {
            issuer_id: issuer_id.to_string(),
            keypair: EcdsaKeyPair::from_seed(seed),
            revocation_registry: RevocationRegistry::new(),
            next_credential_id: 1,
        }
    }

    /// Unieważnia wydany certyfikat w rejestrze Wystawcy (np. z powodu kradzieży urządzenia).
    pub fn revoke_credential(
        &mut self,
        credential_id: u64,
        revoked_at: CredentialDate,
        reason: &str,
    ) -> bool {
        self.revocation_registry
            .revoke(credential_id, revoked_at, reason)
    }

    /// Zwraca klucz publiczny Wystawcy $PK_{\text{issuer}}$ na krzywej NIST P-256.
    pub fn public_key(&self) -> P256Point {
        self.keypair.public_key
    }

    /// Wystawia i podpisuje poświadczenie z wyliczoną przez urząd flagą `is_over18`:
    /// 1. Urząd weryfikuje datę urodzenia obywatela `birth_date` względem `valid_from` (z dokładnością co do dnia)
    ///    i wyznacza flagę `is_over18: bool`,
    /// 2. Generuje tajną 128-bitową sól `secret_salt`,
    /// 3. Oblicza zobowiązanie `AttributeCommitment` (`SHA-256`) do flagi `is_over18` (data urodzenia nie trafia do certyfikatu!),
    /// 4. Podpisuje zobowiązanie i okres ważności kluczem prywatnym ECDSA P-256.
    pub fn issue_age_credential(
        &mut self,
        holder_label: &str,
        birth_date: CredentialDate,
        valid_from: CredentialDate,
        valid_until: CredentialDate,
    ) -> Result<SignedAgeCredential, &'static str> {
        if birth_date > valid_from {
            return Err("Data urodzenia nie może być późniejsza niż początek ważności poświadczenia");
        }
        let is_over18 = birth_date.has_reached_age_18_on(&valid_from);
        self.issue_over18_flag_credential(holder_label, is_over18, valid_from, valid_until)
    }

    /// Wystawia poświadczenie bezpośrednio dla zadanej wartości flagi `is_over18: bool`.
    pub fn issue_over18_flag_credential(
        &mut self,
        holder_label: &str,
        is_over18: bool,
        valid_from: CredentialDate,
        valid_until: CredentialDate,
    ) -> Result<SignedAgeCredential, &'static str> {
        if holder_label.trim().is_empty() {
            return Err("Nazwa podmiotu nie może być pusta");
        }
        if valid_until < valid_from {
            return Err("Data końca ważności (valid_until) musi być >= valid_from");
        }

        let credential_id = self.next_credential_id;
        self.next_credential_id += 1;

        let secret_salt = self.derive_secret_salt(credential_id, holder_label, is_over18);
        let is_over18_commitment = AttributeCommitment::commit(
            IS_OVER18_ATTR_NAME,
            u64::from(is_over18),
            &secret_salt,
        );

        let signing_payload = SignedAgeCredential::canonical_signing_payload(
            credential_id,
            &self.issuer_id,
            &is_over18_commitment,
            &valid_from,
            &valid_until,
        );
        let issuer_signature = self.keypair.sign_message(&signing_payload);

        let private_witness = PrivateAgeWitness {
            is_over18,
            secret_salt,
            valid_from,
            valid_until,
        };

        Ok(SignedAgeCredential {
            credential_id,
            issuer_id: self.issuer_id.clone(),
            is_over18_commitment,
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
        is_over18: bool,
    ) -> [u8; 16] {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"ZeroAge-MVP-Issuer-Salt:");
        buf.extend_from_slice(&credential_id.to_be_bytes());
        buf.extend_from_slice(holder_label.as_bytes());
        buf.push(u8::from(is_over18));
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
    fn test_issuer_signs_is_over18_flag_credential_and_verifies_commitment() {
        let mut issuer = CredentialIssuer::new("PL-Test-Issuer-MVP", b"mvp-issuer-key-seed");
        let dob = CredentialDate::parse_iso("2004-05-15").unwrap();
        let valid_from = CredentialDate::parse_iso("2026-01-01").unwrap();
        let valid_until = CredentialDate::parse_iso("2027-01-01").unwrap();

        let cred = issuer
            .issue_age_credential("Jan Kowalski", dob, valid_from, valid_until)
            .expect("Emisja poświadczenia MVP musi się powieść");

        assert!(cred.private_witness.is_over18);
        assert!(cred.verify_issuer_signature());
        assert!(cred.private_witness.matches_commitment(&cred.is_over18_commitment));

        // Próba podmiany zobowiązania unieważnia podpis
        let mut tampered = cred.clone();
        tampered.is_over18_commitment.digest[0] ^= 0x01;
        assert!(!tampered.verify_issuer_signature());
    }
}
