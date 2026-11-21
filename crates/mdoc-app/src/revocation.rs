use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::date_witness::CredentialDate;
use crate::serialization::bytes_to_hex;

/// Pojedynczy wpis unieważnienia poświadczenia w rejestrze Wystawcy (`issued_credentials.is_revoked`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub credential_id: u64,
    pub revoked_at: CredentialDate,
    pub reason: String,
}

/// Rejestr unieważnień poświadczeń (CRL / Revocation Registry) utrzymywany przez Wystawcę
/// i udostępniany Weryfikatorowi do odrzucania skradzionych lub wycofanych certyfikatów (Test 4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRegistry {
    entries: BTreeMap<u64, RevocationEntry>,
}

impl RevocationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Dodaje poświadczenie `credential_id` do listy unieważnionych.
    /// Zwraca `true`, jeśli wpis został dodany po raz pierwszy; `false`, jeśli już był unieważniony.
    pub fn revoke(&mut self, credential_id: u64, revoked_at: CredentialDate, reason: &str) -> bool {
        if self.entries.contains_key(&credential_id) {
            return false;
        }
        self.entries.insert(
            credential_id,
            RevocationEntry {
                credential_id,
                revoked_at,
                reason: reason.to_string(),
            },
        );
        true
    }

    /// Sprawdza, czy dane poświadczenie zostało unieważnione.
    pub fn is_revoked(&self, credential_id: u64) -> bool {
        self.entries.contains_key(&credential_id)
    }

    /// Zwraca szczegóły unieważnienia dla danego `credential_id`.
    pub fn get_entry(&self, credential_id: u64) -> Option<&RevocationEntry> {
        self.entries.get(&credential_id)
    }

    /// Liczba unieważnionych poświadczeń w rejestrze.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serializuje rejestr unieważnień do czytelnego formatu JSON.
    pub fn to_json_pretty(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("Błąd serializacji rejestru unieważnień: {e}"))
    }

    /// Deserializuje rejestr unieważnień z JSON.
    pub fn from_json_str(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("Błąd deserializacji rejestru unieważnień: {e}"))
    }
}

/// Rejestr zużytych wyzwań sesyjnych (`challenge_nonce`) po stronie Weryfikatora.
/// Chroni przed atakiem powtórzeniowym (Replay Attack – Test bezpieczeństwa nr 2).
#[derive(Clone, Debug, Default)]
pub struct NonceReplayCache {
    used_nonces: BTreeSet<[u8; 16]>,
}

impl NonceReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sprawdza, czy dane wyzwanie `nonce` zostało już wcześniej wykorzystane.
    pub fn is_nonce_used(&self, nonce: &[u8; 16]) -> bool {
        self.used_nonces.contains(nonce)
    }

    /// Oznacza wyzwanie `nonce` jako zużyte.
    /// Zwraca `true`, jeśli nonce był świeży; `false`, jeśli już wcześniej był zużyty (Replay!).
    pub fn mark_nonce_used(&mut self, nonce: [u8; 16]) -> bool {
        self.used_nonces.insert(nonce)
    }

    /// Liczba zużytych wyzwań w pamięci podręcznej.
    pub fn len(&self) -> usize {
        self.used_nonces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.used_nonces.is_empty()
    }

    /// Zwraca listę zużytych nonce'ów w formacie szesnastkowym (do audytu).
    pub fn used_nonces_hex(&self) -> Vec<String> {
        self.used_nonces.iter().map(|n| bytes_to_hex(n)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_registry_revoke_and_json_roundtrip() {
        let mut registry = RevocationRegistry::new();
        let rev_date = CredentialDate::parse_iso("2026-11-20").unwrap();

        assert!(!registry.is_revoked(42));
        assert!(registry.revoke(42, rev_date, "Zgłoszona kradzież urządzenia"));
        assert!(!registry.revoke(42, rev_date, "Duplikat"));
        assert!(registry.is_revoked(42));
        assert_eq!(
            registry.get_entry(42).unwrap().reason,
            "Zgłoszona kradzież urządzenia"
        );

        let json = registry.to_json_pretty().unwrap();
        let restored = RevocationRegistry::from_json_str(&json).unwrap();
        assert_eq!(registry, restored);
    }

    #[test]
    fn test_nonce_replay_cache_blocks_reuse() {
        let mut cache = NonceReplayCache::new();
        let nonce = [0xABu8; 16];

        assert!(!cache.is_nonce_used(&nonce));
        assert!(cache.mark_nonce_used(nonce));
        assert!(cache.is_nonce_used(&nonce));
        assert!(!cache.mark_nonce_used(nonce));
    }
}
