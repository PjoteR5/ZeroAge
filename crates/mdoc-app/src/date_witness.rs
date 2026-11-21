use serde::{Deserialize, Serialize};

use crate::commitment::AttributeCommitment;
use crate::serialization::{hex16, p256_point};
use zkp_circuits::age_circuit::{build_age_and_validity_witness, AGE_18_SECONDS};
use zkp_circuits::ecdsa_p256::P256Point;
use zkp_core::field::Fp256;

/// Nazwa atrybutu pełnoletności w poświadczeniu (zgodnie ze standardem ISO/IEC 18013-5 MDOC).
pub const IS_OVER18_ATTR_NAME: &str = "is_over18";

/// Kanoniczna reprezentacja daty kalendarzowej UTC `(rok, miesiąc, dzień)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CredentialDate {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

impl CredentialDate {
    /// Tworzy nową datę kalendarzową po sprawdzeniu poprawności miesiąca, dnia oraz roku przestępnego.
    pub fn new(year: u16, month: u8, day: u8) -> Result<Self, &'static str> {
        if !(1900..=2100).contains(&year) {
            return Err("Rok musi mieścić się w przedziale 1900..=2100");
        }
        if !(1..=12).contains(&month) {
            return Err("Miesiąc musi mieścić się w przedziale 1..=12");
        }
        let max_day = days_in_month(year, month);
        if day < 1 || day > max_day {
            return Err("Nieprawidłowy dzień dla podanego miesiąca i roku");
        }
        Ok(Self { year, month, day })
    }

    /// Parsuje datę z łańcucha znaków w formacie ISO-8601 `"YYYY-MM-DD"` (np. `"2004-05-15"`).
    pub fn parse_iso(iso_date: &str) -> Result<Self, &'static str> {
        let parts: Vec<&str> = iso_date.trim().split('-').collect();
        if parts.len() != 3 {
            return Err("Oczekiwano formatu daty YYYY-MM-DD");
        }
        let year: u16 = parts[0].parse().map_err(|_| "Nieprawidłowy rok w dacie")?;
        let month: u8 = parts[1]
            .parse()
            .map_err(|_| "Nieprawidłowy miesiąc w dacie")?;
        let day: u8 = parts[2]
            .parse()
            .map_err(|_| "Nieprawidłowy dzień w dacie")?;
        Self::new(year, month, day)
    }

    /// Formatuje datę do postaci ISO-8601 `"YYYY-MM-DD"`.
    pub fn to_iso_string(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// Sprawdza z dokładnością co do dnia kalendarzowego (rozróżniając np. styczeń od grudnia),
    /// czy osoba urodzona w dacie `self` ma ukończone 18 lat w dniu `reference_date`.
    pub const fn has_reached_age_18_on(&self, reference_date: &CredentialDate) -> bool {
        if reference_date.year < self.year + 18 {
            return false;
        }
        if reference_date.year > self.year + 18 {
            return true;
        }
        if reference_date.month != self.month {
            return reference_date.month > self.month;
        }
        reference_date.day >= self.day
    }

    /// Konwertuje datę na liczbę sekund od epoki `1900-01-01 00:00:00 UTC`.
    pub fn to_timestamp_seconds(&self) -> u64 {
        let mut total_days: u64 = 0;
        for y in 1900..self.year {
            total_days += if is_leap_year(y) { 366 } else { 365 };
        }
        for m in 1..self.month {
            total_days += days_in_month(self.year, m) as u64;
        }
        total_days += (self.day - 1) as u64;
        total_days * 86_400
    }

    /// Mapuje znacznik czasu daty bezpośrednio na element ciała skończonego $\mathbb{F}_{p_{256}}$.
    pub fn to_field_element(&self) -> Fp256 {
        Fp256::from(self.to_timestamp_seconds())
    }
}

/// Sprawdza regułę roku przestępnego w kalendarzu gregoriańskim.
pub const fn is_leap_year(year: u16) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Zwraca liczbę dni w danym miesiącu dla zadanego roku.
pub const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

// ===========================================================================
// Jawny Podział na Dane Publiczne (PublicInputs) oraz Dane Ukryte (PrivateWitness)
// ===========================================================================

/// **Dane Publiczne (`PublicAgeInputs`)** – widoczne dla Weryfikatora i włączane do transkryptu Fiata-Shamira.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAgeInputs {
    /// Aktualna data weryfikacji po stronie serwisu (`t_now`)
    pub verification_date: CredentialDate,
    /// Publiczne zobowiązanie kryptograficzne `SHA-256` do flagi `is_over18` podpisane przez Wystawcę
    pub is_over18_commitment: AttributeCommitment,
    /// Zaufany klucz publiczny Wystawcy $PK_{\text{issuer}}$ na krzywej NIST P-256
    #[serde(with = "p256_point")]
    pub issuer_public_key: P256Point,
    /// Jednorazowe wyzwanie losowe sesji (`nonce`) zapobiegające atakom powtórzeniowym (Replay)
    #[serde(with = "hex16")]
    pub challenge_nonce: [u8; 16],
}

impl PublicAgeInputs {
    /// Zwraca publiczny znacznik czasu weryfikacji `t_now` w sekundach.
    pub fn t_now_seconds(&self) -> u64 {
        self.verification_date.to_timestamp_seconds()
    }
}

/// **Dane Ukryte (`PrivateAgeWitness`)** – prywatny świadek przechowywany wyłącznie w portfelu użytkownika.
/// Certyfikat przechowuje jedynie flagę `is_over18` wydaną przez urząd oraz sól — dokładna data urodzenia
/// obywatela w ogóle nie znajduje się w certyfikacie ani w pamięci obwodu ZKP!
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateAgeWitness {
    /// Flaga pełnoletności `is_over18` potwierdzona przez Wystawcę podczas emisji certyfikatu
    pub is_over18: bool,
    /// Tajna 128-bitowa sól otwierająca zobowiązanie `is_over18_commitment`
    #[serde(with = "hex16")]
    pub secret_salt: [u8; 16],
    /// Początek okresu ważności poświadczenia (`valid_from`)
    pub valid_from: CredentialDate,
    /// Koniec okresu ważności poświadczenia (`valid_until`)
    pub valid_until: CredentialDate,
}

impl PrivateAgeWitness {
    /// Sprawdza lokalnie, czy prywatny świadek (`is_over18`, `secret_salt`) otwiera zobowiązanie `is_over18_commitment`.
    pub fn matches_commitment(&self, commitment: &AttributeCommitment) -> bool {
        commitment.verify_opening(
            IS_OVER18_ATTR_NAME,
            u64::from(self.is_over18),
            &self.secret_salt,
        )
    }

    /// Wylicza prywatny skalar zobowiązania `SHA-256(domain || salt || "is_over18" || flag)` w ciele $\mathbb{F}_{p_{256}}$.
    pub fn compute_witness_commitment_field(&self) -> Fp256 {
        AttributeCommitment::commit(
            IS_OVER18_ATTR_NAME,
            u64::from(self.is_over18),
            &self.secret_salt,
        )
        .to_field_element()
    }

    /// Łączy dane publiczne (`PublicAgeInputs`) oraz dane ukryte (`PrivateAgeWitness`)
    /// w kompletny wektor przewodów wejściowych $\mathbf{w} \in \mathbb{F}_{p_{256}}^{136}$
    /// dla obwodu kwadratowego `build_age_and_validity_circuit`.
    pub fn synthesize_circuit_witness(&self, public_inputs: &PublicAgeInputs) -> Vec<Fp256> {
        let t_now = public_inputs.t_now_seconds();
        let v_from_ts = self.valid_from.to_timestamp_seconds();
        let v_until_ts = self.valid_until.to_timestamp_seconds();

        let pub_commit_f = public_inputs.is_over18_commitment.to_field_element();
        let priv_commit_f = self.compute_witness_commitment_field();

        build_age_and_validity_witness::<Fp256>(
            t_now,
            self.is_over18,
            v_from_ts,
            v_until_ts,
            pub_commit_f,
            priv_commit_f,
        )
    }
}

/// Zwraca domyślny próg pełnoletności (18 lat w sekundach).
pub const fn default_min_age_18_seconds() -> u64 {
    AGE_18_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkp_circuits::age_circuit::{
        build_age_and_validity_circuit, is_age_circuit_output_satisfied,
    };

    #[test]
    fn test_credential_date_parsing_and_exact_18yo_month_day_check() {
        let verify_date = CredentialDate::parse_iso("2026-11-17").unwrap();

        // Osoba ze stycznia 2008 -> w listopadzie 2026 ma już 18 lat
        let jan_2008 = CredentialDate::parse_iso("2008-01-10").unwrap();
        assert!(jan_2008.has_reached_age_18_on(&verify_date));

        // Osoba z grudnia 2008 -> w listopadzie 2026 ma jeszcze 17 lat!
        let dec_2008 = CredentialDate::parse_iso("2008-12-15").unwrap();
        assert!(!dec_2008.has_reached_age_18_on(&verify_date));
    }

    #[test]
    fn test_public_and_private_witness_synthesis_for_is_over18() {
        let valid_from = CredentialDate::parse_iso("2026-01-01").unwrap();
        let valid_until = CredentialDate::parse_iso("2027-01-01").unwrap();
        let verify_date = CredentialDate::parse_iso("2026-11-17").unwrap();
        let salt = [0x42u8; 16];

        let commitment = AttributeCommitment::commit(IS_OVER18_ATTR_NAME, 1, &salt);

        let public_inputs = PublicAgeInputs {
            verification_date: verify_date,
            is_over18_commitment: commitment,
            issuer_public_key: P256Point::generator(),
            challenge_nonce: [0x99u8; 16],
        };

        let private_witness = PrivateAgeWitness {
            is_over18: true,
            secret_salt: salt,
            valid_from,
            valid_until,
        };

        assert!(private_witness.matches_commitment(&public_inputs.is_over18_commitment));

        let circuit = build_age_and_validity_circuit::<Fp256>();
        let wires = private_witness.synthesize_circuit_witness(&public_inputs);
        let evals = circuit.evaluate_all(&wires);
        assert!(is_age_circuit_output_satisfied(&evals[0]));
    }
}
