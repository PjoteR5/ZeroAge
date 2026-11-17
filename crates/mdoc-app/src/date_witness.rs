//! Moduł 2 (Piotr): **Przygotowanie reprezentacji daty oraz podział na dane publiczne i ukryte**.
//!
//! Definiuje:
//! 1. **`CredentialDate`:** kanoniczną reprezentację daty kalendarzowej `(year, month, day)`
//!    z walidacją lat przestępnych, parsowaniem formatu ISO-8601 (`"YYYY-MM-DD"`), konwersją
//!    do sekundowego znacznika czasu UTC (`u64`) oraz elementu ciała pierwszego $\mathbb{F}_{p_{256}}$.
//! 2. **`PublicAgeInputs` (Dane Publiczne):** parametry jawne znane zarówno Dowodzącemu, jak i Weryfikatorowi
//!    (aktualna data weryfikacji `t_now`, próg `AGE_18_SECONDS`, publiczne zobowiązanie do atrybutu,
//!    klucz publiczny Wystawcy $PK_{\text{issuer}}$ oraz jednorazowy `nonce`).
//! 3. **`PrivateAgeWitness` (Dane Ukryte):** tajne dane przechowywane wyłącznie w portfelu obywatela
//!    (dokładna data urodzenia `birth_date`, tajna sól `secret_salt`, okres ważności oraz
//!    64-bitowe rozkłady binarne różnic czasu zapobiegające atakowi zawinięcia modulo $p$).

use crate::commitment::AttributeCommitment;
use zkp_circuits::age_circuit::{build_age_and_validity_witness, AGE_18_SECONDS};
use zkp_circuits::ecdsa_p256::P256Point;
use zkp_core::field::Fp256;

/// Kanoniczna reprezentacja daty kalendarzowej UTC `(rok, miesiąc, dzień)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

    /// Konwertuje datę na liczbę sekund od epoki `1900-01-01 00:00:00 UTC` (monotoniczny znacznik `u64`
    /// obsługujący bezbłędnie również daty urodzenia sprzed 1970 roku).
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
/// Nie ujawniają żadnych informacji o dokładnym wieku ani tożsamości użytkownika.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicAgeInputs {
    /// Aktualna data weryfikacji po stronie serwisu (`t_now`)
    pub verification_date: CredentialDate,
    /// Wymagany próg pełnoletności w sekundach (`AGE_18_SECONDS = 567_993_600`)
    pub min_age_seconds: u64,
    /// Publiczne zobowiązanie kryptograficzne `SHA-256` do daty urodzenia podpisane przez Wystawcę
    pub dob_commitment: AttributeCommitment,
    /// Zaufany klucz publiczny Wystawcy $PK_{\text{issuer}}$ na krzywej NIST P-256
    pub issuer_public_key: P256Point,
    /// Jednorazowe wyzwanie losowe sesji (`nonce`) zapobiegające atakom powtórzeniowym (Replay)
    pub challenge_nonce: [u8; 16],
}

impl PublicAgeInputs {
    /// Zwraca publiczny znacznik czasu weryfikacji `t_now` w sekundach.
    pub fn t_now_seconds(&self) -> u64 {
        self.verification_date.to_timestamp_seconds()
    }
}

/// **Dane Ukryte (`PrivateAgeWitness`)** – prywatny świadek przechowywany wyłącznie w portfelu użytkownika.
/// Żadne z poniższych pól nigdy nie jest przesyłane w wiadomościach sieciowych do Weryfikatora.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateAgeWitness {
    /// Tajna data urodzenia obywatela
    pub birth_date: CredentialDate,
    /// Tajna 128-bitowa sól otwierająca zobowiązanie `dob_commitment`
    pub secret_salt: [u8; 16],
    /// Początek okresu ważności poświadczenia (`valid_from`)
    pub valid_from: CredentialDate,
    /// Koniec okresu ważności poświadczenia (`valid_until`)
    pub valid_until: CredentialDate,
}

impl PrivateAgeWitness {
    /// Sprawdza lokalnie, czy prywatny świadek otwiera publiczne zobowiązanie `dob_commitment`.
    pub fn matches_commitment(&self, commitment: &AttributeCommitment) -> bool {
        commitment.verify_opening(
            "birth_date",
            self.birth_date.to_timestamp_seconds(),
            &self.secret_salt,
        )
    }

    /// Wylicza prywatny skalar zobowiązania `SHA-256(salt || "birth_date" || dob)` w ciele $\mathbb{F}_{p_{256}}$.
    pub fn compute_witness_commitment_field(&self) -> Fp256 {
        AttributeCommitment::commit(
            "birth_date",
            self.birth_date.to_timestamp_seconds(),
            &self.secret_salt,
        )
        .to_field_element()
    }

    /// Łączy dane publiczne (`PublicAgeInputs`) oraz dane ukryte (`PrivateAgeWitness`)
    /// w kompletny wektor przewodów wejściowych $\mathbf{w} \in \mathbb{F}_{p_{256}}^{200}$
    /// dla obwodu kwadratowego `build_age_and_validity_circuit` (wraz z 64-bitowym rozkładem różnic dat).
    pub fn synthesize_circuit_witness(&self, public_inputs: &PublicAgeInputs) -> Vec<Fp256> {
        let t_now = public_inputs.t_now_seconds();
        let dob_ts = self.birth_date.to_timestamp_seconds();
        let v_from_ts = self.valid_from.to_timestamp_seconds();
        let v_until_ts = self.valid_until.to_timestamp_seconds();

        let pub_commit_f = public_inputs.dob_commitment.to_field_element();
        let priv_commit_f = self.compute_witness_commitment_field();

        build_age_and_validity_witness::<Fp256>(
            t_now,
            dob_ts,
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
    fn test_credential_date_parsing_and_ordering() {
        let d1 = CredentialDate::parse_iso("2004-05-15").unwrap();
        let d2 = CredentialDate::parse_iso("2026-11-17").unwrap();
        assert!(d1 < d2);
        assert_eq!(d1.to_iso_string(), "2004-05-15");

        // Walidacja roku przestępnego (2024 był przestępny, 2025 nie)
        assert!(CredentialDate::parse_iso("2024-02-29").is_ok());
        assert!(CredentialDate::parse_iso("2025-02-29").is_err());
    }

    #[test]
    fn test_public_and_private_witness_synthesis() {
        let birth_date = CredentialDate::parse_iso("2004-05-15").unwrap();
        let valid_from = CredentialDate::parse_iso("2026-01-01").unwrap();
        let valid_until = CredentialDate::parse_iso("2027-01-01").unwrap();
        let verify_date = CredentialDate::parse_iso("2026-11-17").unwrap();
        let salt = [0x42u8; 16];

        let commitment =
            AttributeCommitment::commit("birth_date", birth_date.to_timestamp_seconds(), &salt);

        let public_inputs = PublicAgeInputs {
            verification_date: verify_date,
            min_age_seconds: default_min_age_18_seconds(),
            dob_commitment: commitment,
            issuer_public_key: P256Point::generator(),
            challenge_nonce: [0x99u8; 16],
        };

        let private_witness = PrivateAgeWitness {
            birth_date,
            secret_salt: salt,
            valid_from,
            valid_until,
        };

        assert!(private_witness.matches_commitment(&public_inputs.dob_commitment));

        let circuit = build_age_and_validity_circuit::<Fp256>();
        let wires = private_witness.synthesize_circuit_witness(&public_inputs);
        let evals = circuit.evaluate_all(&wires);
        assert!(is_age_circuit_output_satisfied(&evals[0]));
    }
}
