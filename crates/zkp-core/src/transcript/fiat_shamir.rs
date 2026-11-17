use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;
use std::collections::BTreeSet;

/// Wrapper wokół `merlin::Transcript` implementujący heurystykę Fiata-Shamira
/// dla protokołów Verifiable Computation i ZKP (Sumcheck, Ligero, Protokół 2.5).
///
/// Transkrypt zarządza stanem gąbki kryptograficznej (kryptograficzny Fiat-Shamir),
/// absorbując zobowiązania (korzenie Merkle'a, wielomiany rundy, wektory)
/// oraz deterministycznie wyciskając wyzwania (skalary z ciała $\mathbb{F}_p$,
/// zapytania o indeksy kolumn).
#[derive(Clone)]
pub struct FiatShamirTranscript {
    transcript: Transcript,
}

impl FiatShamirTranscript {
    /// Inicjalizuje nowy transkrypt z separatorem domeny protokołu.
    pub fn new(protocol_name: &'static [u8]) -> Self {
        Self {
            transcript: Transcript::new(protocol_name),
        }
    }

    /// Dołącza dowolną surową wiadomość bajtową pod zadaną etykietą.
    pub fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        self.transcript.append_message(label, message);
    }

    /// Dołącza korzeń drzewa Merkle'a (32 bajty).
    pub fn append_root(&mut self, label: &'static [u8], root: &[u8; 32]) {
        self.transcript.append_message(label, root);
    }

    /// Dołącza element ciała $\mathbb{F}_p$ w postaci skompresowanej kanonicznej serializacji.
    pub fn append_field_element<F: PrimeField + CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        elem: &F,
    ) {
        let mut bytes = Vec::new();
        elem.serialize_compressed(&mut bytes)
            .expect("Błąd kanonicznej serializacji elementu ciała");
        self.transcript.append_message(label, &bytes);
    }

    /// Dołącza plaster elementów ciała $\mathbb{F}_p$.
    pub fn append_field_elements<F: PrimeField + CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        elems: &[F],
    ) {
        let mut bytes = Vec::new();
        elems
            .serialize_compressed(&mut bytes)
            .expect("Błąd kanonicznej serializacji wektora elementów ciała");
        self.transcript.append_message(label, &bytes);
    }

    /// Generuje (wyciska) losowe wyzwanie skalarne w ciele $\mathbb{F}_p$.
    ///
    /// Pobiera 64 bajty (512 bitów) ze stanu gąbki i mapuje modulo rząd ciała $p$,
    /// co dla krzywych 256-bitowych (np. P-256) gwarantuje pomijalny błąd
    /// statystyczny (odchylenie od rozkładu jednostajnego $< 2^{-256}$).
    pub fn challenge_scalar<F: PrimeField>(&mut self, label: &'static [u8]) -> F {
        let mut buf = [0u8; 64];
        self.transcript.challenge_bytes(label, &mut buf);
        F::from_le_bytes_mod_order(&buf)
    }

    /// Generuje wektor $k$ losowych wyzwań skalarnych w ciele $\mathbb{F}_p$.
    pub fn challenge_scalars<F: PrimeField>(&mut self, label: &'static [u8], count: usize) -> Vec<F> {
        (0..count).map(|_| self.challenge_scalar(label)).collect()
    }

    /// Generuje `count` unikalnych losowych indeksów z przedziału `[0, max_exclusive)`.
    /// Używane w protokole Ligero do losowania zapytań o $t$ kolumn macierzy.
    ///
    /// Wynikowe indeksy są posortowane rosnąco.
    pub fn challenge_indices(
        &mut self,
        label: &'static [u8],
        max_exclusive: usize,
        count: usize,
    ) -> Vec<usize> {
        assert!(
            count <= max_exclusive,
            "Liczba żądanych indeksów ({count}) nie może przekraczać zakresu ({max_exclusive})"
        );

        let mut indices = BTreeSet::new();
        let mut attempts = 0usize;

        while indices.len() < count {
            let mut buf = [0u8; 8];
            self.transcript.challenge_bytes(label, &mut buf);
            let raw = u64::from_le_bytes(buf);
            let idx = (raw as usize) % max_exclusive;
            indices.insert(idx);

            attempts += 1;
            if attempts > 10_000 + count * 20 {
                panic!("Przekroczono limit prób podczas losowania unikalnych indeksów Fiata-Shamira");
            }
        }

        indices.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::MontConfig;

    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    pub struct FqConfig;
    pub type F17 = ark_ff::Fp64<ark_ff::MontBackend<FqConfig, 1>>;

    #[test]
    fn test_fiat_shamir_determinism() {
        let mut t1 = FiatShamirTranscript::new(b"TestProtocol");
        let mut t2 = FiatShamirTranscript::new(b"TestProtocol");

        let elem = F17::from(11u64);
        t1.append_field_element(b"round_1", &elem);
        t2.append_field_element(b"round_1", &elem);

        let c1: F17 = t1.challenge_scalar(b"challenge");
        let c2: F17 = t2.challenge_scalar(b"challenge");

        assert_eq!(c1, c2, "Determinizm: identyczne wiadomości muszą dać identyczne wyzwanie");
    }

    #[test]
    fn test_fiat_shamir_soundness_divergence() {
        let mut t1 = FiatShamirTranscript::new(b"TestProtocol");
        let mut t2 = FiatShamirTranscript::new(b"TestProtocol");

        t1.append_field_element(b"round_1", &F17::from(11u64));
        t2.append_field_element(b"round_1", &F17::from(12u64));

        let c1: F17 = t1.challenge_scalar(b"challenge");
        let c2: F17 = t2.challenge_scalar(b"challenge");

        assert_ne!(c1, c2, "Różne wiadomości muszą wygenerować różne wyzwania");
    }

    #[test]
    fn test_fiat_shamir_indices_uniqueness() {
        let mut t = FiatShamirTranscript::new(b"LigeroTest");
        t.append_root(b"merkle_root", &[0x42; 32]);

        let indices = t.challenge_indices(b"column_queries", 100, 15);
        assert_eq!(indices.len(), 15);

        // Sprawdzamy zakres i brak duplikatów
        for i in 0..indices.len() - 1 {
            assert!(indices[i] < indices[i + 1]);
            assert!(indices[i] < 100);
        }
        assert!(indices.last().unwrap() < &100);
    }
}
