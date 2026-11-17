use ark_ff::Field;
use ark_std::rand::RngCore;

/// Zestaw masek One-Time Pad (OTP) dla pojedynczej redukcji warstwy w Protokole 2.5.
///
/// Zgodnie z Rozdziałem 2.3 artykułu Frigo & shelat:
/// Wszystkie wiadomości przesyłane w trakcie protokołu Sumcheck są maskowane
/// niezależnymi, jednostajnie losowymi elementami ciała $\mathbb{F}_p$.
/// Maski te są dołączane do świadka i zaangażowane z góry w schemacie Ligero:
/// $w' = (w, \mathbf{pad})$.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerPads<F: Field> {
    /// Maski dla poszczególnych rund sumchecka.
    /// Dla każdej rundy $i \in \{0, \dots, R-1\}$ losowane są 3 maski:
    /// `[pad_{i,0}, pad_{i,1}, pad_{i,2}]` dla ewaluacji wielomianu $p_i(0), p_i(1), p_i(2)$.
    pub round_pads: Vec<[F; 3]>,

    /// Maska dla ewaluacji multilinearnej lewego wejścia: $\text{pad}_L$.
    pub pad_l: F,

    /// Maska dla ewaluacji multilinearnej prawego wejścia: $\text{pad}_R$.
    pub pad_r: F,
}

impl<F: Field> LayerPads<F> {
    /// Losuje zestaw kryptograficznych masek OTP dla zadanej liczby rund sumchecka.
    pub fn sample<R: RngCore>(num_rounds: usize, rng: &mut R) -> Self {
        let mut round_pads = Vec::with_capacity(num_rounds);
        for _ in 0..num_rounds {
            let p0 = F::rand(rng);
            let p1 = F::rand(rng);
            let p2 = F::rand(rng);
            round_pads.push([p0, p1, p2]);
        }
        let pad_l = F::rand(rng);
        let pad_r = F::rand(rng);

        Self {
            round_pads,
            pad_l,
            pad_r,
        }
    }

    /// Spłaszcza wszystkie maski do pojedynczego wektora elementów ciała $\mathbb{F}_p$
    /// o długości $3 \cdot R + 2$.
    pub fn to_vec(&self) -> Vec<F> {
        let mut vec = Vec::with_capacity(self.round_pads.len() * 3 + 2);
        for round in &self.round_pads {
            vec.push(round[0]);
            vec.push(round[1]);
            vec.push(round[2]);
        }
        vec.push(self.pad_l);
        vec.push(self.pad_r);
        vec
    }

    /// Odtwarza strukturę `LayerPads` z płaskiego wektora elementów ciała.
    pub fn from_slice(slice: &[F], num_rounds: usize) -> Self {
        let expected_len = num_rounds * 3 + 2;
        assert_eq!(
            slice.len(),
            expected_len,
            "Nieprawidłowa długość wektora masek: oczekiwano {}, otrzymano {}",
            expected_len,
            slice.len()
        );

        let mut round_pads = Vec::with_capacity(num_rounds);
        for i in 0..num_rounds {
            let offset = i * 3;
            round_pads.push([slice[offset], slice[offset + 1], slice[offset + 2]]);
        }
        let pad_l = slice[num_rounds * 3];
        let pad_r = slice[num_rounds * 3 + 1];

        Self {
            round_pads,
            pad_l,
            pad_r,
        }
    }

    /// Liczba wszystkich elementów maskujących: $3 \cdot R + 2$.
    pub fn total_len(&self) -> usize {
        self.round_pads.len() * 3 + 2
    }
}

/// Zamaskowany wielomian stopnia 2 wysyłany w rundzie sumchecka:
/// $P_i(X) = p_i(X) + \text{pad}_i$.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskedRoundPoly<F: Field> {
    pub eval_0: F, // p(0) + pad_0
    pub eval_1: F, // p(1) + pad_1
    pub eval_2: F, // p(2) + pad_2
}

impl<F: Field> MaskedRoundPoly<F> {
    /// Maskuje autentyczny wielomian $p$ za pomocą masek $[pad_0, pad_1, pad_2]$.
    pub fn mask(unmasked_evals: [F; 3], pads: [F; 3]) -> Self {
        Self {
            eval_0: unmasked_evals[0] + pads[0],
            eval_1: unmasked_evals[1] + pads[1],
            eval_2: unmasked_evals[2] + pads[2],
        }
    }

    /// Zwraca ewaluacje w postaci tablicy 3-elementowej.
    pub fn as_array(&self) -> [F; 3] {
        [self.eval_0, self.eval_1, self.eval_2]
    }
}

/// Zamaskowany transkrypt redukcji warstwy przekazywany weryfikatorowi: $T'$.
/// Zapewnia doskonałą wiedzę zerową (One-Time Pad Information-Theoretic Security).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskedTranscript<F: Field> {
    /// Zamaskowane wielomiany wszystkich rund sumchecka dla warstwy.
    pub rounds: Vec<MaskedRoundPoly<F>>,

    /// Zamaskowana ewaluacja wejścia lewego: $W_L = w(L) + \text{pad}_L$.
    pub masked_w_l: F,

    /// Zamaskowana ewaluacja wejścia prawego: $W_R = w(R) + \text{pad}_R$.
    pub masked_w_r: F,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::MontConfig;
    use ark_std::test_rng;

    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    pub struct FqConfig;
    pub type F17 = ark_ff::Fp64<ark_ff::MontBackend<FqConfig, 1>>;

    #[test]
    fn test_pads_serialization_roundtrip() {
        let mut rng = test_rng();
        let pads = LayerPads::<F17>::sample(4, &mut rng);

        assert_eq!(pads.total_len(), 4 * 3 + 2); // 14 elementów
        let vec = pads.to_vec();
        assert_eq!(vec.len(), 14);

        let restored = LayerPads::<F17>::from_slice(&vec, 4);
        assert_eq!(pads, restored);
    }

    #[test]
    fn test_masked_round_poly() {
        let p = [F17::from(3u64), F17::from(5u64), F17::from(7u64)];
        let pad = [F17::from(10u64), F17::from(12u64), F17::from(15u64)];

        let masked = MaskedRoundPoly::mask(p, pad);
        // 3+10 = 13 (mod 17)
        // 5+12 = 17 = 0 (mod 17)
        // 7+15 = 22 = 5 (mod 17)
        assert_eq!(masked.eval_0, F17::from(13u64));
        assert_eq!(masked.eval_1, F17::from(0u64));
        assert_eq!(masked.eval_2, F17::from(5u64));
    }
}
