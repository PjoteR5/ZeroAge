use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;

use crate::circuit::layered::{build_eq_table, eq_eval, CircuitLayer, LayeredCircuit};
use crate::ligero::matrix::EncodedMatrix;
use crate::ligero::prover::LigeroProver;
use crate::ligero::verifier::LigeroVerifier;
use crate::merkle::MerkleProof;
use crate::protocol25::constraints::{lagrange_eval_degree2, LinearConstraint};
use crate::protocol25::pad::{LayerPads, MaskedRoundPoly, MaskedTranscript};
use crate::rs_code::ReedSolomonEncoder;
use crate::sumcheck::prover::SumcheckProver;
use crate::transcript::FiatShamirTranscript;

/// Parametry macierzy ZK-Ligero dla Protokołu 2.5.
/// - `m`: liczba wierszy danych + 1 wiersz maskujący (`m - 1` wierszy danych),
/// - `data_cols`: liczba kolumn danych w każdym wierszu ($\ell < k$),
/// - `k`: długość bazowa wiersza przed kodowaniem RS ($\ell + t_{\text{pad}}$, gdzie $t_{\text{pad}} \ge \text{open\_t}$),
/// - `n`: długość słowa kodowego po kodowaniu RS ($n \ge 2k$),
/// - `open_t`: liczba otwieranych kolumn z części parzystości $[k, n)$.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protocol25Params {
    pub m: usize,
    pub data_cols: usize,
    pub k: usize,
    pub n: usize,
    pub open_t: usize,
}

impl Protocol25Params {
    pub fn new(m: usize, data_cols: usize, k: usize, n: usize, open_t: usize) -> Self {
        assert!(m >= 2, "Wymagane co najmniej 2 wiersze (1 danych + 1 maskujący)");
        assert!(
            data_cols > 0 && data_cols + open_t <= k,
            "Wymagane data_cols + open_t <= k dla pełnej własności Zero-Knowledge wierszy"
        );
        assert!(
            n >= 2 * k && n - k >= open_t,
            "Wymagane n >= 2k oraz n - k >= open_t"
        );
        Self {
            m,
            data_cols,
            k,
            n,
            open_t,
        }
    }

    /// Całkowita liczba wierszy w macierzy Ligero (wiersze danych + 5 wierszy weryfikacji kwadratowej + 1 wiersz blind_dot).
    pub fn total_matrix_rows(&self) -> usize {
        (self.m - 1) + 6
    }
}

/// Kompletny nieinteraktywny dowód wiedzy zerowej (NIZK) Protokołu 2.5 dla obwodu jednowarstwowego.
#[derive(Clone, Debug)]
pub struct Protocol25Proof<F: PrimeField> {
    pub ligero_root: [u8; 32],
    pub masked_transcript: MaskedTranscript<F>,
    pub ligero_lin_comb: Vec<F>,
    pub dot_product_codeword: Vec<F>,
    pub quad_check_codeword: Vec<F>,
    pub ligero_openings: Vec<(usize, Vec<F>, MerkleProof)>,
}

/// Kompletny nieinteraktywny dowód wiedzy zerowej (NIZK) Protokołu 2.2 + 2.5
/// dla dowolnego wielowarstwowego obwodu `LayeredCircuit<F>`.
#[derive(Clone, Debug)]
pub struct LayeredProtocol25Proof<F: PrimeField> {
    pub ligero_root: [u8; 32],
    pub layer_transcripts: Vec<MaskedTranscript<F>>,
    pub ligero_lin_comb: Vec<F>,
    pub dot_product_codeword: Vec<F>,
    pub quad_check_codeword: Vec<F>,
    pub ligero_openings: Vec<(usize, Vec<F>, MerkleProof)>,
}

/// Oblicza wartość wielomianu $\psi(x) = x^{k - \ell} \prod_{j=0}^{\ell - 1} (x - j)$ w punkcie $x \in \mathbb{F}$.
fn eval_psi<F: PrimeField>(x_idx: usize, data_cols: usize, k: usize) -> F {
    let x = F::from(x_idx as u64);
    let mut acc = F::one();
    for j in 0..data_cols {
        acc *= x - F::from(j as u64);
    }
    let exp = k - data_cols;
    for _ in 0..exp {
        acc *= x;
    }
    acc
}

/// Wysokopoziomowy Prover Protokołu 2.2 + 2.5 (Sumcheck + OTP + ZK-Ligero z testem trójek kwadratowych).
pub struct Protocol25Prover;

impl Protocol25Prover {
    /// Dowodzi spełnienia pojedynczej warstwy obwodu `CircuitLayer<F>`.
    pub fn prove<F, R>(
        layer: &CircuitLayer<F>,
        witness_wires: &[F],
        public_inputs: &[(usize, F)],
        params: &Protocol25Params,
        transcript: &mut FiatShamirTranscript,
        rng: &mut R,
    ) -> Result<Protocol25Proof<F>, &'static str>
    where
        F: PrimeField + CanonicalSerialize,
        R: RngCore,
    {
        let circuit = LayeredCircuit::new(vec![layer.clone()], layer.in_width);
        let mut layered_proof = Self::prove_layered(
            &circuit,
            witness_wires,
            public_inputs,
            params,
            transcript,
            rng,
        )?;
        let masked_transcript = layered_proof
            .layer_transcripts
            .pop()
            .ok_or("Brak transkryptu warstwy")?;

        Ok(Protocol25Proof {
            ligero_root: layered_proof.ligero_root,
            masked_transcript,
            ligero_lin_comb: layered_proof.ligero_lin_comb,
            dot_product_codeword: layered_proof.dot_product_codeword,
            quad_check_codeword: layered_proof.quad_check_codeword,
            ligero_openings: layered_proof.ligero_openings,
        })
    }

    /// Dowodzi spełnienia pełnego wielowarstwowego obwodu `LayeredCircuit<F>` zgodnie z Protokołem 2.2 i 2.5.
    pub fn prove_layered<F, R>(
        circuit: &LayeredCircuit<F>,
        witness_wires: &[F],
        public_inputs: &[(usize, F)],
        params: &Protocol25Params,
        transcript: &mut FiatShamirTranscript,
        rng: &mut R,
    ) -> Result<LayeredProtocol25Proof<F>, &'static str>
    where
        F: PrimeField + CanonicalSerialize,
        R: RngCore,
    {
        let depth = circuit.depth();
        if depth == 0 || depth > params.data_cols {
            return Err("Głębokość obwodu musi mieścić się w przedziale 1..=params.data_cols");
        }
        if witness_wires.len() != circuit.input_width {
            return Err("Niezgodna długość wektora świadka z input_width obwodu");
        }

        let wire_values = circuit.evaluate_all(witness_wires);
        let v_0 = &wire_values[0];
        if v_0[0] != F::one() || v_0[1..].iter().any(|v| !v.is_zero()) {
            return Err("Świadek nie spełnia ograniczeń wyjścia obwodu (V_0 != 0)");
        }
        for &(idx, expected) in public_inputs {
            if idx >= witness_wires.len() || witness_wires[idx] != expected {
                return Err("Wektor świadka nie zgadza się z zadeklarowanymi wejściami publicznymi");
            }
        }

        // 1. Generujemy maski OTP dla wszystkich warstw j = 0 .. depth - 1
        let data_rows = params.m - 1;
        let mut layer_pads = Vec::with_capacity(depth);
        let mut total_round_pads = 0usize;
        for layer in &circuit.layers {
            let omega_in = layer.in_width.next_power_of_two().max(2).trailing_zeros() as usize;
            let num_rounds = 2 * omega_in;
            let pads = LayerPads::<F>::sample(num_rounds, rng);
            total_round_pads += num_rounds * 3;
            layer_pads.push(pads);
        }

        let primary_len = witness_wires.len() + total_round_pads;
        if data_rows * params.data_cols < primary_len {
            return Err("Parametry macierzy Ligero (m - 1) * data_cols są za małe na świadka i maski");
        }

        // 2. Układamy wiersze macierzy przed kodowaniem RS:
        //    - rows 0..data_rows: [witness_wires, round_pads wszystkich warstw]
        //    - row data_rows + 0 (row_a): pad_l dla każdej warstwy
        //    - row data_rows + 1 (row_b): pad_r dla każdej warstwy
        //    - row data_rows + 2 (row_z): pad_l * pad_r dla każdej warstwy
        //    - row data_rows + 3 (row_r0): zera na 0..data_cols, losowy ogon na data_cols..k
        //    - row data_rows + 4 (row_s): losowe elementy 0..k
        //    - row data_rows + 5 (row_blind_dot): losowe o sumie 0 na 0..data_cols + losowy ogon
        let mut raw_rows = Vec::with_capacity(params.total_matrix_rows());
        let mut flat_primary = Vec::with_capacity(data_rows * params.data_cols);
        flat_primary.extend_from_slice(witness_wires);
        for pads in &layer_pads {
            for round in &pads.round_pads {
                flat_primary.extend_from_slice(round);
            }
        }
        flat_primary.resize(data_rows * params.data_cols, F::zero());

        for r in 0..data_rows {
            let mut row = Vec::with_capacity(params.k);
            let start = r * params.data_cols;
            row.extend_from_slice(&flat_primary[start..start + params.data_cols]);
            for _ in params.data_cols..params.k {
                row.push(F::rand(rng));
            }
            raw_rows.push(row);
        }

        let mut row_a = vec![F::zero(); params.k];
        let mut row_b = vec![F::zero(); params.k];
        let mut row_z = vec![F::zero(); params.k];
        for (j, pads) in layer_pads.iter().enumerate() {
            row_a[j] = pads.pad_l;
            row_b[j] = pads.pad_r;
            row_z[j] = pads.pad_l * pads.pad_r;
        }
        for col in params.data_cols..params.k {
            row_a[col] = F::rand(rng);
            row_b[col] = F::rand(rng);
            row_z[col] = F::rand(rng);
        }
        raw_rows.push(row_a);
        raw_rows.push(row_b);
        raw_rows.push(row_z);

        let mut row_r0 = vec![F::zero(); params.k];
        for col in params.data_cols..params.k {
            row_r0[col] = F::rand(rng);
        }
        raw_rows.push(row_r0);

        let row_s: Vec<F> = (0..params.k).map(|_| F::rand(rng)).collect();
        raw_rows.push(row_s);

        let mut row_blind_dot = Vec::with_capacity(params.k);
        let mut sum_prefix = F::zero();
        for _ in 0..(params.data_cols - 1) {
            let r = F::rand(rng);
            sum_prefix += r;
            row_blind_dot.push(r);
        }
        row_blind_dot.push(-sum_prefix);
        for _ in params.data_cols..params.k {
            row_blind_dot.push(F::rand(rng));
        }
        raw_rows.push(row_blind_dot);

        // Tworzymy wektor spłaszczony dla wszystkich nie-blind_dot wierszy do sprawdzania dot-product
        let non_blind_rows = data_rows + 5;
        let flat_w_len = non_blind_rows * params.data_cols;
        let mut flat_w = Vec::with_capacity(flat_w_len);
        for r in 0..non_blind_rows {
            flat_w.extend_from_slice(&raw_rows[r][..params.data_cols]);
        }

        let matrix = EncodedMatrix::from_raw_rows(&raw_rows, params.k, params.n);
        let ligero_prover = LigeroProver::from_encoded_matrix(matrix);
        let ligero_root = ligero_prover.commitment();
        transcript.append_root(b"ligero_root", &ligero_root);

        // 3. Wielowarstwowy zamaskowany Sumcheck (Protokół 2.2 + 2.5)
        let row_a_idx = data_rows;
        let row_b_idx = data_rows + 1;
        let row_z_idx = data_rows + 2;
        let row_r0_idx = data_rows + 3;
        let row_s_idx = data_rows + 4;

        let omega_0 = circuit.layers[0]
            .out_width
            .next_power_of_two()
            .max(2)
            .trailing_zeros() as usize;
        let r_init: Vec<F> = transcript.challenge_scalars(b"r_out", omega_0);
        let initial_claim_0 = eq_eval(&r_init, 0);
        transcript.append_field_element(b"claim_y0", &initial_claim_0);

        let mut r_out_0 = r_init.clone();
        let mut r_out_1 = r_init;
        let mut layer_transcripts = Vec::with_capacity(depth);
        let mut linear_constraints = Vec::new();

        let mut pad_cursor = witness_wires.len();
        let mut prev_masked_w: Option<(F, F)> = None;
        let mut final_lr: Option<(Vec<F>, Vec<F>)> = None;

        for j in 0..depth {
            let layer = &circuit.layers[j];
            let pads = &layer_pads[j];
            let omega_in = layer.in_width.next_power_of_two().max(2).trailing_zeros() as usize;
            let num_rounds = 2 * omega_in;

            let alpha_j: F = transcript.challenge_scalar(b"alpha_j");
            let mut sc_prover = SumcheckProver::new(
                layer.clone(),
                alpha_j,
                r_out_0.clone(),
                r_out_1.clone(),
                &wire_values[j + 1],
            );

            let mut rounds = Vec::with_capacity(num_rounds);
            let mut challenges = Vec::with_capacity(num_rounds);
            for r_idx in 0..num_rounds {
                let poly = sc_prover.compute_round_poly();
                let masked = MaskedRoundPoly::mask(
                    [poly.eval_0, poly.eval_1, poly.eval_2],
                    pads.round_pads[r_idx],
                );
                transcript.append_field_elements(b"round_poly", &masked.as_array());
                let ch: F = transcript.challenge_scalar(b"challenge_r");
                sc_prover.receive_challenge(ch);
                rounds.push(masked);
                challenges.push(ch);
            }

            let (w_l, w_r) = sc_prover.compute_next_claims();
            let masked_w_l = w_l + pads.pad_l;
            let masked_w_r = w_r + pads.pad_r;
            transcript.append_field_element(b"masked_w_l", &masked_w_l);
            transcript.append_field_element(b"masked_w_r", &masked_w_r);

            // Więzy liniowe rund Sumchecka dla warstwy j:
            // Runda 0: powiązanie z claim_0 (j=0) lub z poprzednią warstwą (j>0)
            {
                let mut weights = vec![F::zero(); flat_w_len];
                weights[pad_cursor] = F::one();
                weights[pad_cursor + 1] = F::one();
                let target = if let Some((prev_wl, prev_wr)) = prev_masked_w {
                    let prev_pad_l_idx = row_a_idx * params.data_cols + (j - 1);
                    let prev_pad_r_idx = row_b_idx * params.data_cols + (j - 1);
                    weights[prev_pad_l_idx] = -alpha_j;
                    weights[prev_pad_r_idx] = -(F::one() - alpha_j);
                    let pub_y = alpha_j * prev_wl + (F::one() - alpha_j) * prev_wr;
                    rounds[0].eval_0 + rounds[0].eval_1 - pub_y
                } else {
                    rounds[0].eval_0 + rounds[0].eval_1 - initial_claim_0
                };
                linear_constraints.push(LinearConstraint::new(weights, target));
            }

            // Rundy pośrednie i = 0..num_rounds-2
            for i in 0..(num_rounds - 1) {
                let lambdas = lagrange_eval_degree2(challenges[i]);
                let mut weights = vec![F::zero(); flat_w_len];
                let next_base = pad_cursor + (i + 1) * 3;
                let cur_base = pad_cursor + i * 3;
                weights[next_base] = F::one();
                weights[next_base + 1] = F::one();
                weights[cur_base] = -lambdas[0];
                weights[cur_base + 1] = -lambdas[1];
                weights[cur_base + 2] = -lambdas[2];

                let p_cur = &rounds[i];
                let p_next = &rounds[i + 1];
                let lambda_dot_p = lambdas[0] * p_cur.eval_0
                    + lambdas[1] * p_cur.eval_1
                    + lambdas[2] * p_cur.eval_2;
                let target = p_next.eval_0 + p_next.eval_1 - lambda_dot_p;
                linear_constraints.push(LinearConstraint::new(weights, target));
            }

            // Zlinearyzowane ograniczenie kwadratowe na końcu warstwy j
            let l_j = challenges[0..omega_in].to_vec();
            let r_j = challenges[omega_in..2 * omega_in].to_vec();
            let q0 = layer.eval_wiring_predicate(&r_out_0, &l_j, &r_j);
            let q1 = layer.eval_wiring_predicate(&r_out_1, &l_j, &r_j);
            let q_eval = alpha_j * q0 + (F::one() - alpha_j) * q1;

            let ell = num_rounds - 1;
            let lambdas_ell = lagrange_eval_degree2(challenges[ell]);
            let p_ell = &rounds[ell];
            let lambda_dot_p_ell = lambdas_ell[0] * p_ell.eval_0
                + lambdas_ell[1] * p_ell.eval_1
                + lambdas_ell[2] * p_ell.eval_2;
            let quad_target = lambda_dot_p_ell - q_eval * masked_w_l * masked_w_r;

            let mut quad_weights = vec![F::zero(); flat_w_len];
            let ell_base = pad_cursor + ell * 3;
            quad_weights[ell_base] = lambdas_ell[0];
            quad_weights[ell_base + 1] = lambdas_ell[1];
            quad_weights[ell_base + 2] = lambdas_ell[2];
            quad_weights[row_a_idx * params.data_cols + j] = -q_eval * masked_w_r;
            quad_weights[row_b_idx * params.data_cols + j] = -q_eval * masked_w_l;
            quad_weights[row_z_idx * params.data_cols + j] = q_eval;
            linear_constraints.push(LinearConstraint::new(quad_weights, quad_target));

            pad_cursor += num_rounds * 3;
            prev_masked_w = Some((masked_w_l, masked_w_r));
            r_out_0 = l_j.clone();
            r_out_1 = r_j.clone();
            final_lr = Some((l_j, r_j));
            layer_transcripts.push(MaskedTranscript {
                rounds,
                masked_w_l,
                masked_w_r,
            });
        }

        // 4. Więzy MLE wiążące ostatnią warstwę z zaangażowanymi wejściami V_d (flat_w[0..input_width])
        let (final_l, final_r) = final_lr.expect("Obwód ma co najmniej 1 warstwę");
        let (last_wl, last_wr) = prev_masked_w.expect("Obwód ma co najmniej 1 warstwę");
        let last_idx = depth - 1;
        let last_pad_l_idx = row_a_idx * params.data_cols + last_idx;
        let last_pad_r_idx = row_b_idx * params.data_cols + last_idx;

        for (target_val, point, pad_idx) in [
            (last_wl, &final_l, last_pad_l_idx),
            (last_wr, &final_r, last_pad_r_idx),
        ] {
            let mut weights = vec![F::zero(); flat_w_len];
            if point.len() <= 20 {
                let eq_tbl = build_eq_table(point);
                let copy_len = witness_wires.len().min(eq_tbl.len());
                weights[..copy_len].copy_from_slice(&eq_tbl[..copy_len]);
                for k in copy_len..witness_wires.len() {
                    weights[k] = eq_eval(point, k);
                }
            } else {
                for k in 0..witness_wires.len() {
                    weights[k] = eq_eval(point, k);
                }
            }
            weights[pad_idx] = F::one();
            linear_constraints.push(LinearConstraint::new(weights, target_val));
        }

        // 5. Więzy wiążące publiczne wejścia z zaangażowanym świadkiem
        for &(wire_idx, expected_val) in public_inputs {
            if wire_idx >= witness_wires.len() {
                return Err("Indeks wejścia publicznego poza szerokością obwodu");
            }
            let mut weights = vec![F::zero(); flat_w_len];
            weights[wire_idx] = F::one();
            linear_constraints.push(LinearConstraint::new(weights, expected_val));
        }

        // 6. Więzy zerujące część danych wiersza R_0 (0..data_cols == 0)
        for col in 0..params.data_cols {
            let mut weights = vec![F::zero(); flat_w_len];
            weights[row_r0_idx * params.data_cols + col] = F::one();
            linear_constraints.push(LinearConstraint::new(weights, F::zero()));
        }

        // 7. Kompresja wszystkich więzów liniowych w jedno sprawdzenie dot-product Ligero
        let betas: Vec<F> = transcript.challenge_scalars(b"p25_betas", linear_constraints.len());
        let mut combined_weights = vec![F::zero(); flat_w_len];
        let mut combined_target = F::zero();
        for (c, &beta) in linear_constraints.iter().zip(betas.iter()) {
            combined_target += beta * c.target;
            for (dst, &src) in combined_weights.iter_mut().zip(c.weights.iter()) {
                *dst += beta * src;
            }
        }
        debug_assert_eq!(
            combined_weights
                .iter()
                .zip(flat_w.iter())
                .map(|(&a, &w)| a * w)
                .sum::<F>(),
            combined_target
        );

        let dot_product_codeword =
            ligero_prover.prove_dot_product_constraint(&combined_weights, params.data_cols);

        // 8. Wielomian weryfikacji trójek kwadratowych P_quad(x) = A(x)*B(x) - Z(x) + R0(x) + psi(x)*S(x)
        let row_a_cw = ligero_prover.matrix.get_row(row_a_idx);
        let row_b_cw = ligero_prover.matrix.get_row(row_b_idx);
        let row_z_cw = ligero_prover.matrix.get_row(row_z_idx);
        let row_r0_cw = ligero_prover.matrix.get_row(row_r0_idx);
        let row_s_cw = ligero_prover.matrix.get_row(row_s_idx);

        let mut quad_check_codeword = Vec::with_capacity(params.n);
        for x in 0..params.n {
            let psi = eval_psi::<F>(x, params.data_cols, params.k);
            let val = row_a_cw[x] * row_b_cw[x] - row_z_cw[x] + row_r0_cw[x] + psi * row_s_cw[x];
            quad_check_codeword.push(val);
        }

        transcript.append_field_elements(b"p25_dot_codeword", &dot_product_codeword);
        transcript.append_field_elements(b"p25_quad_codeword", &quad_check_codeword);

        let total_rows = params.total_matrix_rows();
        let mut row_weights: Vec<F> = transcript.challenge_scalars(b"row_weights", total_rows - 1);
        row_weights.push(F::one());
        let ligero_lin_comb = ligero_prover.answer_linear_combination(&row_weights);
        transcript.append_field_elements(b"ligero_lin_comb", &ligero_lin_comb);

        let queried_cols = transcript.challenge_indices_in_range(
            b"col_queries",
            params.k,
            params.n,
            params.open_t,
        );
        let ligero_openings = ligero_prover.open_columns(&queried_cols);

        Ok(LayeredProtocol25Proof {
            ligero_root,
            layer_transcripts,
            ligero_lin_comb,
            dot_product_codeword,
            quad_check_codeword,
            ligero_openings,
        })
    }
}

/// Wysokopoziomowy Weryfikator Protokołu 2.2 + 2.5.
pub struct Protocol25Verifier;

impl Protocol25Verifier {
    /// Weryfikuje dowód dla pojedynczej warstwy obwodu `CircuitLayer<F>`.
    pub fn verify<F>(
        layer: &CircuitLayer<F>,
        public_inputs: &[(usize, F)],
        params: &Protocol25Params,
        proof: &Protocol25Proof<F>,
        transcript: &mut FiatShamirTranscript,
    ) -> Result<(), &'static str>
    where
        F: PrimeField + CanonicalSerialize,
    {
        let circuit = LayeredCircuit::new(vec![layer.clone()], layer.in_width);
        let layered_proof = LayeredProtocol25Proof {
            ligero_root: proof.ligero_root,
            layer_transcripts: vec![proof.masked_transcript.clone()],
            ligero_lin_comb: proof.ligero_lin_comb.clone(),
            dot_product_codeword: proof.dot_product_codeword.clone(),
            quad_check_codeword: proof.quad_check_codeword.clone(),
            ligero_openings: proof.ligero_openings.clone(),
        };
        Self::verify_layered(&circuit, public_inputs, params, &layered_proof, transcript)
    }

    /// Weryfikuje kompletny wielowarstwowy dowód Protokołu 2.2 + 2.5 dla `LayeredCircuit<F>`.
    pub fn verify_layered<F>(
        circuit: &LayeredCircuit<F>,
        public_inputs: &[(usize, F)],
        params: &Protocol25Params,
        proof: &LayeredProtocol25Proof<F>,
        transcript: &mut FiatShamirTranscript,
    ) -> Result<(), &'static str>
    where
        F: PrimeField + CanonicalSerialize,
    {
        let depth = circuit.depth();
        if depth == 0 || depth > params.data_cols {
            return Err("Nieprawidłowa głębokość obwodu dla parametrów Protokołu 2.5");
        }
        if proof.layer_transcripts.len() != depth {
            return Err("Liczba transkryptów warstw nie zgadza się z głębokością obwodu");
        }
        if proof.ligero_openings.len() != params.open_t {
            return Err("Nieprawidłowa liczba otwartych kolumn Ligero");
        }
        if proof.quad_check_codeword.len() != params.n {
            return Err("Nieprawidłowa długość wielomianu weryfikacji kwadratowej");
        }

        let data_rows = params.m - 1;
        let row_a_idx = data_rows;
        let row_b_idx = data_rows + 1;
        let row_z_idx = data_rows + 2;
        let row_r0_idx = data_rows + 3;
        let row_s_idx = data_rows + 4;
        let non_blind_rows = data_rows + 5;
        let flat_w_len = non_blind_rows * params.data_cols;

        transcript.append_root(b"ligero_root", &proof.ligero_root);

        let omega_0 = circuit.layers[0]
            .out_width
            .next_power_of_two()
            .max(2)
            .trailing_zeros() as usize;
        let r_init: Vec<F> = transcript.challenge_scalars(b"r_out", omega_0);
        let initial_claim_0 = eq_eval(&r_init, 0);
        transcript.append_field_element(b"claim_y0", &initial_claim_0);

        let mut r_out_0 = r_init.clone();
        let mut r_out_1 = r_init;
        let mut linear_constraints = Vec::new();
        let mut pad_cursor = circuit.input_width;
        let mut prev_masked_w: Option<(F, F)> = None;
        let mut final_lr: Option<(Vec<F>, Vec<F>)> = None;

        for j in 0..depth {
            let layer = &circuit.layers[j];
            let layer_tr = &proof.layer_transcripts[j];
            let omega_in = layer.in_width.next_power_of_two().max(2).trailing_zeros() as usize;
            let num_rounds = 2 * omega_in;

            if layer_tr.rounds.len() != num_rounds {
                return Err("Nieprawidłowa liczba rund Sumchecka w warstwie obwodu");
            }

            let alpha_j: F = transcript.challenge_scalar(b"alpha_j");
            let mut challenges = Vec::with_capacity(num_rounds);
            for masked in &layer_tr.rounds {
                transcript.append_field_elements(b"round_poly", &masked.as_array());
                let ch: F = transcript.challenge_scalar(b"challenge_r");
                challenges.push(ch);
            }

            transcript.append_field_element(b"masked_w_l", &layer_tr.masked_w_l);
            transcript.append_field_element(b"masked_w_r", &layer_tr.masked_w_r);

            {
                let mut weights = vec![F::zero(); flat_w_len];
                weights[pad_cursor] = F::one();
                weights[pad_cursor + 1] = F::one();
                let target = if let Some((prev_wl, prev_wr)) = prev_masked_w {
                    let prev_pad_l_idx = row_a_idx * params.data_cols + (j - 1);
                    let prev_pad_r_idx = row_b_idx * params.data_cols + (j - 1);
                    weights[prev_pad_l_idx] = -alpha_j;
                    weights[prev_pad_r_idx] = -(F::one() - alpha_j);
                    let pub_y = alpha_j * prev_wl + (F::one() - alpha_j) * prev_wr;
                    layer_tr.rounds[0].eval_0 + layer_tr.rounds[0].eval_1 - pub_y
                } else {
                    layer_tr.rounds[0].eval_0 + layer_tr.rounds[0].eval_1 - initial_claim_0
                };
                linear_constraints.push(LinearConstraint::new(weights, target));
            }

            for i in 0..(num_rounds - 1) {
                let lambdas = lagrange_eval_degree2(challenges[i]);
                let mut weights = vec![F::zero(); flat_w_len];
                let next_base = pad_cursor + (i + 1) * 3;
                let cur_base = pad_cursor + i * 3;
                weights[next_base] = F::one();
                weights[next_base + 1] = F::one();
                weights[cur_base] = -lambdas[0];
                weights[cur_base + 1] = -lambdas[1];
                weights[cur_base + 2] = -lambdas[2];

                let p_cur = &layer_tr.rounds[i];
                let p_next = &layer_tr.rounds[i + 1];
                let lambda_dot_p = lambdas[0] * p_cur.eval_0
                    + lambdas[1] * p_cur.eval_1
                    + lambdas[2] * p_cur.eval_2;
                let target = p_next.eval_0 + p_next.eval_1 - lambda_dot_p;
                linear_constraints.push(LinearConstraint::new(weights, target));
            }

            let l_j = challenges[0..omega_in].to_vec();
            let r_j = challenges[omega_in..2 * omega_in].to_vec();
            let q0 = layer.eval_wiring_predicate(&r_out_0, &l_j, &r_j);
            let q1 = layer.eval_wiring_predicate(&r_out_1, &l_j, &r_j);
            let q_eval = alpha_j * q0 + (F::one() - alpha_j) * q1;

            let ell = num_rounds - 1;
            let lambdas_ell = lagrange_eval_degree2(challenges[ell]);
            let p_ell = &layer_tr.rounds[ell];
            let lambda_dot_p_ell = lambdas_ell[0] * p_ell.eval_0
                + lambdas_ell[1] * p_ell.eval_1
                + lambdas_ell[2] * p_ell.eval_2;
            let quad_target =
                lambda_dot_p_ell - q_eval * layer_tr.masked_w_l * layer_tr.masked_w_r;

            let mut quad_weights = vec![F::zero(); flat_w_len];
            let ell_base = pad_cursor + ell * 3;
            quad_weights[ell_base] = lambdas_ell[0];
            quad_weights[ell_base + 1] = lambdas_ell[1];
            quad_weights[ell_base + 2] = lambdas_ell[2];
            quad_weights[row_a_idx * params.data_cols + j] = -q_eval * layer_tr.masked_w_r;
            quad_weights[row_b_idx * params.data_cols + j] = -q_eval * layer_tr.masked_w_l;
            quad_weights[row_z_idx * params.data_cols + j] = q_eval;
            linear_constraints.push(LinearConstraint::new(quad_weights, quad_target));

            pad_cursor += num_rounds * 3;
            prev_masked_w = Some((layer_tr.masked_w_l, layer_tr.masked_w_r));
            r_out_0 = l_j.clone();
            r_out_1 = r_j.clone();
            final_lr = Some((l_j, r_j));
        }

        if pad_cursor > data_rows * params.data_cols {
            return Err("Rozmiar świadka i masek przekracza parametry macierzy Ligero");
        }

        let (final_l, final_r) = final_lr.ok_or("Brak warstw w obwodzie")?;
        let (last_wl, last_wr) = prev_masked_w.ok_or("Brak roszczeń wejściowych")?;
        let last_idx = depth - 1;
        let last_pad_l_idx = row_a_idx * params.data_cols + last_idx;
        let last_pad_r_idx = row_b_idx * params.data_cols + last_idx;

        for (target_val, point, pad_idx) in [
            (last_wl, &final_l, last_pad_l_idx),
            (last_wr, &final_r, last_pad_r_idx),
        ] {
            let mut weights = vec![F::zero(); flat_w_len];
            if point.len() <= 20 {
                let eq_tbl = build_eq_table(point);
                let copy_len = circuit.input_width.min(eq_tbl.len());
                weights[..copy_len].copy_from_slice(&eq_tbl[..copy_len]);
                for k in copy_len..circuit.input_width {
                    weights[k] = eq_eval(point, k);
                }
            } else {
                for k in 0..circuit.input_width {
                    weights[k] = eq_eval(point, k);
                }
            }
            weights[pad_idx] = F::one();
            linear_constraints.push(LinearConstraint::new(weights, target_val));
        }

        for &(wire_idx, expected_val) in public_inputs {
            if wire_idx >= circuit.input_width {
                return Err("Indeks wejścia publicznego poza szerokością obwodu");
            }
            let mut weights = vec![F::zero(); flat_w_len];
            weights[wire_idx] = F::one();
            linear_constraints.push(LinearConstraint::new(weights, expected_val));
        }

        for col in 0..params.data_cols {
            let mut weights = vec![F::zero(); flat_w_len];
            weights[row_r0_idx * params.data_cols + col] = F::one();
            linear_constraints.push(LinearConstraint::new(weights, F::zero()));
        }

        let betas: Vec<F> = transcript.challenge_scalars(b"p25_betas", linear_constraints.len());
        let mut combined_weights = vec![F::zero(); flat_w_len];
        let mut combined_target = F::zero();
        for (c, &beta) in linear_constraints.iter().zip(betas.iter()) {
            combined_target += beta * c.target;
            for (dst, &src) in combined_weights.iter_mut().zip(c.weights.iter()) {
                *dst += beta * src;
            }
        }

        transcript.append_field_elements(b"p25_dot_codeword", &proof.dot_product_codeword);
        transcript.append_field_elements(b"p25_quad_codeword", &proof.quad_check_codeword);

        let total_rows = params.total_matrix_rows();
        let mut row_weights: Vec<F> = transcript.challenge_scalars(b"row_weights", total_rows - 1);
        row_weights.push(F::one());
        transcript.append_field_elements(b"ligero_lin_comb", &proof.ligero_lin_comb);

        let expected_cols = transcript.challenge_indices_in_range(
            b"col_queries",
            params.k,
            params.n,
            params.open_t,
        );
        for ((idx, _, _), exp) in proof.ligero_openings.iter().zip(expected_cols.iter()) {
            if idx != exp {
                return Err("Niezgodność indeksów otwartych kolumn z wyzwaniami Fiata-Shamira");
            }
        }

        let ligero_verifier = LigeroVerifier::<F>::new(total_rows, params.k, params.n);
        if !ligero_verifier.verify_openings(&proof.ligero_root, &proof.ligero_openings) {
            return Err("Błąd weryfikacji ścieżek Drzewa Merkle'a w Ligero");
        }
        if !ligero_verifier.verify_linear_combination(
            &proof.ligero_lin_comb,
            &row_weights,
            &proof.ligero_openings,
        ) {
            return Err("Błąd weryfikacji bliskości kodu Reeda-Solomona w Ligero");
        }
        if !ligero_verifier.verify_dot_product_constraint(
            &combined_weights,
            combined_target,
            &proof.dot_product_codeword,
            params.data_cols,
            &proof.ligero_openings,
        ) {
            return Err("Więzy liniowe Protokołu 2.5 nie zostały spełnione przez zaangażowanego świadka");
        }

        // Weryfikacja wielomianu trójek kwadratowych P_quad(x) = A(x)*B(x) - Z(x) + R0(x) + psi(x)*S(x)
        let encoder_2k = ReedSolomonEncoder::<F>::new(2 * params.k, params.n);
        if !encoder_2k.verify_codeword(&proof.quad_check_codeword) {
            return Err("Wielomian trójek kwadratowych przekroczył dopuszczalny stopień 2k");
        }
        if proof.quad_check_codeword[..params.data_cols]
            .iter()
            .any(|v| !v.is_zero())
        {
            return Err("Wielomian trójek kwadratowych nie zeruje się na kolumnach danych");
        }
        for (col_idx, col_vals, _) in &proof.ligero_openings {
            let c = *col_idx;
            let psi = eval_psi::<F>(c, params.data_cols, params.k);
            let expected_quad = col_vals[row_a_idx] * col_vals[row_b_idx]
                - col_vals[row_z_idx]
                + col_vals[row_r0_idx]
                + psi * col_vals[row_s_idx];
            if proof.quad_check_codeword[c] != expected_quad {
                return Err("Niezgodność iloczynu pad_L * pad_R na otwartej kolumnie Ligero");
            }
        }

        Ok(())
    }
}
