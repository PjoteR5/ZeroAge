use ark_ff::One;
use ark_std::test_rng;
use std::time::Instant;

use zkp_core::circuit::{CircuitLayer, LayeredCircuit, QuadGate, QuadTerm};
use zkp_core::field::{Fp256, F64};
use zkp_core::merkle::MerkleTree;
use zkp_core::protocol25::{Protocol25Params, Protocol25Prover, Protocol25Verifier};
use zkp_core::rs_code::ReedSolomonEncoder;
use zkp_core::transcript::FiatShamirTranscript;

#[test]
fn test_benchmark_reed_solomon_and_merkle_like_paper_table5() {
    println!("\n=== Benchmark Prymitywów Algebraicznych (Analog Tabeli 5 artykułu) ===");
    for &k in &[16usize, 32, 64] {
        let n = 4 * k; // stopa kodu 1/4 jak w Tabeli 5

        // F_p64
        let msg_64: Vec<F64> = (1..=k as u64).map(F64::from).collect();
        let t0 = Instant::now();
        let enc_64 = ReedSolomonEncoder::<F64>::new(k, n);
        let cw_64 = enc_64.encode(&msg_64);
        let rs_64_ms = t0.elapsed().as_secs_f64() * 1000.0;
        assert!(enc_64.verify_codeword(&cw_64));

        // F_p256
        let msg_256: Vec<Fp256> = (1..=k as u64).map(Fp256::from).collect();
        let t1 = Instant::now();
        let enc_256 = ReedSolomonEncoder::<Fp256>::new(k, n);
        let cw_256 = enc_256.encode(&msg_256);
        let bytes: Vec<Vec<u8>> = cw_256
            .iter()
            .map(|v| {
                let mut b = Vec::new();
                ark_serialize::CanonicalSerialize::serialize_compressed(v, &mut b).unwrap();
                b
            })
            .collect();
        let tree = MerkleTree::from_data_slices(&bytes);
        let rs_256_ms = t1.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(tree.num_leaves, n);

        println!(
            "  k={:2}, n={:3} | RS(Fp64): {:6.3} ms | RS+Merkle(Fp256): {:6.3} ms",
            k, n, rs_64_ms, rs_256_ms
        );
    }
}

#[test]
fn test_layered_protocol25_compliance_and_performance() {
    let mut rng = test_rng();

    // Obwód 2-warstwowy nad F_p256 sprawdzający: ((w[1] + w[2]) * w[3]) - 24 == 0
    // Warstwa wejściowa d=2 (szerokość 4): [1, 3, 5, 3] => (3+5)*3 = 24
    let layer1 = CircuitLayer::<Fp256>::new(
        1,
        4,
        3,
        vec![
            QuadGate::add(1, 1, 2),
            QuadGate::scale(2, 3, Fp256::one()),
        ],
    );
    let layer0 = CircuitLayer::<Fp256>::new(
        0,
        3,
        2,
        vec![QuadGate::new(
            1,
            vec![
                QuadTerm::mul(1, 2),
                QuadTerm::constant(-Fp256::from(24u64)),
            ],
        )],
    );
    let circuit = LayeredCircuit::new(vec![layer0, layer1], 4);
    let witness = vec![
        Fp256::one(),
        Fp256::from(3u64),
        Fp256::from(5u64),
        Fp256::from(3u64),
    ];
    let public_inputs = [(0usize, Fp256::one())];

    // Parametry: depth=2, rounds=(4+4)=8 => pads=24, total primary=4+24=28
    let params = Protocol25Params::new(6, 8, 16, 32, 8);

    let t_prove = Instant::now();
    let mut p_tr = FiatShamirTranscript::new(b"ZeroAge-Layered-Compliance-Test");
    let proof = Protocol25Prover::prove_layered(
        &circuit,
        &witness,
        &public_inputs,
        &params,
        &mut p_tr,
        &mut rng,
    )
    .expect("Dowód wielowarstwowy musi się wygenerować");
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;

    let t_verify = Instant::now();
    let mut v_tr = FiatShamirTranscript::new(b"ZeroAge-Layered-Compliance-Test");
    Protocol25Verifier::verify_layered(&circuit, &public_inputs, &params, &proof, &mut v_tr)
        .expect("Weryfikacja wielowarstwowa Protokołu 2.2 + 2.5 musi się powieść");
    let verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;

    println!(
        "\n=== Protokół 2.2 + 2.5 (Obwód 2-warstwowy F_p256) ===\n  Prover: {:.2} ms | Verifier: {:.2} ms",
        prove_ms, verify_ms
    );

    // Test negatywny: modyfikacja dowolnego elementu wielomianu kwadratowego musi zostać odrzucona
    let mut bad_proof = proof.clone();
    bad_proof.quad_check_codeword[params.k] += Fp256::one();
    let mut bad_v_tr = FiatShamirTranscript::new(b"ZeroAge-Layered-Compliance-Test");
    assert!(Protocol25Verifier::verify_layered(
        &circuit,
        &public_inputs,
        &params,
        &bad_proof,
        &mut bad_v_tr
    )
    .is_err());
}
