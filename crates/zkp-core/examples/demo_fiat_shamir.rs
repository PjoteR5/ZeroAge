use ark_ff::MontConfig;
use zkp_core::transcript::FiatShamirTranscript;

#[derive(MontConfig)]
#[modulus = "17"]
#[generator = "3"]
pub struct FqConfig;
pub type F17 = ark_ff::Fp64<ark_ff::MontBackend<FqConfig, 1>>;

fn main() {
    println!("=== Demonstracja Kompilatora Fiat-Shamir (merlin) ===");

    let mut prover_transcript = FiatShamirTranscript::new(b"ZKP-ECDSA-Credential");
    let mut verifier_transcript = FiatShamirTranscript::new(b"ZKP-ECDSA-Credential");

    // Symulacja etapu 1: Prover wysyła korzeń zaangażowania Merkle'a
    let merkle_root = [0x5au8; 32];
    println!("1. Prover publikuje zaangażowanie Merkle root: {:02x?}...", &merkle_root[..4]);
    prover_transcript.append_root(b"ligero_root", &merkle_root);
    verifier_transcript.append_root(b"ligero_root", &merkle_root);

    // Symulacja etapu 2: Wyciśnięcie losowych wag kombinacji liniowej (Fiat-Shamir challenge)
    let prover_alpha: F17 = prover_transcript.challenge_scalar(b"alpha_weights");
    let verifier_alpha: F17 = verifier_transcript.challenge_scalar(b"alpha_weights");
    println!("2. Wygenerowane wyzwanie skalarne alpha (F_17): {:?}", prover_alpha);
    assert_eq!(prover_alpha, verifier_alpha);

    // Symulacja etapu 3: Prover wysyła wielomian rundy sumchecka g(X)
    let g_evals = [F17::from(5u64), F17::from(12u64), F17::from(3u64)];
    println!("3. Prover wysyła ewaluacje wielomianu sumcheck g(0), g(1), g(2): {:?}", g_evals);
    prover_transcript.append_field_elements(b"sumcheck_round_0", &g_evals);
    verifier_transcript.append_field_elements(b"sumcheck_round_0", &g_evals);

    // Symulacja etapu 4: Wyciśnięcie losowego punktu r dla kolejnej rundy
    let prover_r: F17 = prover_transcript.challenge_scalar(b"sumcheck_r_0");
    let verifier_r: F17 = verifier_transcript.challenge_scalar(b"sumcheck_r_0");
    println!("4. Wyzwanie kolejnej rundy r_0: {:?}", prover_r);
    assert_eq!(prover_r, verifier_r);

    // Symulacja etapu 5: Wybór kolumn weryfikatora dla Ligero
    let prover_cols = prover_transcript.challenge_indices(b"ligero_cols", 64, 5);
    let verifier_cols = verifier_transcript.challenge_indices(b"ligero_cols", 64, 5);
    println!("5. Wybrane kolumny Ligero do weryfikacji: {:?}", prover_cols);
    assert_eq!(prover_cols, verifier_cols);

    println!("\nSukces: Transkrypty Provera i Weryfikatora są w 100% zsynchronizowane!");
}
