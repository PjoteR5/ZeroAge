use ark_ff::{Fp64, MontBackend, MontConfig, One, Zero};
use zkp_core::circuit::{CircuitLayer, QuadGate};
use zkp_core::sumcheck::{SumcheckProver, SumcheckVerifier};

#[derive(MontConfig)]
#[modulus = "17"]
#[generator = "3"]
pub struct FqConfig;
pub type F17 = Fp64<MontBackend<FqConfig, 1>>;

fn main() {
   
    // 1. Definiujemy warstwę obwodu:
    //    Wejście V_1 o szerokości 4: [V[0]=1, V[1]=3, V[2]=5, V[3]=0]
    //    Bramka: V_0[1] = V_1[1] * V_1[2] (mnożenie 3 * 5 = 15 mod 17)
    let gate = QuadGate::mul(1, 1, 2);
    let layer = CircuitLayer::<F17>::new(0, 4, 2, vec![gate]);
    let v_in = vec![F17::one(), F17::from(3u64), F17::from(5u64), F17::zero()];

    // 2. Roszczenia z wyjścia:
    //    V_0[0] = 1, V_0[1] = 15
    let r_out_0 = vec![F17::zero()];
    let r_out_1 = vec![F17::one()];
    let claim_0 = F17::one();
    let claim_1 = F17::from(15u64);

    // Weryfikator losuje wagę kombinacji liniowej: alpha
    let alpha = F17::from(7u64);
    println!("\n[1] Parametry początkowe warstwy:");
    println!("    • Wyjściowe roszczenia: c_0 = {}, c_1 = {}", claim_0, claim_1);
    println!("    • Losowa waga Verifiera alpha: {}", alpha);

    let mut prover = SumcheckProver::<F17>::new(
        layer.clone(),
        alpha,
        r_out_0.clone(),
        r_out_1.clone(),
        &v_in,
    );

    let mut verifier = SumcheckVerifier::<F17>::new(
        layer,
        alpha,
        r_out_0,
        r_out_1,
        claim_0,
        claim_1,
    );

    let total_rounds = prover.total_rounds();
    println!("    • Deklarowana suma początkowa Y = {}", verifier.current_claim);
    println!("    • Całkowita liczba rund do redukcji (2 * omega_in): {}", total_rounds);

    // 3. Przebieg rund interaktywnych
    println!("\n[2] Przebieg rund protokołu Sumcheck:");
    let simulated_challenges = [
        F17::from(2u64),
        F17::from(4u64),
        F17::from(6u64),
        F17::from(8u64),
    ];

    for r in 0..total_rounds {
        println!("\n--- Runda {}/{} ---", r + 1, total_rounds);
        println!("  1. Oczekiwana suma: claim = {}", verifier.current_claim);

        // Krok Provera: wyliczenie wielomianu stopnia 2: g(X)
        let poly = prover.compute_round_poly();
        println!("  2. Prover wysyła wielomian g_{}(X): g(0)={}, g(1)={}, g(2)={}", r, poly.eval_0, poly.eval_1, poly.eval_2);

        // Krok Verifiera: sprawdzenie g(0) + g(1) == claim
        let sum_check = poly.check_sum(&verifier.current_claim);
        println!("  3. Verifier sprawdza g(0) + g(1) = {} ? {}", poly.eval_0 + poly.eval_1, if sum_check { "TAK (OK)" } else { "BŁĄD!" });
        assert!(sum_check);

        // Verifier losuje wyzwanie r_k i oblicza nowe roszczenie g(r_k)
        let challenge = simulated_challenges[r];
        println!("  4. Verifier wysyła wyzwanie losowe r_{} = {}", r, challenge);
        let ok = verifier.verify_round(&poly, challenge);
        assert!(ok);
        println!("  5. Nowe zredukowane roszczenie: new_claim = {}", verifier.current_claim);

        // Prover zamraża zmienną
        prover.receive_challenge(challenge);
    }

    // 4. Końcowe sprawdzenie
    println!("\n[3] Końcowe sprawdzenie Verifiera (Krok 2e z Protokołu 2.2):");
    let (l_point, r_point) = prover.get_final_points();
    println!("    • Ustalony losowy punkt lewy  L = {:?}", l_point);
    println!("    • Ustalony losowy punkt prawy R = {:?}", r_point);

    let (c_next_0, c_next_1) = prover.compute_next_claims();
    println!("    • Prover deklaruje roszczenia wejściowe: V(L)={}, V(R)={}", c_next_0, c_next_1);

    let final_check = verifier.verify_final_check(c_next_0, c_next_1);
    println!("    • Verifier sprawdza równość z wielomianem okablowania Q(r_out, L, R): {}", if final_check { "SUKCES (ZGODNOŚĆ)" } else { "BŁĄD!" });
    assert!(final_check);

    println!("\n>>> SUKCES: Protokół Sumcheck zredukował całe sprawdzenie warstwy do pojedynczej równości! <<<\n");
}
