use ark_ff::{Fp64, MontBackend, MontConfig};
use zkp_core::ligero::{LigeroProver, LigeroVerifier};

#[derive(MontConfig)]
#[modulus = "17"]
#[generator = "3"]
pub struct FqConfig;
pub type F17 = Fp64<MontBackend<FqConfig, 1>>;

fn main() {
    println!("============================================================");
    println!("       DEMO: System Dowodowy Ligero (IOP / Commitment)      ");
    println!("             Zgodny z Rozdziałem 2.2 z ZKP.pdf              ");
    println!("============================================================");

    // 1. Definiujemy tajnego świadka w: 6 liczb w ciele F_17
    let witness = vec![
        F17::from(1u64), F17::from(2u64), F17::from(3u64),
        F17::from(4u64), F17::from(5u64), F17::from(6u64),
    ];
    println!("\n[1] Tajny świadek Provera (w): {:?}", witness);

    // 2. Parametry macierzy Ligero:
    //    Świadek o rozmiarze 6 układamy w macierz m = 2 wiersze, k = 3 kolumny
    //    Kodami Reeda-Salomona rozszerzamy wiersze do n = 6 kolumn (stopa kodu rho = 1/2)
    let m = 2;
    let k = 3;
    let n = 6;
    println!("\n[2] Parametry układu Ligero:");
    println!("    • Wymiary macierzy świadka: {} wiersze x {} kolumny", m, k);
    println!("    • Długość rozszerzenia Reed-Solomon (n): {} kolumn", n);

    // 3. Krok Provera: Commit (Zaangażowanie)
    let prover = LigeroProver::<F17>::new(&witness, m, k, n);
    let commitment_root = prover.commitment();
    println!("\n[3] Krok Provera: LigeroCommit(w)");
    println!("    • Zakodowane wiersze macierzy (po rozszerzeniu RS):");
    for i in 0..m {
        println!("      wiersz {}: {:?}", i, prover.matrix.get_row(i));
    }
    println!("    • Korzeń Merkle'a nad kolumnami: 0x{}", hex::encode(commitment_root));

    // 4. Krok Verifiera: Wyzwanie losowej kombinacji liniowej wierszy
    let weights = vec![F17::from(3u64), F17::from(5u64)];
    println!("\n[4] Krok Verifiera: Losowe wyzwanie wag dla wierszy:");
    println!("    • Wagi r: {:?}", weights);

    // 5. Krok Provera: Odpowiedź kombinacją liniową
    let lin_comb = prover.answer_linear_combination(&weights);
    println!("\n[5] Krok Provera: Kombinacja liniowa wierszy v = sum r_i * wiersz_i:");
    println!("    • Wektor v: {:?}", lin_comb);

    // 6. Krok Verifiera: Losowe zapytanie o kolumny (np. kolumny 1 i 4)
    let queried_cols = vec![1, 4];
    println!("\n[6] Krok Verifiera: Losowe zapytanie o testowe kolumny:");
    println!("    • Wybrane kolumny: {:?}", queried_cols);

    // 7. Krok Provera: Ujawnienie kolumn ze ścieżkami Merkle'a
    let openings = prover.open_columns(&queried_cols);
    println!("\n[7] Krok Provera: Otwarcie zapytanych kolumn z dowodami Merkle'a:");
    for (col_idx, col_vals, proof) in &openings {
        println!("    • Kolumna {}: wartości = {:?}, długość ścieżki Merkle = {}", col_idx, col_vals, proof.path.len());
    }

    // 8. Weryfikacja końcowa Verifiera
    let verifier = LigeroVerifier::<F17>::new(m, k, n);
    println!("\n[8] Weryfikacja końcowa Verifiera:");

    let openings_ok = verifier.verify_openings(&commitment_root, &openings);
    println!("    • 1. Weryfikacja ścieżek Merkle'a: {}", if openings_ok { "POPRAWNA (OK)" } else { "BŁĄD!" });
    assert!(openings_ok);

    let lin_comb_ok = verifier.verify_linear_combination(&lin_comb, &weights, &openings);
    println!("    • 2. Weryfikacja słowa kodowego RS i spójności z kolumnami: {}", if lin_comb_ok { "POPRAWNA (OK)" } else { "BŁĄD!" });
    assert!(lin_comb_ok);

    println!("\n>>> SUKCES: Protokół Ligero pomyślnie zaangażował i zweryfikował świadka w wiedzy zerowej! <<<\n");
}

mod hex {
    pub fn encode(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
