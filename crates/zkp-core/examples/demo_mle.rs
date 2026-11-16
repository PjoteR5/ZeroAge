use ark_ff::{Fp64, MontBackend, MontConfig};
use zkp_core::field::mle::DenseMultilinearExtension;

#[derive(MontConfig)]
#[modulus = "17"]
#[generator = "3"]
pub struct FqConfig;
pub type F17 = Fp64<MontBackend<FqConfig, 1>>;

fn main() {
   
    // 1. Definiujemy wielomian 2 zmiennych: P(X0, X1)
    //    Wartości na wierzchołkach hipersześcianu boolowskiego {0, 1}^2:
    //    P(0, 0) = 1
    //    P(0, 1) = 2
    //    P(1, 0) = 3
    //    P(1, 1) = 8
    let evals = vec![
        F17::from(1u64), // 00
        F17::from(2u64), // 01
        F17::from(3u64), // 10
        F17::from(8u64), // 11
    ];

    let mle = DenseMultilinearExtension::new(2, evals);
    println!("\n[1] Zainicjalizowano wielomian MLE:");
    println!("    • Liczba zmiennych v: {}", mle.num_vars());
    println!("    • Liczba wierzchołków hipersześcianu 2^v: {}", mle.evaluations.len());

    println!("\n[2] Weryfikacja wierzchołków hipersześcianu:");
    println!("    • P(0, 0) = {} (oczekiwano 1)", mle.evaluate(&[F17::from(0u64), F17::from(0u64)]));
    println!("    • P(1, 0) = {} (oczekiwano 2)", mle.evaluate(&[F17::from(1u64), F17::from(0u64)]));
    println!("    • P(0, 1) = {} (oczekiwano 3)", mle.evaluate(&[F17::from(0u64), F17::from(1u64)]));
    println!("    • P(1, 1) = {} (oczekiwano 8)", mle.evaluate(&[F17::from(1u64), F17::from(1u64)]));

    println!("\n[3] Ewaluacja w losowym punkcie poza kostką boolowską, np. (r0=2, r1=3) mod 17:");
    let point = [F17::from(2u64), F17::from(3u64)];
    let full_eval = mle.evaluate(&point);
    println!("    • P(2, 3) = {}", full_eval);

    println!("\n[4] Krok Sumchecka: Zamrożenie zmiennej (operacja BIND dla X0 = 2):");
    let bound_mle = mle.bind(&F17::from(2u64));
    println!("    • Nowy wielomian ma liczbę zmiennych: {}", bound_mle.num_vars());
    println!("    • Ewaluacja P(2, X1) dla X1 = 3: {}", bound_mle.evaluate(&[F17::from(3u64)]));

    assert_eq!(full_eval, bound_mle.evaluate(&[F17::from(3u64)]));
    println!("\n>>> SUKCES: Ewaluacja bezpośrednia i ewaluacja po BIND są w 100% zgodne! <<<\n");
}
