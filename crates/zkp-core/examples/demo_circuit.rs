use ark_ff::{Fp64, MontBackend, MontConfig, One};
use zkp_core::circuit::{CircuitLayer, LayeredCircuit, QuadGate, QuadTerm};

#[derive(MontConfig)]
#[modulus = "17"]
#[generator = "3"]
pub struct FqConfig;
pub type F17 = Fp64<MontBackend<FqConfig, 1>>;

fn main() {

    // Budujemy obwód sprawdzający twierdzenie:
    // "Znam takie tajne liczby x i y, że (x + y) * 3 == 7 (mod 17)"
    //
    // Obwód ma 2 warstwy (głębokość d = 2):
    // Warstwa d=2 (wejścia): [V[0]=1, V[1]=x, V[2]=y, V[3]=3]
    // Warstwa j=1: V_1[1] = V_2[1] + V_2[2] (x + y), V_1[2] = V_2[3] (3)
    // Warstwa j=0 (wyjście): V_0[1] = V_1[1] * V_1[2] - 7 == 0

    let layer1 = CircuitLayer::<F17>::new(
        1,
        4,
        3,
        vec![
            QuadGate::add(1, 1, 2),             // V_1[1] = x + y
            QuadGate::scale(2, 3, F17::one()), // V_1[2] = 3
        ],
    );

    let layer0 = CircuitLayer::<F17>::new(
        0,
        3,
        2,
        vec![
            // V_0[1] = V_1[1] * V_1[2] - 7
            QuadGate::new(
                1,
                vec![
                    QuadTerm::mul(1, 2),
                    QuadTerm::constant(-F17::from(7u64)),
                ],
            ),
        ],
    );

    let circuit = LayeredCircuit::<F17>::new(vec![layer0, layer1], 4);
    println!("\n[1] Zbudowano obwód o głębokości d = {} warstwy", circuit.depth());

    // Scenariusz 1: Prawidłowy świadek x=3, y=5
    // (3 + 5) * 3 = 24 = 7 mod 17  =>  7 - 7 = 0 (SUKCES)
    let valid_witness = vec![F17::one(), F17::from(3u64), F17::from(5u64), F17::from(3u64)];
    println!("\n[2] Test poprawnego świadka: x=3, y=5");
    let wires = circuit.evaluate_all(&valid_witness);
    println!("    • Warstwa wejściowa V_2: {:?}", wires[2]);
    println!("    • Warstwa ukryta     V_1: {:?}", wires[1]);
    println!("    • Warstwa wyjściowa  V_0: {:?}", wires[0]);
    let satisfied = circuit.is_satisfied(&valid_witness);
    println!("    • Czy obwód jest spełniony (V_0[1] == 0)? {}", satisfied);
    assert!(satisfied);

    // Scenariusz 2: Fałszywy świadek x=3, y=4
    // (3 + 4) * 3 = 21 = 4 mod 17  =>  4 - 7 = -3 = 14 != 0 (ODRZUCENIE)
    let invalid_witness = vec![F17::one(), F17::from(3u64), F17::from(4u64), F17::from(3u64)];
    println!("\n[3] Test fałszywego świadka: x=3, y=4");
    let bad_wires = circuit.evaluate_all(&invalid_witness);
    println!("    • Warstwa wyjściowa  V_0: {:?}", bad_wires[0]);
    let bad_satisfied = circuit.is_satisfied(&invalid_witness);
    println!("    • Czy obwód jest spełniony? {}", bad_satisfied);
    assert!(!bad_satisfied);

    println!("\n>>> SUKCES: Obwód bezbłędnie weryfikuje poprawne i odrzuca fałszywe wejścia! <<<\n");
}
