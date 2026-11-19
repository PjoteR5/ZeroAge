# ZeroAge (MVP) - System Poświadczeń Wieku ZKP w Rust

Gałąź **`mvp`** prezentuje minimalny działający prototyp (MVP) systemu anonimowej weryfikacji pełnoletności ($\text{wiek} \ge 18$) w języku **Rust**, wyznaczający kierunek architektury opartej na pracy *Anonymous Credentials from ECDSA* (Frigo & shelat) ze zgodnością z **SHA-256** oraz **NIST P-256 (ECDSA)**.

---

## Zakres Wersji MVP

```text
ZeroAge/
└── crates/
    ├── zkp-core/                  # 1. Fundamenty dowodowe (Ciało F_p256, Obwody QuadGate, Sumcheck, Ligero, Merkle SHA-256)
    ├── zkp-circuits/              # 2. Prymitywy i obwody bazowe (SHA-256 od podstaw, ECDSA P-256, 64-bitowy obwód wieku)
    └── mdoc-app/                  # 3. Moduł Wystawcy, Zobowiązań i Reprezentacji Danych (MVP)
        ├── src/commitment.rs      #    - Schemat zobowiązań SHA-256 z solą (AttributeCommitment) + integracja z Ligero
        ├── src/date_witness.rs    #    - Reprezentacja daty (CredentialDate) oraz podział PublicAgeInputs / PrivateAgeWitness
        ├── src/issuer.rs          #    - Wystawianie i podpisywanie poświadczeń (CredentialIssuer, SignedAgeCredential)
        ├── src/mvp_flow.rs        #    - Spięcie emisji poświadczenia z generowaniem i weryfikacją dowodu ZKP
        └── examples/demo_mvp.rs   #    - Skrypt demonstracyjny MVP
```

---

## Uruchomienie Testów i Demonstracji MVP

```bash
# Uruchomienie testów jednostkowych wszystkich modułów MVP
cargo test --workspace

# Uruchomienie demonstracji emisji poświadczenia, zobowiązania i dowodu ZKP
cargo run -p mdoc-app --example demo_mvp
```
