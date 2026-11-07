"""ZeroAge Pure-Python Zero-Knowledge Proof Engine.

Implements:
- Algebraic Poseidon sponge hash and Fiat-Shamir transcript over BN254 scalar field F_p
- BabyJubjub complete Twisted Edwards curve primitives, Poseidon/Pedersen commitments,
  Schnorr credential signatures, and ES256 JWT tokens
- Sparse rank-1 Quadratic Arithmetic Circuit (Q[i, l, r]) with Poseidon, 64-bit range
  checks, and fixed-base Twisted Edwards scalar multiplication gadgets
- Zero-Knowledge Sumcheck + One-Time Pad (OTP) Ligero proof generator and verifier
"""

from zkp_engine.poseidon import (
    FIELD_PRIME,
    POSEIDON_WIDTH,
    POSEIDON_RATE,
    POSEIDON_CAPACITY,
    FULL_ROUNDS,
    PARTIAL_ROUNDS,
    PoseidonTranscript,
    poseidon_hash,
    poseidon_permute,
)

__all__ = [
    "FIELD_PRIME",
    "POSEIDON_WIDTH",
    "POSEIDON_RATE",
    "POSEIDON_CAPACITY",
    "FULL_ROUNDS",
    "PARTIAL_ROUNDS",
    "PoseidonTranscript",
    "poseidon_hash",
    "poseidon_permute",
]
