"""Algebraic Poseidon Hash Function & Fiat-Shamir Sponge Transcript over F_p.

Parameters (128-bit security over BN254 scalar field per Grassi et al., USENIX 2021):
- Prime field F_p: p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
  Note: gcd(5, p - 1) = 1, so x -> x^5 mod p is a bijection (permutation) over F_p.
- Sponge width t = 3 (capacity c = 1, rate r = 2)
- Full rounds R_F = 8 (4 initial full rounds + 4 terminal full rounds)
- Partial rounds R_P = 56 (S-box applied only to state[0])
- SAFE-style domain & length separation in initial capacity lane: state[0] = (domain_tag << 64) + len(inputs)
- Deterministic nothing-up-my-sleeve round constants (ARK) via rejection-sampled SHAKE-256
- Super-regular 3x3 Cauchy MDS matrix M[i][j] = (x_i + y_j)^(-1) mod p
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Sequence

# BN254 scalar field prime (254-bit prime, 2-adicity = 28, gcd(5, p - 1) = 1)
FIELD_PRIME: int = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

POSEIDON_WIDTH: int = 3
POSEIDON_CAPACITY: int = 1
POSEIDON_RATE: int = 2
HALF_FULL_ROUNDS: int = 4
FULL_ROUNDS: int = 2 * HALF_FULL_ROUNDS  # 8
PARTIAL_ROUNDS: int = 56
TOTAL_ROUNDS: int = FULL_ROUNDS + PARTIAL_ROUNDS  # 64
SBOX_ALPHA: int = 5

# Domain separation tags for SAFE Poseidon sponge
DOMAIN_GENERIC: int = 0x00
DOMAIN_PK_TAG: int = 0x01
DOMAIN_CREDENTIAL: int = 0x02
DOMAIN_SCHNORR_SIG: int = 0x03
DOMAIN_CHALLENGE: int = 0x04
DOMAIN_SESSION_BIND: int = 0x05
DOMAIN_TRANSCRIPT: int = 0x06


def _generate_round_constants(num_constants: int, p: int) -> tuple[int, ...]:
    """Generate uniform nothing-up-my-sleeve field constants via SHAKE-256 rejection sampling."""
    constants: list[int] = []
    counter = 0
    seed_prefix = b"ZeroAge-Poseidon-BN254-t3-RF8-RP56-ARK-"
    while len(constants) < num_constants:
        digest = hashlib.shake_256(seed_prefix + counter.to_bytes(4, "big")).digest(32)
        candidate = int.from_bytes(digest, "big")
        if candidate < p:
            constants.append(candidate)
        counter += 1
    return tuple(constants)


def _generate_cauchy_mds_matrix(width: int, p: int) -> tuple[tuple[int, ...], ...]:
    """Construct a Cauchy MDS matrix M[i][j] = (x_i + y_j)^(-1) mod p and verify super-regularity."""
    xs = [i for i in range(width)]
    ys = [width + j for j in range(width)]
    matrix = tuple(
        tuple(pow((xs[i] + ys[j]) % p, -1, p) for j in range(width))
        for i in range(width)
    )

    # Verify MDS property: every 1x1, 2x2, and 3x3 minor is non-zero mod p
    for i in range(3):
        for j in range(3):
            if matrix[i][j] % p == 0:
                raise RuntimeError("Invalid MDS matrix: zero entry")
    for r1 in range(3):
        for r2 in range(r1 + 1, 3):
            for c1 in range(3):
                for c2 in range(c1 + 1, 3):
                    det2 = (
                        matrix[r1][c1] * matrix[r2][c2]
                        - matrix[r1][c2] * matrix[r2][c1]
                    ) % p
                    if det2 == 0:
                        raise RuntimeError("Invalid MDS matrix: singular 2x2 minor")
    det3 = (
        matrix[0][0] * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1])
        - matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0])
        + matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0])
    ) % p
    if det3 == 0:
        raise RuntimeError("Invalid MDS matrix: singular 3x3 determinant")

    return matrix


ROUND_CONSTANTS: tuple[int, ...] = _generate_round_constants(
    TOTAL_ROUNDS * POSEIDON_WIDTH, FIELD_PRIME
)
MDS_MATRIX: tuple[tuple[int, ...], ...] = _generate_cauchy_mds_matrix(
    POSEIDON_WIDTH, FIELD_PRIME
)

# Pre-unpack MDS entries into module-level constants for fast pure-Python permutation
_M00, _M01, _M02 = MDS_MATRIX[0]
_M10, _M11, _M12 = MDS_MATRIX[1]
_M20, _M21, _M22 = MDS_MATRIX[2]


def poseidon_permute(s0: int, s1: int, s2: int) -> tuple[int, int, int]:
    """Execute the 64-round Poseidon permutation over F_p^3 (R_F=8, R_P=56, alpha=5)."""
    p = FIELD_PRIME
    rc = ROUND_CONSTANTS
    m00, m01, m02 = _M00, _M01, _M02
    m10, m11, m12 = _M10, _M11, _M12
    m20, m21, m22 = _M20, _M21, _M22

    s0 %= p
    s1 %= p
    s2 %= p
    idx = 0

    # Initial 4 full rounds: ARK -> S-Box on all 3 lanes -> MDS
    for _ in range(HALF_FULL_ROUNDS):
        s0 = (s0 + rc[idx]) % p
        s1 = (s1 + rc[idx + 1]) % p
        s2 = (s2 + rc[idx + 2]) % p
        idx += 3

        x2 = (s0 * s0) % p
        s0 = (x2 * x2 % p) * s0 % p
        x2 = (s1 * s1) % p
        s1 = (x2 * x2 % p) * s1 % p
        x2 = (s2 * s2) % p
        s2 = (x2 * x2 % p) * s2 % p

        s0, s1, s2 = (
            (m00 * s0 + m01 * s1 + m02 * s2) % p,
            (m10 * s0 + m11 * s1 + m12 * s2) % p,
            (m20 * s0 + m21 * s1 + m22 * s2) % p,
        )

    # Middle 56 partial rounds: ARK -> S-Box ONLY on lane 0 -> MDS
    for _ in range(PARTIAL_ROUNDS):
        s0 = (s0 + rc[idx]) % p
        s1 = (s1 + rc[idx + 1]) % p
        s2 = (s2 + rc[idx + 2]) % p
        idx += 3

        x2 = (s0 * s0) % p
        s0 = (x2 * x2 % p) * s0 % p

        s0, s1, s2 = (
            (m00 * s0 + m01 * s1 + m02 * s2) % p,
            (m10 * s0 + m11 * s1 + m12 * s2) % p,
            (m20 * s0 + m21 * s1 + m22 * s2) % p,
        )

    # Terminal 4 full rounds: ARK -> S-Box on all 3 lanes -> MDS
    for _ in range(HALF_FULL_ROUNDS):
        s0 = (s0 + rc[idx]) % p
        s1 = (s1 + rc[idx + 1]) % p
        s2 = (s2 + rc[idx + 2]) % p
        idx += 3

        x2 = (s0 * s0) % p
        s0 = (x2 * x2 % p) * s0 % p
        x2 = (s1 * s1) % p
        s1 = (x2 * x2 % p) * s1 % p
        x2 = (s2 * s2) % p
        s2 = (x2 * x2 % p) * s2 % p

        s0, s1, s2 = (
            (m00 * s0 + m01 * s1 + m02 * s2) % p,
            (m10 * s0 + m11 * s1 + m12 * s2) % p,
            (m20 * s0 + m21 * s1 + m22 * s2) % p,
        )

    return s0, s1, s2


def poseidon_hash(inputs: Sequence[int], domain_tag: int = DOMAIN_GENERIC) -> int:
    """Hash an arbitrary sequence of F_p elements using SAFE Poseidon sponge (t=3, r=2, c=1).

    The capacity lane state[0] is initialized to `(domain_tag << 64) + len(inputs)` mod p,
    preventing cross-domain or variable-length extension collisions without extra padding blocks.
    """
    p = FIELD_PRIME
    n = len(inputs)
    s0 = ((domain_tag << 64) + n) % p
    s1 = 0
    s2 = 0

    if n == 0:
        s0, s1, s2 = poseidon_permute(s0, s1, s2)
        return s1

    for offset in range(0, n, POSEIDON_RATE):
        s1 = (s1 + (inputs[offset] % p)) % p
        if offset + 1 < n:
            s2 = (s2 + (inputs[offset + 1] % p)) % p
        s0, s1, s2 = poseidon_permute(s0, s1, s2)

    return s1


def bytes_to_field(data: bytes) -> int:
    """Map arbitrary byte strings deterministically into F_p via SHA-256 + modular reduction."""
    digest = hashlib.sha256(b"ZeroAge-FieldEncode:" + data).digest()
    return int.from_bytes(digest, "big") % FIELD_PRIME


def str_to_field(text: str) -> int:
    """Map an arbitrary UTF-8 string (e.g., verifier domain or nonce) into F_p."""
    return bytes_to_field(text.encode("utf-8"))


class PoseidonTranscript:
    """Fiat-Shamir non-interactive sponge transcript backed by algebraic Poseidon over F_p.

    Maintains a persistent (s0, s1, s2) sponge state over F_p^3 so that every public input,
    Merkle commitment root, Sumcheck polynomial, and Ligero opening polynomial is cryptographically
    bound into subsequent verifier challenges.
    """

    def __init__(self, protocol_label: str = "ZeroAge-Poseidon-Sumcheck-Ligero-v1") -> None:
        label_fe = str_to_field(protocol_label)
        self._s0, self._s1, self._s2 = poseidon_permute(
            (DOMAIN_TRANSCRIPT << 64) + 1, label_fe, 0
        )

    def absorb_field(self, value: int) -> None:
        """Absorb a single F_p element into the Fiat-Shamir sponge."""
        self._s1 = (self._s1 + (value % FIELD_PRIME)) % FIELD_PRIME
        self._s0, self._s1, self._s2 = poseidon_permute(self._s0, self._s1, self._s2)

    def absorb_fields(self, values: Iterable[int]) -> None:
        """Absorb an ordered sequence of F_p elements in rate-2 chunks."""
        vals = list(values)
        # First bind sequence length to prevent boundary ambiguity
        self._s1 = (self._s1 + len(vals)) % FIELD_PRIME
        self._s0, self._s1, self._s2 = poseidon_permute(self._s0, self._s1, self._s2)
        p = FIELD_PRIME
        for i in range(0, len(vals), POSEIDON_RATE):
            self._s1 = (self._s1 + (vals[i] % p)) % p
            if i + 1 < len(vals):
                self._s2 = (self._s2 + (vals[i + 1] % p)) % p
            self._s0, self._s1, self._s2 = poseidon_permute(
                self._s0, self._s1, self._s2
            )

    def absorb_bytes(self, label: str, raw: bytes) -> None:
        """Absorb labeled raw bytes (such as a 32-byte Merkle root) into the sponge."""
        self.absorb_fields([str_to_field(label), bytes_to_field(raw)])

    def squeeze_challenge(self, non_zero: bool = True) -> int:
        """Squeeze a pseudorandom field challenge in F_p (or F_p^* when non_zero=True)."""
        while True:
            self._s0, self._s1, self._s2 = poseidon_permute(
                self._s0, self._s1, self._s2
            )
            chal = self._s1
            if not non_zero or chal != 0:
                return chal

    def squeeze_challenges(self, count: int, non_zero: bool = True) -> list[int]:
        """Squeeze `count` independent field challenges."""
        return [self.squeeze_challenge(non_zero=non_zero) for _ in range(count)]

    def squeeze_distinct_indices(self, count: int, upper_bound: int) -> list[int]:
        """Squeeze `count` distinct indices in [0, upper_bound - 1] for Ligero column openings."""
        if count > upper_bound:
            raise ValueError("Cannot sample more distinct indices than upper_bound")
        chosen: list[int] = []
        seen: set[int] = set()
        # Use rejection sampling against largest multiple of upper_bound < FIELD_PRIME
        limit = (FIELD_PRIME // upper_bound) * upper_bound
        while len(chosen) < count:
            raw = self.squeeze_challenge(non_zero=False)
            if raw < limit:
                idx = raw % upper_bound
                if idx not in seen:
                    seen.add(idx)
                    chosen.append(idx)
        return chosen
