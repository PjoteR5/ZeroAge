"""Quadratic Arithmetic Circuit (Q[i, l, r]) + ZK-Sumcheck + One-Time Pad Ligero Engine.

Architecture (inspired by Frigo & shelat, "Anonymous Credentials from ECDSA",
DOI: 10.62056/a3qjmpgxq, adapted with algebraic Poseidon over BN254 F_p):

1. Sparse Rank-1 Quadratic Circuit `Q[g, l, r] = L[g, l] * R[g, r]`:
   Every gate `g` enforces:
       (sum_l L[g, l] * w[l]) * (sum_r R[g, r] * w[r]) - (sum_o O[g, o] * w[o]) == 0 (mod p)
   where w[0] = 1 is the constant wire, w[1..n_pub] are public inputs, and the remaining
   wires are private witness values.

2. Circuit Gadgets:
   - Algebraic Poseidon permutation & SAFE sponge (240 quadratic gates per permutation)
   - 64-bit binary decomposition range check (prevents modular wrap-around underflow mod p)
   - Complete BabyJubjub Twisted Edwards curve check, point addition, and 2-bit windowed
     fixed-base scalar multiplication (~5 quadratic gates per scalar bit)

3. Zero-Knowledge Sumcheck + One-Time Pad (OTP) Ligero IOP (Fiat-Shamir via Poseidon):
   - Witness `w` (augmented with evaluation-blinding wires and ZK-Sumcheck mask wires) is
     reshaped into an `m x b` matrix, blinded per-row by `(X^b - 1) * r_i(X)` (degree < 24),
     augmented with two full One-Time Pad polynomial rows (`f_code`, `f_dot`), evaluated
     via Radix-2 Cooley-Tukey coset NTT of size N_RS = 512, and committed via column
     Merkle tree.
   - 13-round Zero-Knowledge Sumcheck reduces all 8,192 quadratic gates to multilinear
     evaluations `(v_L, v_R, v_O, v_G)` at random point `r*`, which batch together with
     public-input wire constraints into a SINGLE linear evaluation `<q_total, w> = v_total`.
   - OTP Ligero proves codeword proximity (`P_code`) and univariate sumcheck `<q_total, w>`
     (`P_dot`) simultaneously by opening `t_open = 20` random columns against the Merkle root.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import secrets
from typing import Any, Callable, Sequence

from zkp_engine.crypto_primitives import (
    BABYJUBJUB_A,
    BABYJUBJUB_D,
    BASE_POINT,
    FIELD_BITS,
    Point,
    SCALAR_BITS,
    precompute_2bit_windows,
)
from zkp_engine.poseidon import (
    DOMAIN_CREDENTIAL,
    DOMAIN_PK_TAG,
    DOMAIN_SCHNORR_SIG,
    DOMAIN_SESSION_BIND,
    FIELD_PRIME,
    HALF_FULL_ROUNDS,
    MDS_MATRIX,
    PARTIAL_ROUNDS,
    POSEIDON_RATE,
    ROUND_CONSTANTS,
    PoseidonTranscript,
)

# 18 years in seconds including the guaranteed >=4 leap days in any 18-year modern span
AGE_18_SECONDS: int = (18 * 365 + 4) * 86400  # 567,993,600 seconds

# Ligero & Reed-Solomon parameters over BN254 F_p (2-adicity of p - 1 is 28)
LIGERO_BLOCK_SIZE: int = 128        # Witness elements per row (power of 2)
LIGERO_BLIND_DEG: int = 24          # Per-row random blinding polynomial degree (> t_open)
LIGERO_OPEN_COLS: int = 20          # Number of randomly queried columns (< LIGERO_BLIND_DEG)
LIGERO_COL_COUNT: int = 512         # Reed-Solomon codeword length (rate ~ 0.30..0.54)
CODE_POLY_LEN: int = LIGERO_BLOCK_SIZE + LIGERO_BLIND_DEG               # 152
DOT_POLY_LEN: int = 2 * LIGERO_BLOCK_SIZE + LIGERO_BLIND_DEG - 1        # 279 < 512
COSET_SHIFT: int = 5                # Disjoint coset generator eta * <zeta>


# ---------------------------------------------------------------------------
# Fast Radix-2 Number Theoretic Transform (NTT) over BN254 F_p
# ---------------------------------------------------------------------------


def _find_2adic_root_of_unity(order: int) -> int:
    """Compute a primitive `order`-th root of unity in F_p (order must be a power of 2 <= 2^28)."""
    if order <= 0 or (order & (order - 1)) != 0:
        raise ValueError("NTT order must be a power of two")
    p = FIELD_PRIME
    # Find quadratic non-residue z (Legendre(z, p) = -1); z = 5 works for BN254
    z = 5
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    # omega_{2^28} = z^((p - 1) / 2^28) has exact order 2^28
    two_adicity = 28
    max_order = 1 << two_adicity
    if order > max_order:
        raise ValueError("Order exceeds 2-adicity of BN254 scalar field")
    root_max = pow(z, (p - 1) // max_order, p)
    omega = pow(root_max, max_order // order, p)
    return omega


@dataclass(frozen=True)
class _NTTPlan:
    n: int
    log_n: int
    omega: int
    omega_inv: int
    n_inv: int
    bit_rev: tuple[int, ...]
    stage_twiddles: tuple[tuple[int, ...], ...]
    stage_inv_twiddles: tuple[tuple[int, ...], ...]
    coset_powers: tuple[int, ...]
    coset_inv_powers: tuple[int, ...]


@lru_cache(maxsize=8)
def _get_ntt_plan(n: int) -> _NTTPlan:
    p = FIELD_PRIME
    log_n = n.bit_length() - 1
    omega = _find_2adic_root_of_unity(n)
    omega_inv = pow(omega, -1, p)
    n_inv = pow(n, -1, p)

    bit_rev = tuple(
        int(f"{i:0{log_n}b}"[::-1], 2) if log_n > 0 else 0 for i in range(n)
    )

    stage_twiddles: list[tuple[int, ...]] = []
    stage_inv_twiddles: list[tuple[int, ...]] = []
    length = 2
    while length <= n:
        half = length // 2
        w_len = pow(omega, n // length, p)
        w_inv_len = pow(omega_inv, n // length, p)
        tw = [1] * half
        tw_inv = [1] * half
        cur = 1
        cur_inv = 1
        for k in range(half):
            tw[k] = cur
            tw_inv[k] = cur_inv
            cur = (cur * w_len) % p
            cur_inv = (cur_inv * w_inv_len) % p
        stage_twiddles.append(tuple(tw))
        stage_inv_twiddles.append(tuple(tw_inv))
        length <<= 1

    eta_inv = pow(COSET_SHIFT, -1, p)
    coset_pows = [1] * n
    coset_inv_pows = [1] * n
    c = 1
    c_inv = 1
    for i in range(n):
        coset_pows[i] = c
        coset_inv_pows[i] = c_inv
        c = (c * COSET_SHIFT) % p
        c_inv = (c_inv * eta_inv) % p

    return _NTTPlan(
        n=n,
        log_n=log_n,
        omega=omega,
        omega_inv=omega_inv,
        n_inv=n_inv,
        bit_rev=bit_rev,
        stage_twiddles=tuple(stage_twiddles),
        stage_inv_twiddles=tuple(stage_inv_twiddles),
        coset_powers=tuple(coset_pows),
        coset_inv_powers=tuple(coset_inv_pows),
    )


# Verify disjointness of evaluation coset eta * <zeta_512> and subgroup H_sub = <omega_128>
if pow(COSET_SHIFT, LIGERO_COL_COUNT, FIELD_PRIME) == 1:
    raise RuntimeError("Coset shift is not disjoint from multiplicative subgroup")


def ntt(coeffs: Sequence[int], n: int) -> list[int]:
    """Evaluate polynomial `coeffs` (padded to `n`) at {1, omega, ..., omega^(n-1)}."""
    p = FIELD_PRIME
    plan = _get_ntt_plan(n)
    buf = [0] * n
    m = len(coeffs)
    br = plan.bit_rev
    for i in range(m):
        buf[br[i]] = coeffs[i] % p

    length = 2
    for stage_idx, tw in enumerate(plan.stage_twiddles):
        half = 1 << stage_idx
        for start in range(0, n, length):
            for k in range(half):
                u = buf[start + k]
                v = (buf[start + k + half] * tw[k]) % p
                x = u + v
                buf[start + k] = x - p if x >= p else x
                y = u - v
                buf[start + k + half] = y + p if y < 0 else y
        length <<= 1
    return buf


def intt(evals: Sequence[int], n: int) -> list[int]:
    """Interpolate polynomial coefficients of degree < `n` from evaluations on <omega>."""
    p = FIELD_PRIME
    plan = _get_ntt_plan(n)
    br = plan.bit_rev
    buf = [evals[br[i]] % p for i in range(n)]

    length = 2
    for stage_idx, tw_inv in enumerate(plan.stage_inv_twiddles):
        half = 1 << stage_idx
        for start in range(0, n, length):
            for k in range(half):
                u = buf[start + k]
                v = (buf[start + k + half] * tw_inv[k]) % p
                x = u + v
                buf[start + k] = x - p if x >= p else x
                y = u - v
                buf[start + k + half] = y + p if y < 0 else y
        length <<= 1

    n_inv = plan.n_inv
    return [(val * n_inv) % p for val in buf]


def coset_ntt(coeffs: Sequence[int], n: int) -> list[int]:
    """Evaluate polynomial `coeffs` on disjoint coset {eta * zeta^j : j = 0..n-1}."""
    p = FIELD_PRIME
    cp = _get_ntt_plan(n).coset_powers
    shifted = [(coeffs[i] * cp[i]) % p for i in range(len(coeffs))]
    return ntt(shifted, n)


def coset_intt(evals: Sequence[int], n: int) -> list[int]:
    """Invert `coset_ntt` back to canonical monomial coefficients."""
    p = FIELD_PRIME
    raw = intt(evals, n)
    cip = _get_ntt_plan(n).coset_inv_powers
    return [(raw[i] * cip[i]) % p for i in range(n)]


def poly_eval_horner(coeffs: Sequence[int], x: int) -> int:
    """Evaluate polynomial sum_d coeffs[d] * x^d mod p via Horner's method."""
    p = FIELD_PRIME
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % p
    return acc


# ---------------------------------------------------------------------------
# Sparse Rank-1 Quadratic Circuit Q[i, l, r] Builder
# ---------------------------------------------------------------------------

LinearTerms = dict[int, int]


class LinearComb:
    """Affine/linear combination of circuit wires: sum_j terms[j] * w[j] (mod p), w[0] == 1."""

    __slots__ = ("terms",)

    def __init__(self, terms: dict[int, int] | None = None) -> None:
        p = FIELD_PRIME
        cleaned: dict[int, int] = {}
        if terms:
            for idx, coeff in terms.items():
                c = coeff % p
                if c:
                    cleaned[idx] = c
        self.terms = cleaned

    @classmethod
    def from_wire(cls, wire_idx: int, coeff: int = 1) -> LinearComb:
        return cls({wire_idx: coeff})

    @classmethod
    def from_const(cls, value: int) -> LinearComb:
        return cls({0: value})

    def add(self, other: LinearComb, scale: int = 1) -> LinearComb:
        p = FIELD_PRIME
        s = scale % p
        if s == 0:
            return LinearComb(dict(self.terms))
        merged = dict(self.terms)
        for idx, coeff in other.terms.items():
            nv = (merged.get(idx, 0) + coeff * s) % p
            if nv:
                merged[idx] = nv
            else:
                merged.pop(idx, None)
        return LinearComb(merged)

    def scale(self, factor: int) -> LinearComb:
        p = FIELD_PRIME
        f = factor % p
        if f == 0:
            return LinearComb()
        return LinearComb({idx: (coeff * f) % p for idx, coeff in self.terms.items()})

    def eval(self, witness: Sequence[int]) -> int:
        p = FIELD_PRIME
        total = 0
        for idx, coeff in self.terms.items():
            total = (total + coeff * witness[idx]) % p
        return total

    def to_tuple(self) -> tuple[tuple[int, int], ...]:
        return tuple(sorted(self.terms.items()))


@dataclass(frozen=True)
class QuadraticGate:
    """Single rank-1 quadratic constraint (L . w) * (R . w) - (O . w) == 0 (mod p).

    Represents slice Q[g, l, r] = L[g, l] * R[g, r] of the quadratic constraint tensor.
    """

    left: tuple[tuple[int, int], ...]
    right: tuple[tuple[int, int], ...]
    out: tuple[tuple[int, int], ...]
    category: str = "generic"

    def q_entry(self, l_wire: int, r_wire: int) -> int:
        """Return exact quadratic tensor coefficient Q[g, l_wire, r_wire] mod p."""
        l_dict = dict(self.left)
        r_dict = dict(self.right)
        return (l_dict.get(l_wire, 0) * r_dict.get(r_wire, 0)) % FIELD_PRIME


WitnessOp = Callable[[list[int]], None]


class QuadraticCircuit:
    """Builder and evaluator for layered/R1CS quadratic arithmetic circuits over F_p."""

    def __init__(self) -> None:
        self.num_wires: int = 1  # Wire 0 is fixed constant 1
        self.public_wires: list[int] = []
        self.public_names: list[str] = []
        self.gates: list[QuadraticGate] = []
        self._witness_ops: list[WitnessOp] = []
        self.category_counts: dict[str, int] = {
            "poseidon": 0,
            "bit_decomposition": 0,
            "curve": 0,
            "equality": 0,
        }

    def alloc_public_input(self, name: str) -> int:
        w = self.num_wires
        self.num_wires += 1
        self.public_wires.append(w)
        self.public_names.append(name)
        return w

    def alloc_private_wire(self, compute_fn: Callable[[list[int]], int] | None = None) -> int:
        w = self.num_wires
        self.num_wires += 1
        if compute_fn is not None:
            def _op(wit: list[int], target: int = w, fn: Callable[[list[int]], int] = compute_fn) -> None:
                wit[target] = fn(wit) % FIELD_PRIME
            self._witness_ops.append(_op)
        return w

    def add_gate(
        self,
        left: LinearComb,
        right: LinearComb,
        out: LinearComb,
        category: str = "equality",
    ) -> None:
        gate = QuadraticGate(
            left=left.to_tuple(),
            right=right.to_tuple(),
            out=out.to_tuple(),
            category=category,
        )
        self.gates.append(gate)
        self.category_counts[category] = self.category_counts.get(category, 0) + 1

    def mul_lc(
        self, left: LinearComb, right: LinearComb, category: str
    ) -> LinearComb:
        """Allocate wire z = (left . w) * (right . w) mod p and add quadratic gate."""
        z_wire = self.alloc_private_wire(
            lambda wit, l_lc=left, r_lc=right: (l_lc.eval(wit) * r_lc.eval(wit)) % FIELD_PRIME
        )
        out_lc = LinearComb.from_wire(z_wire)
        self.add_gate(left, right, out_lc, category=category)
        return out_lc

    def assert_zero(self, expr: LinearComb, category: str = "equality") -> None:
        """Enforce (expr . w) * 1 == 0 (mod p)."""
        self.add_gate(expr, LinearComb.from_const(1), LinearComb(), category=category)

    def assert_equal(
        self, lhs: LinearComb, rhs: LinearComb, category: str = "equality"
    ) -> None:
        """Enforce lhs == rhs (mod p)."""
        self.assert_zero(lhs.add(rhs, scale=-1), category=category)

    def assert_bit(self, bit_wire: int) -> None:
        """Enforce b * (b - 1) == 0 (mod p), guaranteeing b in {0, 1}."""
        b_lc = LinearComb.from_wire(bit_wire)
        b_minus_1 = b_lc.add(LinearComb.from_const(-1))
        self.add_gate(b_lc, b_minus_1, LinearComb(), category="bit_decomposition")

    def range_check_bits(
        self, target: LinearComb, num_bits: int = 64
    ) -> list[int]:
        """Enforce `target` in [0, 2^num_bits - 1] via binary decomposition sum_{i} b_i * 2^i == target.

        Prevents modular underflow attacks where negative deltas wrap around modulo p (~2^254).
        """
        bit_wires: list[int] = []
        for i in range(num_bits):
            bw = self.alloc_private_wire(
                lambda wit, lc=target, bit_idx=i: (lc.eval(wit) >> bit_idx) & 1
            )
            self.assert_bit(bw)
            bit_wires.append(bw)

        reconstructed_terms = {bw: (1 << i) for i, bw in enumerate(bit_wires)}
        reconstructed = LinearComb(reconstructed_terms)
        self.assert_equal(reconstructed, target, category="bit_decomposition")
        return bit_wires

    # --- Algebraic Poseidon Gadgets ---

    def _sbox_pow5(self, x: LinearComb) -> LinearComb:
        x2 = self.mul_lc(x, x, category="poseidon")
        x4 = self.mul_lc(x2, x2, category="poseidon")
        return self.mul_lc(x4, x, category="poseidon")

    def _mds_mix(
        self, s0: LinearComb, s1: LinearComb, s2: LinearComb
    ) -> tuple[LinearComb, LinearComb, LinearComb]:
        out: list[LinearComb] = []
        for row in MDS_MATRIX:
            comb = s0.scale(row[0]).add(s1, scale=row[1]).add(s2, scale=row[2])
            out.append(comb)
        return out[0], out[1], out[2]

    def poseidon_permute_gadget(
        self, s0: LinearComb, s1: LinearComb, s2: LinearComb
    ) -> tuple[LinearComb, LinearComb, LinearComb]:
        """Compile all 64 rounds of Poseidon(t=3, R_F=8, R_P=56) into 240 quadratic gates."""
        rc = ROUND_CONSTANTS
        idx = 0

        for _ in range(HALF_FULL_ROUNDS):
            s0 = s0.add(LinearComb.from_const(rc[idx]))
            s1 = s1.add(LinearComb.from_const(rc[idx + 1]))
            s2 = s2.add(LinearComb.from_const(rc[idx + 2]))
            idx += 3
            s0 = self._sbox_pow5(s0)
            s1 = self._sbox_pow5(s1)
            s2 = self._sbox_pow5(s2)
            s0, s1, s2 = self._mds_mix(s0, s1, s2)

        for _ in range(PARTIAL_ROUNDS):
            s0 = s0.add(LinearComb.from_const(rc[idx]))
            s1 = s1.add(LinearComb.from_const(rc[idx + 1]))
            s2 = s2.add(LinearComb.from_const(rc[idx + 2]))
            idx += 3
            s0 = self._sbox_pow5(s0)
            s0, s1, s2 = self._mds_mix(s0, s1, s2)

        for _ in range(HALF_FULL_ROUNDS):
            s0 = s0.add(LinearComb.from_const(rc[idx]))
            s1 = s1.add(LinearComb.from_const(rc[idx + 1]))
            s2 = s2.add(LinearComb.from_const(rc[idx + 2]))
            idx += 3
            s0 = self._sbox_pow5(s0)
            s1 = self._sbox_pow5(s1)
            s2 = self._sbox_pow5(s2)
            s0, s1, s2 = self._mds_mix(s0, s1, s2)

        return s0, s1, s2

    def poseidon_hash_gadget(
        self, inputs: Sequence[LinearComb], domain_tag: int
    ) -> LinearComb:
        """SAFE Poseidon sponge hash gadget matching `poseidon.poseidon_hash` bit-for-bit."""
        n = len(inputs)
        s0 = LinearComb.from_const((domain_tag << 64) + n)
        s1 = LinearComb.from_const(0)
        s2 = LinearComb.from_const(0)

        if n == 0:
            s0, s1, s2 = self.poseidon_permute_gadget(s0, s1, s2)
            return s1

        for offset in range(0, n, POSEIDON_RATE):
            s1 = s1.add(inputs[offset])
            if offset + 1 < n:
                s2 = s2.add(inputs[offset + 1])
            s0, s1, s2 = self.poseidon_permute_gadget(s0, s1, s2)
        return s1

    # --- BabyJubjub Twisted Edwards Curve Gadgets ---

    def assert_on_curve_gadget(self, px: LinearComb, py: LinearComb) -> None:
        """Enforce BabyJubjub curve equation: a * x^2 + y^2 == 1 + d * x^2 * y^2 (mod p)."""
        x2 = self.mul_lc(px, px, category="curve")
        y2 = self.mul_lc(py, py, category="curve")
        x2y2 = self.mul_lc(x2, y2, category="curve")
        lhs = x2.scale(BABYJUBJUB_A).add(y2)
        rhs = LinearComb.from_const(1).add(x2y2, scale=BABYJUBJUB_D)
        self.assert_equal(lhs, rhs, category="curve")

    def edwards_add_gadget(
        self,
        x1: LinearComb,
        y1: LinearComb,
        x2: LinearComb,
        y2: LinearComb,
    ) -> tuple[LinearComb, LinearComb]:
        """Complete Twisted Edwards point addition in 7 quadratic gates (zero edge cases)."""
        p = FIELD_PRIME
        u = self.mul_lc(x1, y2, category="curve")
        v = self.mul_lc(y1, x2, category="curve")
        pxx = self.mul_lc(x1, x2, category="curve")
        pyy = self.mul_lc(y1, y2, category="curve")
        t = self.mul_lc(pxx.scale(BABYJUBJUB_D), pyy, category="curve")

        num_x = u.add(v)
        num_y = pyy.add(pxx, scale=-BABYJUBJUB_A)
        one_plus_t = LinearComb.from_const(1).add(t)
        one_minus_t = LinearComb.from_const(1).add(t, scale=-1)

        x3_wire = self.alloc_private_wire(
            lambda wit, nx=num_x, d_lc=one_plus_t: (
                nx.eval(wit) * pow(d_lc.eval(wit), -1, p)
            )
            % p
        )
        y3_wire = self.alloc_private_wire(
            lambda wit, ny=num_y, d_lc=one_minus_t: (
                ny.eval(wit) * pow(d_lc.eval(wit), -1, p)
            )
            % p
        )
        x3 = LinearComb.from_wire(x3_wire)
        y3 = LinearComb.from_wire(y3_wire)

        # (1 + t) * x3 == u + v   and   (1 - t) * y3 == pyy - a * pxx
        self.add_gate(one_plus_t, x3, num_x, category="curve")
        self.add_gate(one_minus_t, y3, num_y, category="curve")
        return x3, y3

    def fixed_base_scalar_mul_gadget(
        self, bit_wires: Sequence[int], base: Point
    ) -> tuple[LinearComb, LinearComb]:
        """Compute sum_{i} [b_i * 2^i] * base using 2-bit constant-table windows (~5 gates/bit)."""
        num_bits = len(bit_wires)
        if num_bits % 2 != 0:
            raise ValueError("bit_wires length must be even")
        windows = precompute_2bit_windows(base, num_bits)

        acc_x: LinearComb | None = None
        acc_y: LinearComb | None = None

        for w_idx, (_, p1, p2, p3) in enumerate(windows):
            b0_wire = bit_wires[2 * w_idx]
            b1_wire = bit_wires[2 * w_idx + 1]
            b0 = LinearComb.from_wire(b0_wire)
            b1 = LinearComb.from_wire(b1_wire)
            b01 = self.mul_lc(b0, b1, category="curve")

            # Exact multilinear lookup on {0, 1}^2 with P0 = (0, 1):
            # Tx(b0, b1) = x1*b0 + x2*b1 + (x3 - x1 - x2)*b01
            # Ty(b0, b1) = 1 + (y1 - 1)*b0 + (y2 - 1)*b1 + (y3 - y1 - y2 + 1)*b01
            tx = (
                b0.scale(p1.x)
                .add(b1, scale=p2.x)
                .add(b01, scale=p3.x - p1.x - p2.x)
            )
            ty = (
                LinearComb.from_const(1)
                .add(b0, scale=p1.y - 1)
                .add(b1, scale=p2.y - 1)
                .add(b01, scale=p3.y - p1.y - p2.y + 1)
            )

            if acc_x is None or acc_y is None:
                acc_x, acc_y = tx, ty
            else:
                acc_x, acc_y = self.edwards_add_gadget(acc_x, acc_y, tx, ty)

        assert acc_x is not None and acc_y is not None
        return acc_x, acc_y

    def evaluate_gate_vectors(
        self, witness: Sequence[int]
    ) -> tuple[list[int], list[int], list[int]]:
        """Evaluate L_g(w), R_g(w), O_g(w) for all gates g = 0..len(gates)-1."""
        p = FIELD_PRIME
        m = len(self.gates)
        l_vals = [0] * m
        r_vals = [0] * m
        o_vals = [0] * m

        for g_idx, gate in enumerate(self.gates):
            lv = 0
            for w_i, c in gate.left:
                lv = (lv + c * witness[w_i]) % p
            rv = 0
            for w_i, c in gate.right:
                rv = (rv + c * witness[w_i]) % p
            ov = 0
            for w_i, c in gate.out:
                ov = (ov + c * witness[w_i]) % p
            l_vals[g_idx] = lv
            r_vals[g_idx] = rv
            o_vals[g_idx] = ov
        return l_vals, r_vals, o_vals

    def is_satisfied(self, witness: Sequence[int]) -> tuple[bool, int | None]:
        """Check whether all quadratic gates hold on `witness`; return (ok, first_failed_gate)."""
        p = FIELD_PRIME
        l_vals, r_vals, o_vals = self.evaluate_gate_vectors(witness)
        for g_idx in range(len(self.gates)):
            if (l_vals[g_idx] * r_vals[g_idx] - o_vals[g_idx]) % p != 0:
                return False, g_idx
        return True, None


# ---------------------------------------------------------------------------
# Complete Age-Verification Circuit Specification & Witness Populator
# ---------------------------------------------------------------------------


@dataclass
class AgeVerificationCircuitSpec:
    """Compiled circuit layout for ZeroAge anonymous age verification."""

    circuit: QuadraticCircuit
    issuer_pub_key: Point
    # Public input wires
    pub_pk_issuer_x: int
    pub_pk_issuer_y: int
    pub_t_now: int
    pub_revocation_epoch: int
    pub_challenge_hash: int
    pub_session_tag: int
    # Private root input wires
    priv_dob_timestamp: int
    priv_valid_from: int
    priv_valid_until: int
    priv_secret_salt: int
    priv_cred_epoch: int
    priv_sig_rx: int
    priv_sig_ry: int
    priv_sig_s_bits: list[int]
    priv_dev_sk_bits: list[int]
    priv_session_blind: int
    # Range check bit wire groups (exposed for adversarial security test inspection)
    age_delta_bit_wires: list[int]
    valid_from_bit_wires: list[int]
    valid_until_bit_wires: list[int]
    # Evaluation-blinding gate wires (reserved at final gate index M - 1)
    blind_l_wire: int
    blind_r_wire: int
    blind_o_wire: int
    padded_gate_count: int
    sumcheck_rounds: int
    zk_mask_wires: list[int]  # 3*k + 1 wires for ZK-Sumcheck masking polynomial G(x)


@lru_cache(maxsize=8)
def build_age_verification_circuit(issuer_pub_key: Point) -> AgeVerificationCircuitSpec:
    """Compile the complete Poseidon + BabyJubjub Schnorr + 64-bit Range-Check circuit."""
    c = QuadraticCircuit()

    # 1. Public input wires (verified against server-authoritative state)
    pub_pk_x = c.alloc_public_input("pk_issuer_x")
    pub_pk_y = c.alloc_public_input("pk_issuer_y")
    pub_t_now = c.alloc_public_input("t_now")
    pub_rev_epoch = c.alloc_public_input("active_revocation_epoch")
    pub_chal_hash = c.alloc_public_input("challenge_hash")
    pub_sess_tag = c.alloc_public_input("session_tag")

    # Enforce public issuer key matches the compiled fixed-base curve table
    c.assert_equal(
        LinearComb.from_wire(pub_pk_x), LinearComb.from_const(issuer_pub_key.x)
    )
    c.assert_equal(
        LinearComb.from_wire(pub_pk_y), LinearComb.from_const(issuer_pub_key.y)
    )

    # 2. Private root witness wires
    priv_dob = c.alloc_private_wire()
    priv_v_from = c.alloc_private_wire()
    priv_v_until = c.alloc_private_wire()
    priv_salt = c.alloc_private_wire()
    priv_cred_epoch = c.alloc_private_wire()
    priv_sig_rx = c.alloc_private_wire()
    priv_sig_ry = c.alloc_private_wire()

    priv_sig_s_bits = [c.alloc_private_wire() for _ in range(SCALAR_BITS)]
    for bw in priv_sig_s_bits:
        c.assert_bit(bw)

    priv_dev_sk_bits = [c.alloc_private_wire() for _ in range(SCALAR_BITS)]
    for bw in priv_dev_sk_bits:
        c.assert_bit(bw)

    priv_sess_blind = c.alloc_private_wire()

    # 3. Device Key Binding: [sk_dev] * G -> (PK_dev_x, PK_dev_y) -> device_pub_key tag
    dev_pk_x, dev_pk_y = c.fixed_base_scalar_mul_gadget(priv_dev_sk_bits, BASE_POINT)
    dev_pk_tag = c.poseidon_hash_gadget([dev_pk_x, dev_pk_y], domain_tag=DOMAIN_PK_TAG)

    # Reconstruct scalar sk_dev in F_p from its verified boolean bits for session tag binding
    dev_sk_lc = LinearComb({bw: (1 << i) for i, bw in enumerate(priv_dev_sk_bits)})
    computed_sess_tag = c.poseidon_hash_gadget(
        [
            dev_sk_lc,
            LinearComb.from_wire(pub_chal_hash),
            LinearComb.from_wire(priv_sess_blind),
        ],
        domain_tag=DOMAIN_SESSION_BIND,
    )
    c.assert_equal(computed_sess_tag, LinearComb.from_wire(pub_sess_tag))

    # 4. Credential Poseidon Commitment C
    cred_commitment = c.poseidon_hash_gadget(
        [
            LinearComb.from_wire(priv_dob),
            LinearComb.from_wire(priv_v_from),
            LinearComb.from_wire(priv_v_until),
            dev_pk_tag,
            LinearComb.from_wire(priv_salt),
            LinearComb.from_wire(priv_cred_epoch),
        ],
        domain_tag=DOMAIN_CREDENTIAL,
    )

    # 5. In-Circuit Blinded Schnorr Signature Verification over BabyJubjub:
    #    - R = (sig_rx, sig_ry) is on BabyJubjub
    #    - e = Poseidon(DOMAIN_SCHNORR_SIG, R_x, R_y, PK_issuer_x, PK_issuer_y, C)
    #    - [s] * G == R + [e] * PK_issuer
    r_x_lc = LinearComb.from_wire(priv_sig_rx)
    r_y_lc = LinearComb.from_wire(priv_sig_ry)
    c.assert_on_curve_gadget(r_x_lc, r_y_lc)

    e_lc = c.poseidon_hash_gadget(
        [
            r_x_lc,
            r_y_lc,
            LinearComb.from_wire(pub_pk_x),
            LinearComb.from_wire(pub_pk_y),
            cred_commitment,
        ],
        domain_tag=DOMAIN_SCHNORR_SIG,
    )
    # Decompose 254-bit field element e into verified bits e_0..e_253
    e_bit_wires = c.range_check_bits(e_lc, num_bits=FIELD_BITS)

    lhs_x, lhs_y = c.fixed_base_scalar_mul_gadget(priv_sig_s_bits, BASE_POINT)
    epk_x, epk_y = c.fixed_base_scalar_mul_gadget(e_bit_wires, issuer_pub_key)
    rhs_x, rhs_y = c.edwards_add_gadget(r_x_lc, r_y_lc, epk_x, epk_y)
    c.assert_equal(lhs_x, rhs_x, category="curve")
    c.assert_equal(lhs_y, rhs_y, category="curve")

    # 6. Age >= 18 Check WITHOUT Modular Underflow:
    #    Delta_age = t_now - dob_timestamp - AGE_18_SECONDS in [0, 2^64 - 1]
    t_now_lc = LinearComb.from_wire(pub_t_now)
    delta_age = (
        t_now_lc.add(LinearComb.from_wire(priv_dob), scale=-1)
        .add(LinearComb.from_const(-AGE_18_SECONDS))
    )
    age_bits = c.range_check_bits(delta_age, num_bits=64)

    # 7. Validity Window & Active Revocation Epoch Check:
    #    t_now - valid_from in [0, 2^64 - 1]
    #    valid_until - t_now in [0, 2^64 - 1]
    #    cred.revocation_epoch == active_revocation_epoch
    delta_from = t_now_lc.add(LinearComb.from_wire(priv_v_from), scale=-1)
    from_bits = c.range_check_bits(delta_from, num_bits=64)

    delta_until = LinearComb.from_wire(priv_v_until).add(t_now_lc, scale=-1)
    until_bits = c.range_check_bits(delta_until, num_bits=64)

    c.assert_equal(
        LinearComb.from_wire(priv_cred_epoch),
        LinearComb.from_wire(pub_rev_epoch),
    )

    # 8. Pad circuit to M = 2^k gates, placing the evaluation-blinding gate at M - 1
    active_plus_blind = len(c.gates) + 1
    k = 1
    while (1 << k) < active_plus_blind:
        k += 1
    padded_m = 1 << k

    # Pad dummy zero gates up to padded_m - 1 (don't inflate active category metrics)
    dummy_gate = QuadraticGate(left=(), right=(), out=(), category="padding")
    while len(c.gates) < padded_m - 1:
        c.gates.append(dummy_gate)

    blind_l = c.alloc_private_wire()
    blind_r = c.alloc_private_wire()
    blind_o = c.alloc_private_wire(
        lambda wit, bl=blind_l, br=blind_r: (wit[bl] * wit[br]) % FIELD_PRIME
    )
    c.gates.append(
        QuadraticGate(
            left=((blind_l, 1),),
            right=((blind_r, 1),),
            out=((blind_o, 1),),
            category="blinding",
        )
    )

    # 9. Allocate 3*k + 1 wires for the ZK-Sumcheck masking polynomial G(x_0, ..., x_{k-1})
    zk_mask_wires = [c.alloc_private_wire() for _ in range(3 * k + 1)]

    return AgeVerificationCircuitSpec(
        circuit=c,
        issuer_pub_key=issuer_pub_key,
        pub_pk_issuer_x=pub_pk_x,
        pub_pk_issuer_y=pub_pk_y,
        pub_t_now=pub_t_now,
        pub_revocation_epoch=pub_rev_epoch,
        pub_challenge_hash=pub_chal_hash,
        pub_session_tag=pub_sess_tag,
        priv_dob_timestamp=priv_dob,
        priv_valid_from=priv_v_from,
        priv_valid_until=priv_v_until,
        priv_secret_salt=priv_salt,
        priv_cred_epoch=priv_cred_epoch,
        priv_sig_rx=priv_sig_rx,
        priv_sig_ry=priv_sig_ry,
        priv_sig_s_bits=priv_sig_s_bits,
        priv_dev_sk_bits=priv_dev_sk_bits,
        priv_session_blind=priv_sess_blind,
        age_delta_bit_wires=age_bits,
        valid_from_bit_wires=from_bits,
        valid_until_bit_wires=until_bits,
        blind_l_wire=blind_l,
        blind_r_wire=blind_r,
        blind_o_wire=blind_o,
        padded_gate_count=padded_m,
        sumcheck_rounds=k,
        zk_mask_wires=zk_mask_wires,
    )


def populate_age_witness(
    spec: AgeVerificationCircuitSpec,
    *,
    t_now: int,
    active_revocation_epoch: int,
    challenge_hash: int,
    session_tag: int,
    dob_timestamp: int,
    valid_from: int,
    valid_until: int,
    secret_salt: int,
    cred_revocation_epoch: int,
    sig_rx: int,
    sig_ry: int,
    sig_s: int,
    device_priv_key: int,
    session_blind: int,
) -> list[int]:
    """Synthesize the complete circuit witness vector `w` in F_p^num_wires."""
    p = FIELD_PRIME
    wit = [0] * spec.circuit.num_wires
    wit[0] = 1

    # Public inputs
    wit[spec.pub_pk_issuer_x] = spec.issuer_pub_key.x % p
    wit[spec.pub_pk_issuer_y] = spec.issuer_pub_key.y % p
    wit[spec.pub_t_now] = t_now % p
    wit[spec.pub_revocation_epoch] = active_revocation_epoch % p
    wit[spec.pub_challenge_hash] = challenge_hash % p
    wit[spec.pub_session_tag] = session_tag % p

    # Private root inputs
    wit[spec.priv_dob_timestamp] = dob_timestamp % p
    wit[spec.priv_valid_from] = valid_from % p
    wit[spec.priv_valid_until] = valid_until % p
    wit[spec.priv_secret_salt] = secret_salt % p
    wit[spec.priv_cred_epoch] = cred_revocation_epoch % p
    wit[spec.priv_sig_rx] = sig_rx % p
    wit[spec.priv_sig_ry] = sig_ry % p

    for i, bw in enumerate(spec.priv_sig_s_bits):
        wit[bw] = (sig_s >> i) & 1
    for i, bw in enumerate(spec.priv_dev_sk_bits):
        wit[bw] = (device_priv_key >> i) & 1

    wit[spec.priv_session_blind] = session_blind % p

    # Fresh random blinding wires for Sumcheck evaluation hiding & ZK-Sumcheck polynomial G
    wit[spec.blind_l_wire] = secrets.randbelow(p - 1) + 1
    wit[spec.blind_r_wire] = secrets.randbelow(p - 1) + 1
    for mw in spec.zk_mask_wires:
        wit[mw] = secrets.randbelow(p)

    # Propagate all deterministic intermediate wires in topological order
    for op in spec.circuit._witness_ops:
        op(wit)

    return wit


# ---------------------------------------------------------------------------
# Compact Field Vector Serialization & Merkle Tree Commitment
# ---------------------------------------------------------------------------


def pack_field_list(values: Sequence[int]) -> str:
    """Pack a list of F_p integers into compact URL-safe Base64 (32 bytes/element)."""
    raw = b"".join((v % FIELD_PRIME).to_bytes(32, "big") for v in values)
    return base64.urlsafe_b64encode(raw).decode("ascii")


def unpack_field_list(encoded: str) -> list[int]:
    """Unpack URL-safe Base64 back into validated canonical F_p elements (< p)."""
    raw = base64.urlsafe_b64decode(encoded.encode("ascii"))
    if len(raw) % 32 != 0:
        raise ValueError("Invalid packed field vector byte length")
    out: list[int] = []
    for offset in range(0, len(raw), 32):
        val = int.from_bytes(raw[offset : offset + 32], "big")
        if val >= FIELD_PRIME:
            raise ValueError("Non-canonical field element >= p in proof payload")
        out.append(val)
    return out


def _hash_column_leaf(col_idx: int, col_values: Sequence[int]) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"ZeroAge-Ligero-Leaf:")
    hasher.update(col_idx.to_bytes(4, "big"))
    for v in col_values:
        hasher.update(v.to_bytes(32, "big"))
    return hasher.digest()


def _hash_merkle_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"ZeroAge-Ligero-Node:" + left + right).digest()


class MerkleTree:
    """Binary SHA-256 Merkle tree over the N_RS = 512 encoded columns of the Ligero tableau."""

    def __init__(self, leaves: Sequence[bytes]) -> None:
        n = len(leaves)
        if n == 0 or (n & (n - 1)) != 0:
            raise ValueError("Leaf count must be a positive power of two")
        self.num_leaves = n
        self.layers: list[list[bytes]] = [list(leaves)]
        cur = list(leaves)
        while len(cur) > 1:
            nxt = [
                _hash_merkle_node(cur[2 * i], cur[2 * i + 1])
                for i in range(len(cur) // 2)
            ]
            self.layers.append(nxt)
            cur = nxt

    @property
    def root(self) -> bytes:
        return self.layers[-1][0]

    def prove(self, index: int) -> list[str]:
        path: list[str] = []
        idx = index
        for layer in self.layers[:-1]:
            sibling = idx ^ 1
            path.append(layer[sibling].hex())
            idx >>= 1
        return path

    @staticmethod
    def verify(root_hex: str, index: int, leaf_hash: bytes, path_hex: Sequence[str], num_leaves: int) -> bool:
        expected_depth = num_leaves.bit_length() - 1
        if len(path_hex) != expected_depth or not (0 <= index < num_leaves):
            return False
        cur = leaf_hash
        idx = index
        for sibling_hex in path_hex:
            sibling = bytes.fromhex(sibling_hex)
            if idx & 1:
                cur = _hash_merkle_node(sibling, cur)
            else:
                cur = _hash_merkle_node(cur, sibling)
            idx >>= 1
        return cur.hex() == root_hex


# ---------------------------------------------------------------------------
# ZK-Sumcheck + One-Time Pad (OTP) Ligero Prover & Verifier
# ---------------------------------------------------------------------------


def _expand_eq_table(point: Sequence[int]) -> list[int]:
    """Compute multilinear equality table [eq(g, point)]_{g=0..2^k-1} with LSB-first bit order."""
    p = FIELD_PRIME
    table = [1]
    for r_j in point:
        rj = r_j % p
        one_minus_rj = (1 - rj) % p
        table = [(v * one_minus_rj) % p for v in table] + [(v * rj) % p for v in table]
    return table


def _eval_eq_points(tau: Sequence[int], r_star: Sequence[int]) -> int:
    """Evaluate multilinear equality polynomial eq(tau, r_star) in O(k) operations."""
    p = FIELD_PRIME
    acc = 1
    for t_j, r_j in zip(tau, r_star):
        term = (t_j * r_j + (1 - t_j) * (1 - r_j)) % p
        acc = (acc * term) % p
    return acc


def _lagrange_eval_deg3(evals_0123: Sequence[int], x: int) -> int:
    """Evaluate unique degree <= 3 polynomial with values y_0, y_1, y_2, y_3 at X = 0,1,2,3."""
    p = FIELD_PRIME
    if 0 <= x <= 3:
        return evals_0123[x] % p
    y0, y1, y2, y3 = evals_0123
    inv6 = pow(6, -1, p)
    inv2 = pow(2, -1, p)

    x0 = x % p
    x1 = (x - 1) % p
    x2 = (x - 2) % p
    x3 = (x - 3) % p

    l0 = (x1 * x2 % p) * x3 % p * (p - inv6) % p
    l1 = (x0 * x2 % p) * x3 % p * inv2 % p
    l2 = (x0 * x1 % p) * x3 % p * (p - inv2) % p
    l3 = (x0 * x1 % p) * x2 % p * inv6 % p
    return (y0 * l0 + y1 * l1 + y2 * l2 + y3 * l3) % p


def _build_batched_linear_query(
    spec: AgeVerificationCircuitSpec,
    public_values: Sequence[int],
    r_star: Sequence[int],
    v_l: int,
    v_r: int,
    v_o: int,
    v_g: int,
    s_g: int,
    betas: Sequence[int],
    padded_witness_len: int,
) -> tuple[list[int], int]:
    """Collapse Sumcheck final claims + ZK mask claims + public wire claims into <q_total, w> = v_total."""
    p = FIELD_PRIME
    k = spec.sumcheck_rounds
    eq_r = _expand_eq_table(r_star)

    q_total = [0] * padded_witness_len
    b_l, b_r, b_o, b_vg, b_sg = betas[:5]
    pub_betas = betas[5:]

    # 1..3: Sumcheck gate linear forms q_L, q_R, q_O
    for g_idx, gate in enumerate(spec.circuit.gates):
        eg = eq_r[g_idx]
        if eg == 0:
            continue
        wl = (eg * b_l) % p
        for w_i, coeff in gate.left:
            q_total[w_i] = (q_total[w_i] + wl * coeff) % p
        wr = (eg * b_r) % p
        for w_i, coeff in gate.right:
            q_total[w_i] = (q_total[w_i] + wr * coeff) % p
        wo = (eg * b_o) % p
        for w_i, coeff in gate.out:
            q_total[w_i] = (q_total[w_i] + wo * coeff) % p

    # 4: ZK-Sumcheck mask evaluation G(r*) = c_0 + sum_j (g_{j,1}*r_j + g_{j,2}*r_j^2 + g_{j,3}*r_j^3)
    mw = spec.zk_mask_wires
    q_total[mw[0]] = (q_total[mw[0]] + b_vg) % p
    for j in range(k):
        rj = r_star[j]
        rj2 = (rj * rj) % p
        rj3 = (rj2 * rj) % p
        q_total[mw[1 + 3 * j]] = (q_total[mw[1 + 3 * j]] + b_vg * rj) % p
        q_total[mw[1 + 3 * j + 1]] = (q_total[mw[1 + 3 * j + 1]] + b_vg * rj2) % p
        q_total[mw[1 + 3 * j + 2]] = (q_total[mw[1 + 3 * j + 2]] + b_vg * rj3) % p

    # 5: ZK-Sumcheck hypercube sum S_G = 2^k * c_0 + 2^(k-1) * sum_{j,d} g_{j,d}
    pow_2k = (1 << k) % p
    pow_2k1 = (1 << (k - 1)) % p
    q_total[mw[0]] = (q_total[mw[0]] + b_sg * pow_2k) % p
    term_sg = (b_sg * pow_2k1) % p
    for wire_id in mw[1:]:
        q_total[wire_id] = (q_total[wire_id] + term_sg) % p

    # 6: Public input wires (including constant wire w[0] == 1)
    all_pub_wires = [0] + spec.circuit.public_wires
    if len(all_pub_wires) != len(public_values) or len(pub_betas) != len(public_values):
        raise ValueError("Public input wire count mismatch during batching")

    v_total = (
        b_l * v_l + b_r * v_r + b_o * v_o + b_vg * v_g + b_sg * s_g
    ) % p
    for w_pub, val_pub, b_pub in zip(all_pub_wires, public_values, pub_betas):
        q_total[w_pub] = (q_total[w_pub] + b_pub) % p
        v_total = (v_total + b_pub * (val_pub % p)) % p

    return q_total, v_total


class SumcheckLigeroProver:
    """Generates a non-interactive ZK-Sumcheck + OTP Ligero proof over BN254 F_p."""

    @staticmethod
    def prove(
        spec: AgeVerificationCircuitSpec,
        witness: Sequence[int],
        public_values: Sequence[int],
    ) -> dict[str, Any]:
        p = FIELD_PRIME
        b = LIGERO_BLOCK_SIZE
        n_rs = LIGERO_COL_COUNT
        k = spec.sumcheck_rounds

        # 1. Arrange witness into m x b matrix and construct blinded Reed-Solomon polynomials
        num_data_rows = (len(witness) + b - 1) // b
        padded_w_len = num_data_rows * b
        w_padded = list(witness) + [0] * (padded_w_len - len(witness))

        row_polys: list[list[int]] = []
        encoded_rows: list[list[int]] = []

        for i in range(num_data_rows):
            row_slice = w_padded[i * b : (i + 1) * b]
            # Base polynomial f_{i,0}(X) of degree < b such that f_{i,0}(omega^c) == W_{i,c}
            base_coeffs = intt(row_slice, b)
            # Blind with (X^b - 1) * r_i(X) where deg(r_i) < LIGERO_BLIND_DEG
            r_poly = [secrets.randbelow(p) for _ in range(LIGERO_BLIND_DEG)]
            f_i = [0] * CODE_POLY_LEN
            for idx_c, c_val in enumerate(base_coeffs):
                f_i[idx_c] = c_val
            for idx_r, r_val in enumerate(r_poly):
                f_i[idx_r] = (f_i[idx_r] - r_val) % p
                f_i[idx_r + b] = (f_i[idx_r + b] + r_val) % p

            row_polys.append(f_i)
            encoded_rows.append(coset_ntt(f_i, n_rs))

        # OTP masking row 1: Codeword proximity mask f_code(X) of degree < CODE_POLY_LEN
        f_code = [secrets.randbelow(p) for _ in range(CODE_POLY_LEN)]
        encoded_code = coset_ntt(f_code, n_rs)

        # OTP masking row 2: Dot-product mask f_dot(X) of degree < DOT_POLY_LEN with sum_{H_sub} == 0
        f_dot = [secrets.randbelow(p) for _ in range(DOT_POLY_LEN)]
        harmonic_sum = sum(f_dot[d] for d in range(b, DOT_POLY_LEN, b)) % p
        f_dot[0] = (-harmonic_sum) % p
        encoded_dot = coset_ntt(f_dot, n_rs)

        # Commit all N_RS = 512 columns via Merkle tree
        total_tableau_rows = num_data_rows + 2
        all_encoded = encoded_rows + [encoded_code, encoded_dot]
        leaves = [
            _hash_column_leaf(
                col_j, [all_encoded[row_r][col_j] for row_r in range(total_tableau_rows)]
            )
            for col_j in range(n_rs)
        ]
        merkle = MerkleTree(leaves)
        ligero_root_bytes = merkle.root

        # Compute hypercube sum S_G of the ZK-Sumcheck masking polynomial G(x)
        mw = spec.zk_mask_wires
        c0 = w_padded[mw[0]]
        g_coeffs = [w_padded[w_id] for w_id in mw[1:]]
        s_g = ((1 << k) * c0 + (1 << (k - 1)) * sum(g_coeffs)) % p

        # 2. Initialize Fiat-Shamir Poseidon Transcript
        transcript = PoseidonTranscript()
        transcript.absorb_fields(public_values)
        transcript.absorb_bytes("ligero_merkle_root", ligero_root_bytes)
        transcript.absorb_field(s_g)

        tau = transcript.squeeze_challenges(k, non_zero=True)
        rho_zk = transcript.squeeze_challenge(non_zero=True)

        # 3. Execute k-round Zero-Knowledge Sumcheck over {0, 1}^k
        eq_arr = _expand_eq_table(tau)
        l_arr, r_arr, o_arr = spec.circuit.evaluate_gate_vectors(w_padded)

        round_polys_packed: list[str] = []
        r_star: list[int] = []
        prefix_g_val = c0

        for j in range(k):
            rem = 1 << (k - 1 - j)
            g_j1 = g_coeffs[3 * j]
            g_j2 = g_coeffs[3 * j + 1]
            g_j3 = g_coeffs[3 * j + 2]
            suffix_sum = sum(g_coeffs[3 * (j + 1) :]) % p
            suffix_contrib = ((rem >> 1) * suffix_sum) % p if j + 1 < k else 0

            # Sum F(r_0..r_{j-1}, X, x_{>j}) over x_{>j} for X in {0, 1, 2, 3}
            f_evals = [0, 0, 0, 0]
            half_len = len(eq_arr) // 2
            for idx in range(half_len):
                i0 = 2 * idx
                i1 = i0 + 1
                e0, e1 = eq_arr[i0], eq_arr[i1]
                de = (e1 - e0) % p
                e2 = (e1 + de) % p
                e3 = (e2 + de) % p

                l0, l1 = l_arr[i0], l_arr[i1]
                dl = (l1 - l0) % p
                l2 = (l1 + dl) % p
                l3 = (l2 + dl) % p

                r0_v, r1_v = r_arr[i0], r_arr[i1]
                dr = (r1_v - r0_v) % p
                r2_v = (r1_v + dr) % p
                r3_v = (r2_v + dr) % p

                o0, o1 = o_arr[i0], o_arr[i1]
                do = (o1 - o0) % p
                o2 = (o1 + do) % p
                o3 = (o2 + do) % p

                f_evals[0] = (f_evals[0] + e0 * (l0 * r0_v - o0)) % p
                f_evals[1] = (f_evals[1] + e1 * (l1 * r1_v - o1)) % p
                f_evals[2] = (f_evals[2] + e2 * (l2 * r2_v - o2)) % p
                f_evals[3] = (f_evals[3] + e3 * (l3 * r3_v - o3)) % p

            h_evals = [0, 0, 0, 0]
            base_g_const = (rem * prefix_g_val + suffix_contrib) % p
            for x_pt in range(4):
                gx = (
                    base_g_const
                    + rem * (g_j1 * x_pt + g_j2 * (x_pt**2) + g_j3 * (x_pt**3))
                ) % p
                h_evals[x_pt] = (f_evals[x_pt] + rho_zk * gx) % p

            round_polys_packed.append(pack_field_list(h_evals))
            transcript.absorb_fields(h_evals)
            rj = transcript.squeeze_challenge(non_zero=True)
            r_star.append(rj)

            # Fold multilinear tables at X = rj
            eq_arr = [
                (eq_arr[2 * i] + rj * (eq_arr[2 * i + 1] - eq_arr[2 * i])) % p
                for i in range(half_len)
            ]
            l_arr = [
                (l_arr[2 * i] + rj * (l_arr[2 * i + 1] - l_arr[2 * i])) % p
                for i in range(half_len)
            ]
            r_arr = [
                (r_arr[2 * i] + rj * (r_arr[2 * i + 1] - r_arr[2 * i])) % p
                for i in range(half_len)
            ]
            o_arr = [
                (o_arr[2 * i] + rj * (o_arr[2 * i + 1] - o_arr[2 * i])) % p
                for i in range(half_len)
            ]

            rj2 = (rj * rj) % p
            rj3 = (rj2 * rj) % p
            prefix_g_val = (
                prefix_g_val + g_j1 * rj + g_j2 * rj2 + g_j3 * rj3
            ) % p

        v_l = l_arr[0]
        v_r = r_arr[0]
        v_o = o_arr[0]
        v_g = prefix_g_val

        transcript.absorb_fields([v_l, v_r, v_o, v_g])

        # 4. Batch all linear witness claims into <q_total, w> = v_total
        num_pub_claims = 1 + len(spec.circuit.public_wires)
        betas = transcript.squeeze_challenges(5 + num_pub_claims, non_zero=True)
        q_total, _ = _build_batched_linear_query(
            spec=spec,
            public_values=public_values,
            r_star=r_star,
            v_l=v_l,
            v_r=v_r,
            v_o=v_o,
            v_g=v_g,
            s_g=s_g,
            betas=betas,
            padded_witness_len=padded_w_len,
        )

        # 5. OTP Ligero Codeword Proximity + Univariate Sumcheck Polynomials
        alphas = transcript.squeeze_challenges(num_data_rows, non_zero=True)

        # P_code(X) = f_code(X) + sum_i alpha_i * f_i(X)  (degree < CODE_POLY_LEN)
        p_code = list(f_code)
        for i in range(num_data_rows):
            ai = alphas[i]
            fi = row_polys[i]
            for d in range(CODE_POLY_LEN):
                p_code[d] = (p_code[d] + ai * fi[d]) % p

        # P_dot(X) = f_dot(X) + sum_i q_i(X) * f_i(X) via fast length-512 coset NTT convolution
        acc_coset_evals = list(encoded_dot)
        for i in range(num_data_rows):
            q_slice = q_total[i * b : (i + 1) * b]
            q_poly = intt(q_slice, b)
            q_coset = coset_ntt(q_poly, n_rs)
            f_coset = encoded_rows[i]
            for col_j in range(n_rs):
                acc_coset_evals[col_j] = (
                    acc_coset_evals[col_j] + q_coset[col_j] * f_coset[col_j]
                ) % p
        p_dot_full = coset_intt(acc_coset_evals, n_rs)
        p_dot = p_dot_full[:DOT_POLY_LEN]

        transcript.absorb_fields(p_code)
        transcript.absorb_fields(p_dot)

        # 6. Open t_open = 20 Fiat-Shamir challenged columns with Merkle authentication paths
        opened_indices = transcript.squeeze_distinct_indices(LIGERO_OPEN_COLS, n_rs)
        opened_columns: list[dict[str, Any]] = []
        for col_j in opened_indices:
            col_vals = [all_encoded[row_r][col_j] for row_r in range(total_tableau_rows)]
            opened_columns.append(
                {
                    "col_index": col_j,
                    "values": pack_field_list(col_vals),
                    "merkle_path": merkle.prove(col_j),
                }
            )

        return {
            "scheme": "Poseidon-Sumcheck-OTP-Ligero-BN254-v1",
            "ligero_root": ligero_root_bytes.hex(),
            "num_data_rows": num_data_rows,
            "zk_mask_sum": hex(s_g),
            "sumcheck_rounds": round_polys_packed,
            "final_evals": pack_field_list([v_l, v_r, v_o, v_g]),
            "p_code": pack_field_list(p_code),
            "p_dot": pack_field_list(p_dot),
            "opened_columns": opened_columns,
        }


class SumcheckLigeroVerifier:
    """Cryptographically verifies a non-interactive ZK-Sumcheck + OTP Ligero proof."""

    @staticmethod
    def verify(
        spec: AgeVerificationCircuitSpec,
        proof: dict[str, Any],
        public_values: Sequence[int],
    ) -> tuple[bool, str]:
        p = FIELD_PRIME
        b = LIGERO_BLOCK_SIZE
        n_rs = LIGERO_COL_COUNT
        k = spec.sumcheck_rounds

        try:
            if proof.get("scheme") != "Poseidon-Sumcheck-OTP-Ligero-BN254-v1":
                return False, "Unsupported ZKP protocol scheme identifier"

            ligero_root_hex: str = proof["ligero_root"]
            ligero_root_bytes = bytes.fromhex(ligero_root_hex)
            if len(ligero_root_bytes) != 32:
                return False, "Malformed Ligero Merkle root length"

            expected_rows = (spec.circuit.num_wires + b - 1) // b
            num_data_rows = int(proof["num_data_rows"])
            if num_data_rows != expected_rows:
                return False, "Invalid Ligero witness row geometry"

            s_g = int(proof["zk_mask_sum"], 16)
            if not (0 <= s_g < p):
                return False, "Non-canonical ZK mask sum"

            round_polys_packed: list[str] = proof["sumcheck_rounds"]
            if len(round_polys_packed) != k:
                return False, f"Expected {k} Sumcheck rounds, received {len(round_polys_packed)}"

            final_evals = unpack_field_list(proof["final_evals"])
            if len(final_evals) != 4:
                return False, "Invalid final Sumcheck evaluation tuple"
            v_l, v_r, v_o, v_g = final_evals

            p_code = unpack_field_list(proof["p_code"])
            p_dot = unpack_field_list(proof["p_dot"])
            if len(p_code) != CODE_POLY_LEN or len(p_dot) != DOT_POLY_LEN:
                return False, "Degree bound violation in OTP Ligero polynomials"

            opened_columns: list[dict[str, Any]] = proof["opened_columns"]
            if len(opened_columns) != LIGERO_OPEN_COLS:
                return False, "Invalid number of opened Ligero columns"
        except (KeyError, ValueError, TypeError) as exc:
            return False, f"Malformed ZKP transcript payload: {exc}"

        # 1. Reconstruct Fiat-Shamir transcript from authoritative public inputs
        transcript = PoseidonTranscript()
        transcript.absorb_fields(public_values)
        transcript.absorb_bytes("ligero_merkle_root", ligero_root_bytes)
        transcript.absorb_field(s_g)

        tau = transcript.squeeze_challenges(k, non_zero=True)
        rho_zk = transcript.squeeze_challenge(non_zero=True)

        # 2. Verify all k rounds of ZK-Sumcheck
        claimed_sum = (rho_zk * s_g) % p
        r_star: list[int] = []

        for j in range(k):
            try:
                h_evals = unpack_field_list(round_polys_packed[j])
            except ValueError as exc:
                return False, f"Malformed Sumcheck round {j} polynomial: {exc}"
            if len(h_evals) != 4:
                return False, f"Sumcheck round {j} polynomial must have 4 evaluations"

            if (h_evals[0] + h_evals[1]) % p != claimed_sum:
                return False, f"Sumcheck round {j} consistency check h(0) + h(1) == sum failed"

            transcript.absorb_fields(h_evals)
            rj = transcript.squeeze_challenge(non_zero=True)
            r_star.append(rj)
            claimed_sum = _lagrange_eval_deg3(h_evals, rj)

        # Check final Sumcheck oracle identity at r*:
        # eq(tau, r*) * (v_L * v_R - v_O) + rho_zk * v_G == claimed_sum
        eq_tau_r = _eval_eq_points(tau, r_star)
        expected_final = (eq_tau_r * (v_l * v_r - v_o) + rho_zk * v_g) % p
        if expected_final != claimed_sum:
            return False, "Final Sumcheck quadratic gate identity failed"

        transcript.absorb_fields([v_l, v_r, v_o, v_g])

        # 3. Recompute batched linear query <q_total, w> = v_total
        padded_w_len = num_data_rows * b
        num_pub_claims = 1 + len(spec.circuit.public_wires)
        betas = transcript.squeeze_challenges(5 + num_pub_claims, non_zero=True)
        q_total, v_total = _build_batched_linear_query(
            spec=spec,
            public_values=public_values,
            r_star=r_star,
            v_l=v_l,
            v_r=v_r,
            v_o=v_o,
            v_g=v_g,
            s_g=s_g,
            betas=betas,
            padded_witness_len=padded_w_len,
        )

        # 4. Verify univariate sumcheck identity on P_dot: sum_{c=0..b-1} P_dot(omega^c) == v_total
        dot_sum = (b * sum(p_dot[d] for d in range(0, DOT_POLY_LEN, b))) % p
        if dot_sum != v_total:
            return False, "OTP Ligero linear evaluation sumcheck failed"

        alphas = transcript.squeeze_challenges(num_data_rows, non_zero=True)
        transcript.absorb_fields(p_code)
        transcript.absorb_fields(p_dot)

        expected_indices = transcript.squeeze_distinct_indices(LIGERO_OPEN_COLS, n_rs)

        # Precompute evaluation points x_j = eta * zeta^j for queried columns
        plan_rs = _get_ntt_plan(n_rs)
        zeta = plan_rs.omega

        # Interpolate stencil polynomials q_i(X) of degree < b so we can evaluate at queried x_j
        q_polys = [intt(q_total[i * b : (i + 1) * b], b) for i in range(num_data_rows)]

        total_tableau_rows = num_data_rows + 2
        for expected_col, col_entry in zip(expected_indices, opened_columns):
            if col_entry.get("col_index") != expected_col:
                return False, "Opened Ligero column index does not match Fiat-Shamir challenge"
            try:
                col_vals = unpack_field_list(col_entry["values"])
            except ValueError as exc:
                return False, f"Invalid field encoding in opened column: {exc}"
            if len(col_vals) != total_tableau_rows:
                return False, "Opened Ligero column height mismatch"

            leaf_hash = _hash_column_leaf(expected_col, col_vals)
            if not MerkleTree.verify(
                ligero_root_hex,
                expected_col,
                leaf_hash,
                col_entry.get("merkle_path", []),
                n_rs,
            ):
                return False, f"Merkle authentication path failed at column {expected_col}"

            x_j = (COSET_SHIFT * pow(zeta, expected_col, p)) % p
            u_data = col_vals[:num_data_rows]
            u_code = col_vals[num_data_rows]
            u_dot = col_vals[num_data_rows + 1]

            # Check 1: Reed-Solomon Codeword Proximity
            lhs_code = u_code
            for i in range(num_data_rows):
                lhs_code = (lhs_code + alphas[i] * u_data[i]) % p
            rhs_code = poly_eval_horner(p_code, x_j)
            if lhs_code != rhs_code:
                return False, f"OTP Ligero Reed-Solomon proximity failed at column {expected_col}"

            # Check 2: Batched Linear Evaluation / Dot Product Consistency
            lhs_dot = u_dot
            for i in range(num_data_rows):
                q_ij = poly_eval_horner(q_polys[i], x_j)
                lhs_dot = (lhs_dot + q_ij * u_data[i]) % p
            rhs_dot = poly_eval_horner(p_dot, x_j)
            if lhs_dot != rhs_dot:
                return False, f"OTP Ligero linear evaluation check failed at column {expected_col}"

        return True, "Verified"
