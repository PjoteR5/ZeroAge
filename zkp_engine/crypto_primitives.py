"""Cryptographic Primitives for ZeroAge ZKP Age Verification.

Provides:
1. BabyJubjub complete Twisted Edwards curve over BN254 scalar field F_p (EIP-2494),
   allowing curve group operations to be proven natively inside the F_p quadratic circuit
   with ~5 gates per bit and zero point-at-infinity edge cases.
2. Poseidon algebraic commitments & BabyJubjub Pedersen commitments.
3. Schnorr signatures over BabyJubjub with algebraic Poseidon challenge hashing.
4. RFC 7519 / RFC 7518 ES256 (NIST P-256 ECDSA) JWT session token signing & verification
   backed by Python's `cryptography` library.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import secrets
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from zkp_engine.poseidon import (
    DOMAIN_CHALLENGE,
    DOMAIN_CREDENTIAL,
    DOMAIN_PK_TAG,
    DOMAIN_SCHNORR_SIG,
    DOMAIN_SESSION_BIND,
    FIELD_PRIME,
    poseidon_hash,
    str_to_field,
)

# BabyJubjub Twisted Edwards curve parameters over BN254 scalar field F_p:
# Equation: a * x^2 + y^2 = 1 + d * x^2 * y^2 (mod p)
# Since Legendre(a, p) = +1 and Legendre(d, p) = -1, the addition law is 100% complete.
BABYJUBJUB_A: int = 168700
BABYJUBJUB_D: int = 168696
BABYJUBJUB_COFACTOR: int = 8

# Prime order q of the BabyJubjub cryptographic subgroup G (251-bit prime)
SUBGROUP_ORDER: int = (
    2736030358979909402780800718157159386076813972158567259200215660948447373041
)
SCALAR_BITS: int = 252  # ceil_even(Subgroup bit-length 251) = 252 (126 2-bit windows)
FIELD_BITS: int = 254   # BN254 field bit-length = 254 (127 2-bit windows)


@dataclass(frozen=True)
class Point:
    """Affine point (x, y) on the BabyJubjub Twisted Edwards curve over F_p."""

    x: int
    y: int

    def to_dict(self) -> dict[str, str]:
        return {"x": hex(self.x), "y": hex(self.y)}

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> Point:
        return cls(x=int(data["x"], 16), y=int(data["y"], 16))


NEUTRAL_POINT = Point(0, 1)

# Canonical EIP-2494 prime-order subgroup generator G of order SUBGROUP_ORDER
BASE_POINT = Point(
    x=5299619240641551281634865583518297030282874472190772894086521144482721001553,
    y=16950150798460657717958625567821834550301663161624707787222815936182638968203,
)


def is_on_curve(pt: Point) -> bool:
    """Check whether (x, y) lies on BabyJubjub over F_p."""
    p = FIELD_PRIME
    if not (0 <= pt.x < p and 0 <= pt.y < p):
        return False
    x2 = (pt.x * pt.x) % p
    y2 = (pt.y * pt.y) % p
    lhs = (BABYJUBJUB_A * x2 + y2) % p
    rhs = (1 + BABYJUBJUB_D * x2 % p * y2) % p
    return lhs == rhs


def point_neg(pt: Point) -> Point:
    """Negate a Twisted Edwards curve point: -(x, y) = (-x mod p, y)."""
    return Point((FIELD_PRIME - pt.x) % FIELD_PRIME, pt.y)


def point_add(p1: Point, p2: Point) -> Point:
    """Complete Twisted Edwards group addition over F_p."""
    p = FIELD_PRIME
    x1, y1 = p1.x, p1.y
    x2, y2 = p2.x, p2.y

    u = (x1 * y2 + y1 * x2) % p
    v = (y1 * y2 - BABYJUBJUB_A * x1 * x2) % p
    t = (BABYJUBJUB_D * x1 % p * x2 % p * y1 % p * y2) % p

    x3 = (u * pow((1 + t) % p, -1, p)) % p
    y3 = (v * pow((1 - t) % p, -1, p)) % p
    return Point(x3, y3)


def point_sub(p1: Point, p2: Point) -> Point:
    """Subtract two Twisted Edwards curve points: p1 - p2 = p1 + (-p2)."""
    return point_add(p1, point_neg(p2))


@lru_cache(maxsize=32)
def precompute_2bit_windows(
    base: Point, num_bits: int = SCALAR_BITS
) -> tuple[tuple[Point, Point, Point, Point], ...]:
    """Precompute 2-bit multiples (0*B_j, 1*B_j, 2*B_j, 3*B_j) where B_j = [4^j] base."""
    if num_bits % 2 != 0:
        raise ValueError("num_bits must be even for 2-bit window precomputation")
    num_windows = num_bits // 2
    windows: list[tuple[Point, Point, Point, Point]] = []
    cur = base
    for _ in range(num_windows):
        p0 = NEUTRAL_POINT
        p1 = cur
        p2 = point_add(cur, cur)
        p3 = point_add(p2, cur)
        windows.append((p0, p1, p2, p3))
        cur = point_add(p2, p2)  # [4] * cur
    return tuple(windows)


def scalar_mul(scalar: int, base: Point = BASE_POINT) -> Point:
    """Multiply `base` by non-negative integer `scalar` using 2-bit windows when cached."""
    if scalar < 0:
        return point_neg(scalar_mul(-scalar, base))
    if scalar == 0 or base == NEUTRAL_POINT:
        return NEUTRAL_POINT

    if base == BASE_POINT and scalar < (1 << SCALAR_BITS):
        windows = precompute_2bit_windows(BASE_POINT, SCALAR_BITS)
        acc = NEUTRAL_POINT
        k = scalar
        idx = 0
        while k > 0:
            digit = k & 0b11
            if digit:
                acc = point_add(acc, windows[idx][digit])
            k >>= 2
            idx += 1
        return acc

    # Generic double-and-add for uncached bases or large scalars
    acc = NEUTRAL_POINT
    addend = base
    k = scalar
    while k > 0:
        if k & 1:
            acc = point_add(acc, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return acc


def is_in_subgroup(pt: Point) -> bool:
    """Verify that `pt` is on the curve and lies in the prime-order subgroup G."""
    return is_on_curve(pt) and scalar_mul(SUBGROUP_ORDER, pt) == NEUTRAL_POINT


def _derive_pedersen_h() -> Point:
    """Derive an independent nothing-up-my-sleeve generator H in G with unknown discrete log."""
    p = FIELD_PRIME
    counter = 0
    while True:
        digest = hashlib.sha256(
            b"ZeroAge-BabyJubjub-Pedersen-Generator-H:" + counter.to_bytes(4, "big")
        ).digest()
        y = int.from_bytes(digest, "big") % p
        y2 = (y * y) % p
        num = (1 - y2) % p
        den = (BABYJUBJUB_A - BABYJUBJUB_D * y2) % p
        if den != 0:
            x2 = (num * pow(den, -1, p)) % p
            # Tonelli-Shanks square root mod p
            if pow(x2, (p - 1) // 2, p) == 1:
                x = _tonelli_shanks_sqrt(x2, p)
                candidate = Point(x, y)
                # Clear cofactor 8 to project into prime-order subgroup G
                h = scalar_mul(BABYJUBJUB_COFACTOR, candidate)
                if h != NEUTRAL_POINT and is_in_subgroup(h):
                    return h
        counter += 1


def _tonelli_shanks_sqrt(n: int, p: int) -> int:
    """Compute modular square root x such that x^2 = n (mod p) via Tonelli-Shanks."""
    if n == 0:
        return 0
    q_ts = p - 1
    s = 0
    while q_ts % 2 == 0:
        q_ts //= 2
        s += 1
    z = 5  # Non-residue search
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m = s
    c = pow(z, q_ts, p)
    t = pow(n, q_ts, p)
    r = pow(n, (q_ts + 1) // 2, p)
    while t != 1:
        i = 1
        temp = (t * t) % p
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p
    return min(r, p - r)


PEDERSEN_H: Point = _derive_pedersen_h()


@dataclass(frozen=True)
class KeyPair:
    """Asymmetric BabyJubjub keypair (priv_key in [1, q-1], pub_key = [priv_key] * G)."""

    priv_key: int
    pub_key: Point

    def to_dict(self) -> dict[str, Any]:
        return {
            "priv_key": hex(self.priv_key),
            "pub_key": self.pub_key.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KeyPair:
        return cls(
            priv_key=int(data["priv_key"], 16),
            pub_key=Point.from_dict(data["pub_key"]),
        )


def generate_keypair() -> KeyPair:
    """Generate a cryptographically secure BabyJubjub keypair."""
    priv = secrets.randbelow(SUBGROUP_ORDER - 1) + 1
    pub = scalar_mul(priv, BASE_POINT)
    return KeyPair(priv_key=priv, pub_key=pub)


def generate_random_field_element(non_zero: bool = True) -> int:
    """Sample a cryptographically random element in F_p (or F_p^*)."""
    if non_zero:
        return secrets.randbelow(FIELD_PRIME - 1) + 1
    return secrets.randbelow(FIELD_PRIME)


def pedersen_commit(value: int, blinding: int) -> Point:
    """Compute hiding & binding BabyJubjub Pedersen commitment C = [value]*G + [blinding]*H."""
    v_pt = scalar_mul(value % SUBGROUP_ORDER, BASE_POINT)
    r_pt = scalar_mul(blinding % SUBGROUP_ORDER, PEDERSEN_H)
    return point_add(v_pt, r_pt)


def compute_device_pub_key_tag(device_pub_key: Point) -> int:
    """Hash a BabyJubjub device public key (x, y) into a single canonical F_p element."""
    return poseidon_hash([device_pub_key.x, device_pub_key.y], domain_tag=DOMAIN_PK_TAG)


def compute_credential_commitment(
    dob_timestamp: int,
    valid_from: int,
    valid_until: int,
    device_pub_key: int,
    secret_salt: int,
    revocation_epoch: int,
) -> int:
    """Compute the Poseidon credential commitment C in F_p over all 6 credential attributes."""
    return poseidon_hash(
        [
            dob_timestamp % FIELD_PRIME,
            valid_from % FIELD_PRIME,
            valid_until % FIELD_PRIME,
            device_pub_key % FIELD_PRIME,
            secret_salt % FIELD_PRIME,
            revocation_epoch % FIELD_PRIME,
        ],
        domain_tag=DOMAIN_CREDENTIAL,
    )


def compute_challenge_hash(nonce: str, domain: str, t_now: int) -> int:
    """Compute algebraic challenge digest Poseidon(nonce, domain, t_now) in F_p."""
    return poseidon_hash(
        [str_to_field(nonce), str_to_field(domain), t_now % FIELD_PRIME],
        domain_tag=DOMAIN_CHALLENGE,
    )


def compute_session_binding_tag(
    device_priv_key: int, challenge_hash: int, session_blind: int
) -> int:
    """Compute blinded session-unique device binding tag Poseidon(sk_dev, h_chal, blind)."""
    return poseidon_hash(
        [
            device_priv_key % FIELD_PRIME,
            challenge_hash % FIELD_PRIME,
            session_blind % FIELD_PRIME,
        ],
        domain_tag=DOMAIN_SESSION_BIND,
    )


@dataclass(frozen=True)
class SchnorrSignature:
    """Poseidon-Schnorr signature (R_x, R_y, s) over BabyJubjub."""

    rx: int
    ry: int
    s: int

    @property
    def r_point(self) -> Point:
        return Point(self.rx, self.ry)

    def to_dict(self) -> dict[str, str]:
        return {
            "rx": hex(self.rx),
            "ry": hex(self.ry),
            "s": hex(self.s),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> SchnorrSignature:
        return cls(
            rx=int(data["rx"], 16),
            ry=int(data["ry"], 16),
            s=int(data["s"], 16),
        )


def schnorr_sign(priv_key: int, message_field: int) -> SchnorrSignature:
    """Sign a field element `message_field` (e.g., Poseidon commitment C) using Schnorr."""
    if not (1 <= priv_key < SUBGROUP_ORDER):
        raise ValueError("Invalid BabyJubjub signing key")
    pub_key = scalar_mul(priv_key, BASE_POINT)

    # Hedged nonce: combines CSPRNG randomness with secret key & message digest
    hedge_entropy = secrets.token_bytes(32)
    nonce_digest = hashlib.sha512(
        b"ZeroAge-Schnorr-Nonce:"
        + priv_key.to_bytes(32, "big")
        + (message_field % FIELD_PRIME).to_bytes(32, "big")
        + hedge_entropy
    ).digest()
    k = (int.from_bytes(nonce_digest, "big") % (SUBGROUP_ORDER - 1)) + 1
    r_pt = scalar_mul(k, BASE_POINT)

    e = poseidon_hash(
        [r_pt.x, r_pt.y, pub_key.x, pub_key.y, message_field % FIELD_PRIME],
        domain_tag=DOMAIN_SCHNORR_SIG,
    )
    s = (k + e * priv_key) % SUBGROUP_ORDER
    return SchnorrSignature(rx=r_pt.x, ry=r_pt.y, s=s)


def schnorr_verify(
    pub_key: Point, message_field: int, signature: SchnorrSignature
) -> bool:
    """Verify a Poseidon-Schnorr signature [s]*G == R + [e]*PK over BabyJubjub."""
    if not (0 <= signature.s < SUBGROUP_ORDER):
        return False
    if not is_in_subgroup(pub_key) or pub_key == NEUTRAL_POINT:
        return False
    r_pt = signature.r_point
    if not is_on_curve(r_pt):
        return False

    e = poseidon_hash(
        [r_pt.x, r_pt.y, pub_key.x, pub_key.y, message_field % FIELD_PRIME],
        domain_tag=DOMAIN_SCHNORR_SIG,
    )
    lhs = scalar_mul(signature.s, BASE_POINT)
    # Note: Since pub_key has prime order q, [e]*pub_key == [e mod q]*pub_key identically
    rhs = point_add(r_pt, scalar_mul(e % SUBGROUP_ORDER, pub_key))
    return lhs == rhs


# ---------------------------------------------------------------------------
# ES256 (NIST P-256 ECDSA) JWT Session Token Utilities (via `cryptography`)
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode((segment + padding).encode("ascii"))


class ES256JWTManager:
    """RFC 7519 JWT issuer & verifier using NIST P-256 ECDSA (`ES256`)."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None) -> None:
        self._private_key = private_key or ec.generate_private_key(ec.SECP256R1())
        self._public_key = self._private_key.public_key()

    def issue_token(
        self,
        *,
        domain: str,
        session_tag_hex: str,
        ttl_seconds: int = 900,
        now_ts: int | None = None,
    ) -> str:
        """Issue a signed ES256 JWT token granting anonymous 18+ session access."""
        iat = int(now_ts if now_ts is not None else time.time())
        header = {"alg": "ES256", "typ": "JWT"}
        payload = {
            "iss": "zeroage-zkp-verifier",
            "aud": domain,
            "sub": f"anon:{session_tag_hex[:32]}",
            "iat": iat,
            "exp": iat + ttl_seconds,
            "age_verified": True,
            "min_age": 18,
            "zkp_protocol": "Poseidon-Sumcheck-Ligero-BN254",
            "jti": secrets.token_hex(16),
        }
        header_b64 = _b64url_encode(
            json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        payload_b64 = _b64url_encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        der_sig = self._private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{header_b64}.{payload_b64}.{_b64url_encode(raw_sig)}"

    def verify_token(
        self,
        token: str,
        *,
        expected_domain: str | None = None,
        now_ts: int | None = None,
    ) -> dict[str, Any]:
        """Verify an ES256 JWT signature and expiration claims, returning decoded payload."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed JWT structure")
        header_b64, payload_b64, sig_b64 = parts
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        if header.get("alg") != "ES256":
            raise ValueError("Unsupported JWT algorithm")

        raw_sig = _b64url_decode(sig_b64)
        if len(raw_sig) != 64:
            raise ValueError("Invalid ES256 signature length")
        r = int.from_bytes(raw_sig[:32], "big")
        s = int.from_bytes(raw_sig[32:], "big")
        der_sig = encode_dss_signature(r, s)

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        try:
            self._public_key.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise ValueError("Invalid JWT ECDSA signature") from exc

        payload: dict[str, Any] = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        current_ts = int(now_ts if now_ts is not None else time.time())
        if payload.get("exp", 0) < current_ts:
            raise ValueError("JWT session token has expired")
        if expected_domain is not None and payload.get("aud") != expected_domain:
            raise ValueError("JWT audience domain mismatch")
        return payload
