"""High-Level Zero-Knowledge Verifier (`AgeZKVerifier`).

Verifies non-interactive Poseidon + ZK-Sumcheck + OTP Ligero age proofs against
server-authoritative challenge parameters (`nonce`, `domain`, `t_now`), active
`revocation_epoch`, and the trusted `PK_issuer`.
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any

from zkp_engine.circuit import (
    AgeVerificationCircuitSpec,
    FIELD_PRIME,
    SumcheckLigeroVerifier,
    build_age_verification_circuit,
)
from zkp_engine.crypto_primitives import Point, compute_challenge_hash


@dataclass(frozen=True)
class ZKVerificationOutcome:
    """Result of cryptographic verification of a Zero-Knowledge Age Proof."""

    valid: bool
    reason: str
    verify_time_ms: float


class AgeZKVerifier:
    """Server-side stateless ZKP cryptographic verifier over BN254 F_p."""

    def __init__(self, issuer_pub_key: Point) -> None:
        self.issuer_pub_key = issuer_pub_key
        self.spec: AgeVerificationCircuitSpec = build_age_verification_circuit(
            issuer_pub_key
        )

    def verify_proof(
        self,
        *,
        zkp_transcript: dict[str, Any],
        session_tag_hex: str,
        expected_nonce: str,
        expected_domain: str,
        expected_t_now: int,
        expected_revocation_epoch: int,
    ) -> ZKVerificationOutcome:
        """Verify the ZKP transcript strictly against server-authoritative public inputs."""
        t0 = time.perf_counter()

        try:
            session_tag_int = int(session_tag_hex, 16)
        except (ValueError, TypeError):
            return ZKVerificationOutcome(
                valid=False,
                reason="Malformed session_tag hex encoding",
                verify_time_ms=(time.perf_counter() - t0) * 1000.0,
            )

        if not (0 < session_tag_int < FIELD_PRIME):
            return ZKVerificationOutcome(
                valid=False,
                reason="Non-canonical session_tag field element",
                verify_time_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Recompute challenge digest solely from server-stored challenge record
        challenge_hash = compute_challenge_hash(
            nonce=expected_nonce,
            domain=expected_domain,
            t_now=expected_t_now,
        )

        public_values = [
            1,
            self.issuer_pub_key.x,
            self.issuer_pub_key.y,
            expected_t_now % FIELD_PRIME,
            expected_revocation_epoch % FIELD_PRIME,
            challenge_hash,
            session_tag_int,
        ]

        valid, reason = SumcheckLigeroVerifier.verify(
            spec=self.spec,
            proof=zkp_transcript,
            public_values=public_values,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return ZKVerificationOutcome(
            valid=valid,
            reason=reason,
            verify_time_ms=elapsed_ms,
        )
