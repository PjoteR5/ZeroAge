"""High-Level Zero-Knowledge Age Prover (`AgeProver`).

Synthesizes non-interactive Poseidon + ZK-Sumcheck + OTP Ligero proofs demonstrating:
1. Credential Integrity: Knowledge of attributes opening Poseidon commitment C signed by
   trusted `PK_issuer`, completely blinded in zero-knowledge (full session unlinkability).
2. Age >= 18 without Modular Underflow: Delta = t_now - dob_timestamp - AGE_18_SECONDS
   lies in [0, 2^64 - 1] via 64-bit boolean decomposition in F_p.
3. Validity Window & Active Epoch: valid_from <= t_now <= valid_until and active epoch match.
4. Device Key & Anti-Replay Challenge Binding: Knowledge of `device_priv_key` matching
   `device_pub_key` inside C, cryptographically bound to Poseidon(nonce, domain, t_now).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import time
from typing import Any, Callable

from zkp_engine.circuit import (
    AGE_18_SECONDS,
    AgeVerificationCircuitSpec,
    SumcheckLigeroProver,
    build_age_verification_circuit,
    populate_age_witness,
)
from zkp_engine.crypto_primitives import (
    KeyPair,
    Point,
    SchnorrSignature,
    compute_challenge_hash,
    compute_credential_commitment,
    compute_device_pub_key_tag,
    compute_session_binding_tag,
    generate_random_field_element,
    schnorr_verify,
)


class ZKProverError(Exception):
    """Base exception raised when local credential preconditions fail."""


class UnderageProofError(ZKProverError):
    """Raised when the credential holder is under 18 years old at `t_now`."""


class CredentialValidityWindowError(ZKProverError):
    """Raised when `t_now` falls outside `[valid_from, valid_until]`."""


class CredentialRevokedOrEpochError(ZKProverError):
    """Raised when credential `revocation_epoch` does not match active registry epoch."""


class InvalidCredentialIntegrityError(ZKProverError):
    """Raised when credential commitment, device binding, or Issuer signature is invalid."""


@dataclass(frozen=True)
class ProofMetrics:
    """Detailed constraint & performance telemetry for CLI Rich tables and benchmarks."""

    proving_time_ms: float
    poseidon_constraints: int
    bit_decomposition_gates: int
    curve_auth_gates: int
    equality_gates: int
    total_active_gates: int
    padded_hypercube_gates: int
    num_wires: int
    proof_size_bytes: int


@dataclass(frozen=True)
class GeneratedAgeProof:
    """Complete ZKP verification bundle and local telemetry."""

    session_id: str
    nonce: str
    domain: str
    t_now: int
    active_revocation_epoch: int
    session_tag: str
    zkp_transcript: dict[str, Any]
    metrics: ProofMetrics

    def to_verify_request_dict(self) -> dict[str, Any]:
        """Serialize only the unlinkable zero-knowledge network payload for `/verifier/verify`."""
        return {
            "session_id": self.session_id,
            "nonce": self.nonce,
            "domain": self.domain,
            "t_now": self.t_now,
            "revocation_epoch": self.active_revocation_epoch,
            "session_tag": self.session_tag,
            "zkp_transcript": self.zkp_transcript,
        }


class AgeProver:
    """Client-side Zero-Knowledge Prover generating unlinkable 18+ age proofs."""

    def __init__(self, issuer_pub_key: Point) -> None:
        self.issuer_pub_key = issuer_pub_key
        self.spec: AgeVerificationCircuitSpec = build_age_verification_circuit(
            issuer_pub_key
        )

    def generate_proof(
        self,
        *,
        credential: dict[str, Any],
        device_keypair: KeyPair,
        session_id: str,
        nonce: str,
        domain: str,
        t_now: int,
        active_revocation_epoch: int,
        allow_invalid_witness: bool = False,
        witness_mutator: Callable[[AgeVerificationCircuitSpec, list[int]], None] | None = None,
    ) -> GeneratedAgeProof:
        """Synthesize a non-interactive Poseidon + Sumcheck + OTP Ligero ZKP proof.

        When `allow_invalid_witness=False` (default), enforces client-side sanity checks.
        When `allow_invalid_witness=True` (used in adversarial security tests), bypasses local
        guards so tests can send forged/underflowed/tampered ZKP transcripts directly to the
        Verifier and confirm cryptographic circuit rejection.
        """
        dob_timestamp = int(credential["dob_timestamp"])
        valid_from = int(credential["valid_from"])
        valid_until = int(credential["valid_until"])
        cred_dev_pk_tag = (
            int(credential["device_pub_key"], 16)
            if isinstance(credential["device_pub_key"], str)
            and credential["device_pub_key"].startswith("0x")
            else int(credential["device_pub_key"])
        )
        secret_salt = (
            int(credential["secret_salt"], 16)
            if isinstance(credential["secret_salt"], str)
            and credential["secret_salt"].startswith("0x")
            else int(credential["secret_salt"])
        )
        cred_epoch = int(credential["revocation_epoch"])
        signature = SchnorrSignature.from_dict(credential["signature"])

        if not allow_invalid_witness:
            derived_dev_tag = compute_device_pub_key_tag(device_keypair.pub_key)
            if derived_dev_tag != cred_dev_pk_tag:
                raise InvalidCredentialIntegrityError(
                    "Wallet device keypair does not match credential device_pub_key binding"
                )

            expected_comm = compute_credential_commitment(
                dob_timestamp=dob_timestamp,
                valid_from=valid_from,
                valid_until=valid_until,
                device_pub_key=cred_dev_pk_tag,
                secret_salt=secret_salt,
                revocation_epoch=cred_epoch,
            )
            if not schnorr_verify(self.issuer_pub_key, expected_comm, signature):
                raise InvalidCredentialIntegrityError(
                    "Credential signature failed verification under trusted PK_issuer"
                )

            if t_now - dob_timestamp < AGE_18_SECONDS:
                raise UnderageProofError(
                    "Holder does not satisfy age >= 18 requirement at challenge timestamp"
                )

            if t_now < valid_from or t_now > valid_until:
                raise CredentialValidityWindowError(
                    "Challenge timestamp t_now lies outside credential [valid_from, valid_until]"
                )

            if cred_epoch != active_revocation_epoch:
                raise CredentialRevokedOrEpochError(
                    f"Credential epoch {cred_epoch} does not match active epoch {active_revocation_epoch}"
                )

        t_start = time.perf_counter()

        challenge_hash = compute_challenge_hash(nonce=nonce, domain=domain, t_now=t_now)
        session_blind = generate_random_field_element(non_zero=True)
        session_tag_int = compute_session_binding_tag(
            device_priv_key=device_keypair.priv_key,
            challenge_hash=challenge_hash,
            session_blind=session_blind,
        )

        witness = populate_age_witness(
            self.spec,
            t_now=t_now,
            active_revocation_epoch=active_revocation_epoch,
            challenge_hash=challenge_hash,
            session_tag=session_tag_int,
            dob_timestamp=dob_timestamp,
            valid_from=valid_from,
            valid_until=valid_until,
            secret_salt=secret_salt,
            cred_revocation_epoch=cred_epoch,
            sig_rx=signature.rx,
            sig_ry=signature.ry,
            sig_s=signature.s,
            device_priv_key=device_keypair.priv_key,
            session_blind=session_blind,
        )

        if witness_mutator is not None:
            witness_mutator(self.spec, witness)

        public_values = [
            1,
            self.issuer_pub_key.x,
            self.issuer_pub_key.y,
            t_now,
            active_revocation_epoch,
            challenge_hash,
            session_tag_int,
        ]

        zkp_transcript = SumcheckLigeroProver.prove(
            spec=self.spec,
            witness=witness,
            public_values=public_values,
        )
        proving_ms = (time.perf_counter() - t_start) * 1000.0

        session_tag_hex = hex(session_tag_int)
        network_payload = {
            "session_id": session_id,
            "nonce": nonce,
            "domain": domain,
            "t_now": t_now,
            "revocation_epoch": active_revocation_epoch,
            "session_tag": session_tag_hex,
            "zkp_transcript": zkp_transcript,
        }
        proof_bytes = len(
            json.dumps(network_payload, separators=(",", ":")).encode("utf-8")
        )

        cats = self.spec.circuit.category_counts
        poseidon_g = cats.get("poseidon", 0)
        bit_g = cats.get("bit_decomposition", 0)
        curve_g = cats.get("curve", 0)
        eq_g = cats.get("equality", 0)
        active_total = poseidon_g + bit_g + curve_g + eq_g

        metrics = ProofMetrics(
            proving_time_ms=proving_ms,
            poseidon_constraints=poseidon_g,
            bit_decomposition_gates=bit_g,
            curve_auth_gates=curve_g,
            equality_gates=eq_g,
            total_active_gates=active_total,
            padded_hypercube_gates=self.spec.padded_gate_count,
            num_wires=self.spec.circuit.num_wires,
            proof_size_bytes=proof_bytes,
        )

        return GeneratedAgeProof(
            session_id=session_id,
            nonce=nonce,
            domain=domain,
            t_now=t_now,
            active_revocation_epoch=active_revocation_epoch,
            session_tag=session_tag_hex,
            zkp_transcript=zkp_transcript,
            metrics=metrics,
        )
