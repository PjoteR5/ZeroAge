"""Pydantic v2 Schemas for Issuer, Verifier, Credentials, Challenges, and ZKP Transcripts."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, ConfigDict, Field, model_validator


class CurvePointModel(BaseModel):
    """Hex-encoded BabyJubjub curve point over BN254 scalar field F_p."""

    model_config = ConfigDict(extra="forbid")

    x: str = Field(..., description="0x-prefixed hex x-coordinate in F_p")
    y: str = Field(..., description="0x-prefixed hex y-coordinate in F_p")


class SchnorrSignatureModel(BaseModel):
    """Hex-encoded Poseidon-Schnorr signature (R_x, R_y, s) over BabyJubjub."""

    model_config = ConfigDict(extra="forbid")

    rx: str = Field(..., description="0x-prefixed hex R_x coordinate")
    ry: str = Field(..., description="0x-prefixed hex R_y coordinate")
    s: str = Field(..., description="0x-prefixed hex scalar response s in Z_q")


# ---------------------------------------------------------------------------
# Issuer Node Models (`/issuer`)
# ---------------------------------------------------------------------------


class IssuerPublicKeyResponse(BaseModel):
    """Public signing key and active revocation epoch published by the Issuer registry."""

    model_config = ConfigDict(extra="forbid")

    issuer_pub_key: CurvePointModel
    active_revocation_epoch: int = Field(..., ge=1)


class IssueCredentialRequest(BaseModel):
    """Request payload to issue a Poseidon-committed anonymous age credential."""

    model_config = ConfigDict(extra="forbid")

    holder_name: str = Field(
        default="Anonymous Citizen",
        min_length=1,
        max_length=200,
        description="Identity name verified during KYC issuance (never included in commitment or proof)",
    )
    dob: str | None = Field(
        default=None,
        description="ISO-8601 birth date 'YYYY-MM-DD' (mutually optional with dob_timestamp)",
    )
    dob_timestamp: int | None = Field(
        default=None,
        description="UTC Unix timestamp of birth in seconds",
    )
    device_pub_key: str = Field(
        ...,
        description="0x-prefixed hex Poseidon tag of holder's BabyJubjub device public key",
    )
    secret_salt: str | None = Field(
        default=None,
        description="Optional 0x-prefixed hex blinding salt in F_p (generated if omitted)",
    )
    valid_from: int | None = Field(
        default=None,
        description="Optional explicit credential start timestamp (defaults to current UTC time)",
    )
    valid_until: int | None = Field(
        default=None,
        description="Optional explicit credential expiration timestamp",
    )
    validity_days: int = Field(
        default=365,
        ge=1,
        le=3650,
        description="Validity duration in days when valid_until is omitted",
    )

    @model_validator(mode="after")
    def _ensure_dob_provided(self) -> IssueCredentialRequest:
        if self.dob is None and self.dob_timestamp is None:
            raise ValueError("Either 'dob' (YYYY-MM-DD) or 'dob_timestamp' must be provided")
        return self


class SignedCredential(BaseModel):
    """Signed digital credential stored locally in the user's wallet (`credential.json`)."""

    model_config = ConfigDict(extra="forbid")

    credential_id: str = Field(
        ..., description="Administrative registry handle (never sent to Verifier)"
    )
    dob_timestamp: int
    valid_from: int
    valid_until: int
    device_pub_key: str
    secret_salt: str
    revocation_epoch: int = Field(..., ge=1)
    commitment: str = Field(..., description="0x-prefixed Poseidon commitment C in F_p")
    signature: SchnorrSignatureModel
    issuer_pub_key: CurvePointModel


class RevokeCredentialRequest(BaseModel):
    """Administrative request to revoke a credential and advance the active revocation epoch."""

    model_config = ConfigDict(extra="forbid")

    credential_id: str = Field(..., min_length=1)
    reason: str = Field(default="Revoked by state registry")


class RevokeCredentialResponse(BaseModel):
    """Confirmation of credential revocation and updated registry epoch."""

    model_config = ConfigDict(extra="forbid")

    revoked_credential_id: str
    new_revocation_epoch: int
    revoked_count: int
    status: str = "revoked"


class RefreshEpochRequest(BaseModel):
    """Request by a non-revoked holder to refresh their credential to the latest epoch."""

    model_config = ConfigDict(extra="forbid")

    credential: SignedCredential


class RevocationStatusResponse(BaseModel):
    """Public revocation epoch summary queried by Verifiers and Wallets."""

    model_config = ConfigDict(extra="forbid")

    active_revocation_epoch: int
    revoked_count: int


# ---------------------------------------------------------------------------
# Verifier Node Models (`/verifier`)
# ---------------------------------------------------------------------------


class ChallengeRequest(BaseModel):
    """Request for a fresh single-use cryptographic age-verification challenge."""

    model_config = ConfigDict(extra="forbid")

    domain: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Relying-party domain name (e.g., 'adult-portal.pl')",
    )


class ChallengeResponse(BaseModel):
    """Single-use anti-replay challenge issued by the Verifier node."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    nonce: str
    domain: str
    t_now: int
    active_revocation_epoch: int
    expires_at: int


class LigeroOpenedColumnModel(BaseModel):
    """Single opened column of the OTP Ligero Reed-Solomon tableau + Merkle path."""

    model_config = ConfigDict(extra="forbid")

    col_index: int = Field(..., ge=0)
    values: str = Field(..., description="Base64url-packed canonical F_p column elements")
    merkle_path: list[str] = Field(..., description="Hex SHA-256 sibling hashes")


class ZKProofTranscriptModel(BaseModel):
    """Non-interactive Poseidon + ZK-Sumcheck + OTP Ligero proof transcript."""

    model_config = ConfigDict(extra="forbid")

    scheme: str
    ligero_root: str
    num_data_rows: int = Field(..., ge=1)
    zk_mask_sum: str
    sumcheck_rounds: list[str]
    final_evals: str
    p_code: str
    p_dot: str
    opened_columns: list[LigeroOpenedColumnModel]

    def to_engine_dict(self) -> dict[str, Any]:
        return self.model_dump()


class VerifyProofRequest(BaseModel):
    """Unlinkable Zero-Knowledge Age Verification request sent to `/verifier/verify`."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    nonce: str
    domain: str
    t_now: int
    revocation_epoch: int
    session_tag: str = Field(
        ..., description="0x-prefixed hex session-blinded device binding tag"
    )
    zkp_transcript: ZKProofTranscriptModel


class VerifyProofResponse(BaseModel):
    """Authorized session response containing a signed ES256 JWT token."""

    model_config = ConfigDict(extra="forbid")

    verified: bool
    access_token: str
    token_type: str = "Bearer"
    domain: str
    expires_in: int
    verify_time_ms: float
