"""Verifier Node Router (`/verifier`) — Age-Restricted Relying Party.

Protects 18+ resources via:
1. `POST /verifier/challenge`: Issues a single-use cryptographic challenge
   `(session_id, nonce, domain, t_now)` stored in an in-memory TTL anti-replay registry.
2. `POST /verifier/verify`: Atomically consumes the single-use `nonce`, enforces the
   Issuer's active `revocation_epoch`, cryptographically verifies the Poseidon +
   ZK-Sumcheck + OTP Ligero transcript against trusted `PK_issuer`, and issues a
   standards-compliant ES256 JWT Bearer session token.
3. `GET /verifier/protected`: Demonstrates 18+ resource authorization using the JWT token.
"""

from __future__ import annotations

from dataclasses import dataclass
import secrets
import threading
import time
from typing import Any, Callable

from fastapi import APIRouter, Header, HTTPException, Query, Request, status

from app.issuer import IssuerRegistryService
from app.models import (
    ChallengeRequest,
    ChallengeResponse,
    VerifyProofRequest,
    VerifyProofResponse,
)
from zkp_engine.crypto_primitives import ES256JWTManager
from zkp_engine.verifier_zk import AgeZKVerifier


@dataclass
class ChallengeRecord:
    """Server-authoritative challenge entry in the anti-replay store."""

    session_id: str
    nonce: str
    domain: str
    t_now: int
    active_revocation_epoch: int
    expires_at: int
    consumed: bool = False


class AntiReplayChallengeStore:
    """Thread-safe in-memory single-use challenge store with TTL expiration."""

    def __init__(
        self,
        ttl_seconds: int = 120,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._ttl_seconds = ttl_seconds
        self._clock = clock or (lambda: int(time.time()))
        self._lock = threading.Lock()
        self._sessions: dict[str, ChallengeRecord] = {}
        self._consumed_nonces: set[str] = set()

    def _prune_expired_unlocked(self, now_ts: int) -> None:
        expired_ids = [
            sid
            for sid, rec in self._sessions.items()
            if rec.expires_at < now_ts and not rec.consumed
        ]
        for sid in expired_ids:
            del self._sessions[sid]

    def create_challenge(
        self, domain: str, active_revocation_epoch: int
    ) -> ChallengeRecord:
        now_ts = self._clock()
        session_id = f"sess-{secrets.token_hex(12)}"
        nonce = secrets.token_hex(24)
        record = ChallengeRecord(
            session_id=session_id,
            nonce=nonce,
            domain=domain.strip().lower(),
            t_now=now_ts,
            active_revocation_epoch=active_revocation_epoch,
            expires_at=now_ts + self._ttl_seconds,
            consumed=False,
        )
        with self._lock:
            self._prune_expired_unlocked(now_ts)
            self._sessions[session_id] = record
        return record

    def consume_challenge(
        self,
        *,
        session_id: str,
        nonce: str,
        domain: str,
        t_now: int,
    ) -> ChallengeRecord:
        """Atomically validate & invalidate a single-use challenge, raising ValueError on replay."""
        now_ts = self._clock()
        normalized_domain = domain.strip().lower()

        with self._lock:
            if nonce in self._consumed_nonces:
                raise ValueError("Replay attack detected: nonce has already been used")

            record = self._sessions.get(session_id)
            if record is None:
                raise ValueError("Unknown or expired challenge session_id")

            if record.consumed:
                raise ValueError(
                    "Replay attack detected: challenge session already consumed"
                )

            if now_ts > record.expires_at:
                del self._sessions[session_id]
                raise ValueError("Challenge TTL has expired")

            if record.nonce != nonce:
                raise ValueError("Challenge nonce mismatch for session")

            if record.domain != normalized_domain:
                raise ValueError(
                    f"Domain mismatch: proof bound to '{normalized_domain}', expected '{record.domain}'"
                )

            if record.t_now != t_now:
                raise ValueError("Challenge timestamp t_now mismatch")

            # Single-use invalidation BEFORE returning so concurrent replays always fail
            record.consumed = True
            self._consumed_nonces.add(nonce)
            return record


class VerifierService:
    """Verifier node business logic coordinating anti-replay, ZKP engine, and JWT issuance."""

    def __init__(
        self,
        issuer_service: IssuerRegistryService,
        challenge_ttl_seconds: int = 120,
        jwt_ttl_seconds: int = 900,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.issuer_service = issuer_service
        self._clock = clock or (lambda: int(time.time()))
        self.challenge_store = AntiReplayChallengeStore(
            ttl_seconds=challenge_ttl_seconds, clock=self._clock
        )
        self.jwt_manager = ES256JWTManager()
        self.jwt_ttl_seconds = jwt_ttl_seconds

    def issue_challenge(self, domain: str) -> ChallengeResponse:
        rec = self.challenge_store.create_challenge(
            domain=domain,
            active_revocation_epoch=self.issuer_service.active_revocation_epoch,
        )
        return ChallengeResponse(
            session_id=rec.session_id,
            nonce=rec.nonce,
            domain=rec.domain,
            t_now=rec.t_now,
            active_revocation_epoch=rec.active_revocation_epoch,
            expires_at=rec.expires_at,
        )

    def verify_age_proof(self, req: VerifyProofRequest) -> VerifyProofResponse:
        # 1. Anti-replay & challenge binding check (single-use atomic consumption)
        try:
            challenge_rec = self.challenge_store.consume_challenge(
                session_id=req.session_id,
                nonce=req.nonce,
                domain=req.domain,
                t_now=req.t_now,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
            ) from exc

        # 2. Live Issuer revocation epoch enforcement
        live_epoch = self.issuer_service.active_revocation_epoch
        if req.revocation_epoch != live_epoch:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Revoked or outdated credential epoch: received {req.revocation_epoch}, "
                    f"active registry epoch is {live_epoch}"
                ),
            )

        # 3. Stateless ZKP cryptographic verification against trusted PK_issuer
        zk_verifier = AgeZKVerifier(self.issuer_service.pub_key)
        outcome = zk_verifier.verify_proof(
            zkp_transcript=req.zkp_transcript.to_engine_dict(),
            session_tag_hex=req.session_tag,
            expected_nonce=challenge_rec.nonce,
            expected_domain=challenge_rec.domain,
            expected_t_now=challenge_rec.t_now,
            expected_revocation_epoch=live_epoch,
        )
        if not outcome.valid:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"ZKP verification rejected: {outcome.reason}",
            )

        # 4. Issue ES256 signed JWT session token
        token = self.jwt_manager.issue_token(
            domain=challenge_rec.domain,
            session_tag_hex=req.session_tag,
            ttl_seconds=self.jwt_ttl_seconds,
            now_ts=self._clock(),
        )
        return VerifyProofResponse(
            verified=True,
            access_token=token,
            token_type="Bearer",
            domain=challenge_rec.domain,
            expires_in=self.jwt_ttl_seconds,
            verify_time_ms=round(outcome.verify_time_ms, 2),
        )


router = APIRouter(prefix="/verifier", tags=["Verifier"])


def _get_verifier_service(request: Request) -> VerifierService:
    svc: VerifierService = request.app.state.verifier_service
    return svc


@router.post("/challenge", response_model=ChallengeResponse)
def request_challenge_endpoint(
    payload: ChallengeRequest, request: Request
) -> ChallengeResponse:
    svc = _get_verifier_service(request)
    return svc.issue_challenge(payload.domain)


@router.post("/verify", response_model=VerifyProofResponse)
def verify_proof_endpoint(
    payload: VerifyProofRequest, request: Request
) -> VerifyProofResponse:
    svc = _get_verifier_service(request)
    return svc.verify_age_proof(payload)


@router.get("/protected")
def access_protected_adult_resource(
    request: Request,
    domain: str = Query(..., description="Expected relying-party audience domain"),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """Protected 18+ endpoint verifying Bearer ES256 JWT session tokens."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer JWT token",
        )
    token = authorization.removeprefix("Bearer ").strip()
    svc = _get_verifier_service(request)
    try:
        claims = svc.jwt_manager.verify_token(
            token,
            expected_domain=domain.strip().lower(),
            now_ts=svc._clock(),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    return {
        "access": "granted",
        "resource": f"18+ Restricted Content on {claims['aud']}",
        "anonymous_subject": claims["sub"],
        "zkp_protocol": claims["zkp_protocol"],
    }
