"""FastAPI Application Entrypoint (`app/main.py`) for ZeroAge ZKP Age Verifier.

Mounts:
- `/issuer`: Trusted state credential issuer & revocation registry
- `/verifier`: Relying-party anti-replay challenge generator, ZKP verifier & JWT session issuer
- CORS middleware pre-configured for Stage 3 Web UI integration
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.issuer import IssuerRegistryService, router as issuer_router
from app.verifier import VerifierService, router as verifier_router
from zkp_engine.crypto_primitives import KeyPair


def create_app(
    *,
    issuer_keypair: KeyPair | None = None,
    issuer_state_file: Path | None = None,
    challenge_ttl_seconds: int = 120,
    jwt_ttl_seconds: int = 900,
    clock: Callable[[], int] | None = None,
) -> FastAPI:
    """Create a configured FastAPI application instance with isolated or persisted state."""
    application = FastAPI(
        title="ZeroAge — Pure-Python ZKP Age Verification API",
        description=(
            "Anonymous 18+ age verification powered by Algebraic Poseidon over BN254 F_p, "
            "BabyJubjub Schnorr credentials, and Zero-Knowledge Sumcheck + OTP Ligero."
        ),
        version="1.0.0",
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:8000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    issuer_service = IssuerRegistryService(
        keypair=issuer_keypair,
        state_file=issuer_state_file,
        clock=clock,
    )
    verifier_service = VerifierService(
        issuer_service=issuer_service,
        challenge_ttl_seconds=challenge_ttl_seconds,
        jwt_ttl_seconds=jwt_ttl_seconds,
        clock=clock,
    )

    application.state.issuer_service = issuer_service
    application.state.verifier_service = verifier_service

    application.include_router(issuer_router)
    application.include_router(verifier_router)

    @application.get("/health", tags=["System"])
    def health_check() -> dict[str, Any]:
        return {
            "status": "ok",
            "zkp_engine": "Poseidon-Sumcheck-OTP-Ligero-BN254-v1",
            "active_revocation_epoch": issuer_service.active_revocation_epoch,
        }

    return application


_env_state_path = os.environ.get("ZKP_ISSUER_STATE_FILE")
app = create_app(
    issuer_state_file=Path(_env_state_path) if _env_state_path else None
)
