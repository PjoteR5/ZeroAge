"""Issuer Node Router (`/issuer`) — Trusted State Identity Registry.

Manages:
- Asymmetric BabyJubjub signing keypair (`SK_issuer`, `PK_issuer`)
- Credential issuance over Poseidon commitment C = Poseidon(dob_timestamp, valid_from,
  valid_until, device_pub_key, secret_salt, revocation_epoch)
- Epoch-based credential revocation registry (`active_revocation_epoch` & `revoked_ids`)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets
import time
from typing import Callable

from fastapi import APIRouter, HTTPException, Request, status

from app.models import (
    CurvePointModel,
    IssueCredentialRequest,
    IssuerPublicKeyResponse,
    RefreshEpochRequest,
    RevocationStatusResponse,
    RevokeCredentialRequest,
    RevokeCredentialResponse,
    SchnorrSignatureModel,
    SignedCredential,
)
from zkp_engine.crypto_primitives import (
    FIELD_PRIME,
    KeyPair,
    Point,
    SchnorrSignature,
    compute_credential_commitment,
    generate_keypair,
    generate_random_field_element,
    schnorr_sign,
    schnorr_verify,
)

UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def parse_dob_to_timestamp(dob_iso: str) -> int:
    """Convert ISO-8601 date string 'YYYY-MM-DD' into exact UTC Unix seconds."""
    try:
        parsed = datetime.strptime(dob_iso.strip(), "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ValueError(
            f"Invalid birth date '{dob_iso}'; expected ISO format YYYY-MM-DD"
        ) from exc
    return (parsed - UNIX_EPOCH) // timedelta(seconds=1)


def _parse_hex_or_int_field(raw: str) -> int:
    text = raw.strip()
    val = int(text, 16) if text.startswith(("0x", "0X")) else int(text)
    if not (0 <= val < FIELD_PRIME):
        raise ValueError("Field element out of canonical [0, p-1] range")
    return val


class IssuerRegistryService:
    """State registry holding `(SK_issuer, PK_issuer)` and active revocation epoch."""

    def __init__(
        self,
        keypair: KeyPair | None = None,
        state_file: Path | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._state_file = state_file
        self._clock = clock or (lambda: int(time.time()))
        self.active_revocation_epoch: int = 1
        self.issued_credential_ids: set[str] = set()
        self.revoked_credential_ids: set[str] = set()

        if state_file is not None and state_file.exists():
            data = json.loads(state_file.read_text(encoding="utf-8"))
            self.keypair = KeyPair.from_dict(data["keypair"])
            self.active_revocation_epoch = int(data.get("active_revocation_epoch", 1))
            self.issued_credential_ids = set(data.get("issued_credential_ids", []))
            self.revoked_credential_ids = set(data.get("revoked_credential_ids", []))
        else:
            self.keypair = keypair or generate_keypair()
            self._persist()

    @property
    def pub_key(self) -> Point:
        return self.keypair.pub_key

    def _persist(self) -> None:
        if self._state_file is None:
            return
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "keypair": self.keypair.to_dict(),
            "active_revocation_epoch": self.active_revocation_epoch,
            "issued_credential_ids": sorted(self.issued_credential_ids),
            "revoked_credential_ids": sorted(self.revoked_credential_ids),
        }
        self._state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def issue_credential(self, req: IssueCredentialRequest) -> SignedCredential:
        """Issue and sign a Poseidon-committed anonymous credential."""
        now_ts = self._clock()

        if req.dob_timestamp is not None:
            dob_ts = int(req.dob_timestamp)
        else:
            assert req.dob is not None
            dob_ts = parse_dob_to_timestamp(req.dob)

        valid_from = int(req.valid_from) if req.valid_from is not None else now_ts
        valid_until = (
            int(req.valid_until)
            if req.valid_until is not None
            else valid_from + req.validity_days * 86400
        )
        if valid_until < valid_from:
            raise ValueError("valid_until must be >= valid_from")

        dev_pk_field = _parse_hex_or_int_field(req.device_pub_key)
        salt_field = (
            _parse_hex_or_int_field(req.secret_salt)
            if req.secret_salt is not None
            else generate_random_field_element(non_zero=True)
        )
        epoch = self.active_revocation_epoch

        commitment = compute_credential_commitment(
            dob_timestamp=dob_ts,
            valid_from=valid_from,
            valid_until=valid_until,
            device_pub_key=dev_pk_field,
            secret_salt=salt_field,
            revocation_epoch=epoch,
        )
        sig = schnorr_sign(self.keypair.priv_key, commitment)

        credential_id = f"cred-{secrets.token_hex(12)}"
        self.issued_credential_ids.add(credential_id)
        self._persist()

        return SignedCredential(
            credential_id=credential_id,
            dob_timestamp=dob_ts,
            valid_from=valid_from,
            valid_until=valid_until,
            device_pub_key=hex(dev_pk_field),
            secret_salt=hex(salt_field),
            revocation_epoch=epoch,
            commitment=hex(commitment),
            signature=SchnorrSignatureModel(**sig.to_dict()),
            issuer_pub_key=CurvePointModel(**self.pub_key.to_dict()),
        )

    def revoke_credential(self, credential_id: str) -> RevokeCredentialResponse:
        """Mark `credential_id` revoked and advance `active_revocation_epoch`."""
        self.revoked_credential_ids.add(credential_id)
        self.active_revocation_epoch += 1
        self._persist()
        return RevokeCredentialResponse(
            revoked_credential_id=credential_id,
            new_revocation_epoch=self.active_revocation_epoch,
            revoked_count=len(self.revoked_credential_ids),
        )

    def refresh_credential_epoch(self, cred: SignedCredential) -> SignedCredential:
        """Re-sign a non-revoked credential under the latest `active_revocation_epoch`."""
        if cred.credential_id in self.revoked_credential_ids:
            raise PermissionError("Credential has been revoked in the Issuer registry")

        dev_pk_field = _parse_hex_or_int_field(cred.device_pub_key)
        salt_field = _parse_hex_or_int_field(cred.secret_salt)
        old_comm = compute_credential_commitment(
            dob_timestamp=cred.dob_timestamp,
            valid_from=cred.valid_from,
            valid_until=cred.valid_until,
            device_pub_key=dev_pk_field,
            secret_salt=salt_field,
            revocation_epoch=cred.revocation_epoch,
        )
        old_sig = SchnorrSignature.from_dict(cred.signature.model_dump())
        if not schnorr_verify(self.pub_key, old_comm, old_sig):
            raise PermissionError("Existing credential signature is invalid")

        new_epoch = self.active_revocation_epoch
        new_comm = compute_credential_commitment(
            dob_timestamp=cred.dob_timestamp,
            valid_from=cred.valid_from,
            valid_until=cred.valid_until,
            device_pub_key=dev_pk_field,
            secret_salt=salt_field,
            revocation_epoch=new_epoch,
        )
        new_sig = schnorr_sign(self.keypair.priv_key, new_comm)

        return SignedCredential(
            credential_id=cred.credential_id,
            dob_timestamp=cred.dob_timestamp,
            valid_from=cred.valid_from,
            valid_until=cred.valid_until,
            device_pub_key=hex(dev_pk_field),
            secret_salt=hex(salt_field),
            revocation_epoch=new_epoch,
            commitment=hex(new_comm),
            signature=SchnorrSignatureModel(**new_sig.to_dict()),
            issuer_pub_key=CurvePointModel(**self.pub_key.to_dict()),
        )


router = APIRouter(prefix="/issuer", tags=["Issuer"])


def _get_issuer_service(request: Request) -> IssuerRegistryService:
    svc: IssuerRegistryService = request.app.state.issuer_service
    return svc


@router.get("/public-key", response_model=IssuerPublicKeyResponse)
def get_issuer_public_key(request: Request) -> IssuerPublicKeyResponse:
    svc = _get_issuer_service(request)
    return IssuerPublicKeyResponse(
        issuer_pub_key=CurvePointModel(**svc.pub_key.to_dict()),
        active_revocation_epoch=svc.active_revocation_epoch,
    )


@router.post(
    "/issue",
    response_model=SignedCredential,
    status_code=status.HTTP_201_CREATED,
)
def issue_credential_endpoint(
    payload: IssueCredentialRequest, request: Request
) -> SignedCredential:
    svc = _get_issuer_service(request)
    try:
        return svc.issue_credential(payload)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@router.post("/revoke", response_model=RevokeCredentialResponse)
def revoke_credential_endpoint(
    payload: RevokeCredentialRequest, request: Request
) -> RevokeCredentialResponse:
    svc = _get_issuer_service(request)
    return svc.revoke_credential(payload.credential_id)


@router.post("/refresh-epoch", response_model=SignedCredential)
def refresh_epoch_endpoint(
    payload: RefreshEpochRequest, request: Request
) -> SignedCredential:
    svc = _get_issuer_service(request)
    try:
        return svc.refresh_credential_epoch(payload.credential)
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc


@router.get("/revocation-status", response_model=RevocationStatusResponse)
def revocation_status_endpoint(request: Request) -> RevocationStatusResponse:
    svc = _get_issuer_service(request)
    return RevocationStatusResponse(
        active_revocation_epoch=svc.active_revocation_epoch,
        revoked_count=len(svc.revoked_credential_ids),
    )
