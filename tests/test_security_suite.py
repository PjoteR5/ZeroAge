"""Comprehensive Security & Cryptographic Audit Suite (`tests/test_security_suite.py`).

Covers all 5 mandatory specification scenarios plus algebraic & CLI integration tests:
1. `test_1_finite_field_underflow_attack`
2. `test_2_replay_attack_resistance`
3. `test_3_issuer_signature_and_tampering_integrity`
4. `test_4_revocation_and_expiration_handling`
5. `test_5_zero_knowledge_and_unlinkability_audit`
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
import pytest
from typer.testing import CliRunner

from app.issuer import parse_dob_to_timestamp
from app.main import create_app
from cli import app_cli
from zkp_engine.circuit import (
    AGE_18_SECONDS,
    AgeVerificationCircuitSpec,
    FIELD_PRIME,
    LinearComb,
    QuadraticCircuit,
    unpack_field_list,
)
from zkp_engine.crypto_primitives import (
    KeyPair,
    Point,
    compute_credential_commitment,
    compute_device_pub_key_tag,
    generate_keypair,
    pedersen_commit,
    schnorr_sign,
)
from zkp_engine.poseidon import DOMAIN_CREDENTIAL, poseidon_hash
from zkp_engine.prover import AgeProver, UnderageProofError


@pytest.fixture()
def test_env() -> dict[str, Any]:
    """Create an isolated FastAPI test instance, device wallet, and adult credential."""
    fixed_now = 1794064800  # 2026-11-07 UTC
    current_time = [fixed_now]

    app = create_app(clock=lambda: current_time[0])
    client = TestClient(app)

    device_kp = generate_keypair()
    dev_pk_tag = hex(compute_device_pub_key_tag(device_kp.pub_key))

    issuer_resp = client.get("/issuer/public-key").json()
    issuer_pk = Point.from_dict(issuer_resp["issuer_pub_key"])
    prover = AgeProver(issuer_pk)

    adult_cred_resp = client.post(
        "/issuer/issue",
        json={
            "holder_name": "Jan Kowalski",
            "dob": "2005-05-10",
            "device_pub_key": dev_pk_tag,
        },
    )
    assert adult_cred_resp.status_code == 201
    adult_cred = adult_cred_resp.json()

    return {
        "client": client,
        "clock_ref": current_time,
        "device_kp": device_kp,
        "dev_pk_tag": dev_pk_tag,
        "issuer_pk": issuer_pk,
        "prover": prover,
        "adult_cred": adult_cred,
    }


def _extract_all_transcript_field_elements(transcript: dict[str, Any]) -> set[int]:
    """Unpack every F_p integer transmitted inside a ZKP transcript for zero-knowledge auditing."""
    elements: set[int] = {int(transcript["zk_mask_sum"], 16)}
    for r_poly in transcript["sumcheck_rounds"]:
        elements.update(unpack_field_list(r_poly))
    elements.update(unpack_field_list(transcript["final_evals"]))
    elements.update(unpack_field_list(transcript["p_code"]))
    elements.update(unpack_field_list(transcript["p_dot"]))
    for col in transcript["opened_columns"]:
        elements.update(unpack_field_list(col["values"]))
    return elements


# ===========================================================================
# Mandatory Security Test 1: Finite Field Modular Underflow Resistance
# ===========================================================================


def test_1_finite_field_underflow_attack(test_env: dict[str, Any]) -> None:
    """A 17-year-old attempts to prove `age >= 18` exploiting 17 - 18 == p - 1 (mod p).

    Verifies BOTH:
    1. Honest Prover rejects underage credentials locally (`UnderageProofError`).
    2. Malicious Prover bypassing local guards (both truncated 64-bit decomposition AND
       non-boolean wire injection b_0 = Delta mod p) is cryptographically rejected by the
       64-bit binary decomposition constraints in the Verifier's Sumcheck + Ligero circuit.
    """
    client: TestClient = test_env["client"]
    device_kp: KeyPair = test_env["device_kp"]
    dev_pk_tag: str = test_env["dev_pk_tag"]
    prover: AgeProver = test_env["prover"]
    t_now = test_env["clock_ref"][0]

    # Issue a genuine signed credential to a 17-year-old citizen
    dob_17yo = t_now - (17 * 365 * 86400)
    minor_cred = client.post(
        "/issuer/issue",
        json={
            "holder_name": "Piotr Nowak (17yo)",
            "dob_timestamp": dob_17yo,
            "device_pub_key": dev_pk_tag,
        },
    ).json()

    chal_a = client.post("/verifier/challenge", json={"domain": "adult-portal.pl"}).json()

    # 1a. Honest prover guard blocks underage proof generation
    with pytest.raises(UnderageProofError):
        prover.generate_proof(
            credential=minor_cred,
            device_keypair=device_kp,
            session_id=chal_a["session_id"],
            nonce=chal_a["nonce"],
            domain=chal_a["domain"],
            t_now=chal_a["t_now"],
            active_revocation_epoch=chal_a["active_revocation_epoch"],
            allow_invalid_witness=False,
        )

    # 1b. Attack Vector A: Hacker forces proof synthesis with modular underflow p - |deficit|
    underflow_proof_a = prover.generate_proof(
        credential=minor_cred,
        device_keypair=device_kp,
        session_id=chal_a["session_id"],
        nonce=chal_a["nonce"],
        domain=chal_a["domain"],
        t_now=chal_a["t_now"],
        active_revocation_epoch=chal_a["active_revocation_epoch"],
        allow_invalid_witness=True,
    )
    resp_a = client.post("/verifier/verify", json=underflow_proof_a.to_verify_request_dict())
    assert resp_a.status_code == 403
    assert "ZKP verification rejected" in resp_a.json()["detail"]

    # 1c. Attack Vector B: Hacker sets b_0 = (t_now - dob_17yo - AGE_18_SECONDS) mod p and
    #     b_1..b_63 = 0 so sum(b_i * 2^i) == Delta holds mod p, trying to cheat b_0*(b_0 - 1) == 0
    chal_b = client.post("/verifier/challenge", json={"domain": "adult-portal.pl"}).json()

    def _non_binary_bit_attack(spec: AgeVerificationCircuitSpec, wit: list[int]) -> None:
        wrapped_delta = (chal_b["t_now"] - dob_17yo - AGE_18_SECONDS) % FIELD_PRIME
        wit[spec.age_delta_bit_wires[0]] = wrapped_delta
        for bw in spec.age_delta_bit_wires[1:]:
            wit[bw] = 0

    underflow_proof_b = prover.generate_proof(
        credential=minor_cred,
        device_keypair=device_kp,
        session_id=chal_b["session_id"],
        nonce=chal_b["nonce"],
        domain=chal_b["domain"],
        t_now=chal_b["t_now"],
        active_revocation_epoch=chal_b["active_revocation_epoch"],
        allow_invalid_witness=True,
        witness_mutator=_non_binary_bit_attack,
    )
    resp_b = client.post("/verifier/verify", json=underflow_proof_b.to_verify_request_dict())
    assert resp_b.status_code == 403
    assert "ZKP verification rejected" in resp_b.json()["detail"]


# ===========================================================================
# Mandatory Security Test 2: Anti-Replay & Cross-Session/Domain Resistance
# ===========================================================================


def test_2_replay_attack_resistance(test_env: dict[str, Any]) -> None:
    """Attacker replays a captured valid ZKP JSON proof or swaps session/domain/TTL."""
    client: TestClient = test_env["client"]
    device_kp: KeyPair = test_env["device_kp"]
    prover: AgeProver = test_env["prover"]
    adult_cred: dict[str, Any] = test_env["adult_cred"]
    clock_ref: list[int] = test_env["clock_ref"]

    # Legitimate first verification succeeds and returns valid ES256 JWT
    chal = client.post("/verifier/challenge", json={"domain": "adult-portal.pl"}).json()
    valid_proof = prover.generate_proof(
        credential=adult_cred,
        device_keypair=device_kp,
        session_id=chal["session_id"],
        nonce=chal["nonce"],
        domain=chal["domain"],
        t_now=chal["t_now"],
        active_revocation_epoch=chal["active_revocation_epoch"],
    )
    captured_payload = valid_proof.to_verify_request_dict()

    first_resp = client.post("/verifier/verify", json=captured_payload)
    assert first_resp.status_code == 200
    jwt_token = first_resp.json()["access_token"]
    assert client.get(
        "/verifier/protected",
        params={"domain": "adult-portal.pl"},
        headers={"Authorization": f"Bearer {jwt_token}"},
    ).status_code == 200

    # 2a. Exact replay of captured ZKP JSON payload -> HTTP 401 Rejected
    replay_resp = client.post("/verifier/verify", json=captured_payload)
    assert replay_resp.status_code == 401
    assert "Replay attack detected" in replay_resp.json()["detail"]

    # 2b. Cross-session & cross-domain splicing of captured ZKP transcript -> HTTP 403 Rejected
    fresh_chal = client.post("/verifier/challenge", json={"domain": "vip-stream.pl"}).json()
    spliced_payload = {
        **captured_payload,
        "session_id": fresh_chal["session_id"],
        "nonce": fresh_chal["nonce"],
        "domain": fresh_chal["domain"],
        "t_now": fresh_chal["t_now"],
    }
    spliced_resp = client.post("/verifier/verify", json=spliced_payload)
    assert spliced_resp.status_code == 403
    assert "ZKP verification rejected" in spliced_resp.json()["detail"]

    # 2c. Expired challenge TTL (> 120 seconds) -> HTTP 401 Rejected
    ttl_chal = client.post("/verifier/challenge", json={"domain": "adult-portal.pl"}).json()
    late_proof = prover.generate_proof(
        credential=adult_cred,
        device_keypair=device_kp,
        session_id=ttl_chal["session_id"],
        nonce=ttl_chal["nonce"],
        domain=ttl_chal["domain"],
        t_now=ttl_chal["t_now"],
        active_revocation_epoch=ttl_chal["active_revocation_epoch"],
    )
    clock_ref[0] += 300  # Advance server clock past 120s challenge TTL
    expired_ttl_resp = client.post("/verifier/verify", json=late_proof.to_verify_request_dict())
    assert expired_ttl_resp.status_code == 401
    assert "expired" in expired_ttl_resp.json()["detail"].lower()


# ===========================================================================
# Mandatory Security Test 3: Signature Authenticity & Tampering Resistance
# ===========================================================================


def test_3_issuer_signature_and_tampering_integrity(test_env: dict[str, Any]) -> None:
    """User tampers with `dob_timestamp`, signs C with a fake key, or uses wrong device key."""
    client: TestClient = test_env["client"]
    device_kp: KeyPair = test_env["device_kp"]
    dev_pk_tag: str = test_env["dev_pk_tag"]
    prover: AgeProver = test_env["prover"]
    t_now = test_env["clock_ref"][0]

    # Issue a credential to a 15-year-old minor
    minor_cred = client.post(
        "/issuer/issue",
        json={
            "holder_name": "Teenager (15yo)",
            "dob_timestamp": t_now - (15 * 365 * 86400),
            "device_pub_key": dev_pk_tag,
        },
    ).json()

    # 3a. Local JSON Tampering: alter `dob_timestamp` to 1998-05-10 while keeping Issuer sig
    tampered_cred = {
        **minor_cred,
        "dob_timestamp": parse_dob_to_timestamp("1998-05-10"),
    }
    chal_a = client.post("/verifier/challenge", json={"domain": "adult-portal.pl"}).json()
    forged_a = prover.generate_proof(
        credential=tampered_cred,
        device_keypair=device_kp,
        session_id=chal_a["session_id"],
        nonce=chal_a["nonce"],
        domain=chal_a["domain"],
        t_now=chal_a["t_now"],
        active_revocation_epoch=chal_a["active_revocation_epoch"],
        allow_invalid_witness=True,
    )
    resp_a = client.post("/verifier/verify", json=forged_a.to_verify_request_dict())
    assert resp_a.status_code == 403
    assert "ZKP verification rejected" in resp_a.json()["detail"]

    # 3b. Fake Private Key Forgery: compute valid Poseidon commitment C' and sign with SK_fake
    fake_issuer_kp = generate_keypair()
    forged_dob = parse_dob_to_timestamp("1992-03-15")
    forged_comm = compute_credential_commitment(
        dob_timestamp=forged_dob,
        valid_from=minor_cred["valid_from"],
        valid_until=minor_cred["valid_until"],
        device_pub_key=int(dev_pk_tag, 16),
        secret_salt=int(minor_cred["secret_salt"], 16),
        revocation_epoch=minor_cred["revocation_epoch"],
    )
    fake_sig = schnorr_sign(fake_issuer_kp.priv_key, forged_comm)
    fake_signed_cred = {
        **minor_cred,
        "dob_timestamp": forged_dob,
        "commitment": hex(forged_comm),
        "signature": fake_sig.to_dict(),
    }

    chal_b = client.post("/verifier/challenge", json={"domain": "adult-portal.pl"}).json()
    forged_b = prover.generate_proof(
        credential=fake_signed_cred,
        device_keypair=device_kp,
        session_id=chal_b["session_id"],
        nonce=chal_b["nonce"],
        domain=chal_b["domain"],
        t_now=chal_b["t_now"],
        active_revocation_epoch=chal_b["active_revocation_epoch"],
        allow_invalid_witness=True,
    )
    resp_b = client.post("/verifier/verify", json=forged_b.to_verify_request_dict())
    assert resp_b.status_code == 403
    assert "ZKP verification rejected" in resp_b.json()["detail"]

    # 3c. Stolen Credential / Wrong Device Private Key Attack
    thief_device_kp = generate_keypair()
    chal_c = client.post("/verifier/challenge", json={"domain": "adult-portal.pl"}).json()
    forged_c = prover.generate_proof(
        credential=test_env["adult_cred"],
        device_keypair=thief_device_kp,
        session_id=chal_c["session_id"],
        nonce=chal_c["nonce"],
        domain=chal_c["domain"],
        t_now=chal_c["t_now"],
        active_revocation_epoch=chal_c["active_revocation_epoch"],
        allow_invalid_witness=True,
    )
    resp_c = client.post("/verifier/verify", json=forged_c.to_verify_request_dict())
    assert resp_c.status_code == 403


# ===========================================================================
# Mandatory Security Test 4: Revocation & Expiration Handling
# ===========================================================================


def test_4_revocation_and_expiration_handling(test_env: dict[str, Any]) -> None:
    """User attempts to authenticate with an expired or Issuer-revoked credential."""
    client: TestClient = test_env["client"]
    device_kp: KeyPair = test_env["device_kp"]
    dev_pk_tag: str = test_env["dev_pk_tag"]
    prover: AgeProver = test_env["prover"]
    adult_cred: dict[str, Any] = test_env["adult_cred"]
    t_now = test_env["clock_ref"][0]

    # 4a. Expired credential (`valid_until < t_now`) rejected by 64-bit range check in circuit
    expired_cred = client.post(
        "/issuer/issue",
        json={
            "holder_name": "Expired Citizen",
            "dob": "1999-08-20",
            "device_pub_key": dev_pk_tag,
            "valid_from": t_now - 86400 * 30,
            "valid_until": t_now - 60,
        },
    ).json()

    chal_exp = client.post("/verifier/challenge", json={"domain": "adult-portal.pl"}).json()
    expired_proof = prover.generate_proof(
        credential=expired_cred,
        device_keypair=device_kp,
        session_id=chal_exp["session_id"],
        nonce=chal_exp["nonce"],
        domain=chal_exp["domain"],
        t_now=chal_exp["t_now"],
        active_revocation_epoch=chal_exp["active_revocation_epoch"],
        allow_invalid_witness=True,
    )
    resp_exp = client.post("/verifier/verify", json=expired_proof.to_verify_request_dict())
    assert resp_exp.status_code == 403
    assert "ZKP verification rejected" in resp_exp.json()["detail"]

    # 4b. Issue a second non-revoked user credential, then revoke `adult_cred` in Issuer registry
    second_kp = generate_keypair()
    second_cred = client.post(
        "/issuer/issue",
        json={
            "holder_name": "Anna Wisniewska",
            "dob": "2001-11-02",
            "device_pub_key": hex(compute_device_pub_key_tag(second_kp.pub_key)),
        },
    ).json()

    rev_resp = client.post(
        "/issuer/revoke",
        json={"credential_id": adult_cred["credential_id"], "reason": "Compromised card"},
    )
    assert rev_resp.status_code == 200
    assert rev_resp.json()["new_revocation_epoch"] == 2

    # Revoked holder attempts to submit proof claiming stale epoch 1 -> HTTP 403
    chal_rev1 = client.post("/verifier/challenge", json={"domain": "adult-portal.pl"}).json()
    assert chal_rev1["active_revocation_epoch"] == 2
    stale_proof = prover.generate_proof(
        credential=adult_cred,
        device_keypair=device_kp,
        session_id=chal_rev1["session_id"],
        nonce=chal_rev1["nonce"],
        domain=chal_rev1["domain"],
        t_now=chal_rev1["t_now"],
        active_revocation_epoch=1,
        allow_invalid_witness=True,
    )
    resp_rev1 = client.post("/verifier/verify", json=stale_proof.to_verify_request_dict())
    assert resp_rev1.status_code == 403

    # Revoked holder attempts to spoof active epoch 2 inside ZKP proof -> HTTP 403
    chal_rev2 = client.post("/verifier/challenge", json={"domain": "adult-portal.pl"}).json()
    spoof_epoch_proof = prover.generate_proof(
        credential=adult_cred,
        device_keypair=device_kp,
        session_id=chal_rev2["session_id"],
        nonce=chal_rev2["nonce"],
        domain=chal_rev2["domain"],
        t_now=chal_rev2["t_now"],
        active_revocation_epoch=chal_rev2["active_revocation_epoch"],
        allow_invalid_witness=True,
    )
    resp_rev2 = client.post("/verifier/verify", json=spoof_epoch_proof.to_verify_request_dict())
    assert resp_rev2.status_code == 403

    # Revoked holder is blocked from refreshing epoch at `/issuer/refresh-epoch` -> HTTP 403
    refresh_denied = client.post("/issuer/refresh-epoch", json={"credential": adult_cred})
    assert refresh_denied.status_code == 403

    # Non-revoked citizen refreshes to epoch 2 cleanly and authenticates -> HTTP 200
    refreshed_second = client.post(
        "/issuer/refresh-epoch", json={"credential": second_cred}
    )
    assert refreshed_second.status_code == 200
    chal_ok = client.post("/verifier/challenge", json={"domain": "adult-portal.pl"}).json()
    ok_proof = prover.generate_proof(
        credential=refreshed_second.json(),
        device_keypair=second_kp,
        session_id=chal_ok["session_id"],
        nonce=chal_ok["nonce"],
        domain=chal_ok["domain"],
        t_now=chal_ok["t_now"],
        active_revocation_epoch=chal_ok["active_revocation_epoch"],
    )
    assert client.post("/verifier/verify", json=ok_proof.to_verify_request_dict()).status_code == 200


# ===========================================================================
# Mandatory Security Test 5: Zero-Knowledge & Session Unlinkability Audit
# ===========================================================================


def test_5_zero_knowledge_and_unlinkability_audit(test_env: dict[str, Any]) -> None:
    """Inspect two consecutive network transcripts from the same user for secret leakage & linkability."""
    client: TestClient = test_env["client"]
    device_kp: KeyPair = test_env["device_kp"]
    prover: AgeProver = test_env["prover"]
    adult_cred: dict[str, Any] = test_env["adult_cred"]

    chal_1 = client.post("/verifier/challenge", json={"domain": "adult-portal.pl"}).json()
    chal_2 = client.post("/verifier/challenge", json={"domain": "adult-portal.pl"}).json()

    proof_1 = prover.generate_proof(
        credential=adult_cred,
        device_keypair=device_kp,
        session_id=chal_1["session_id"],
        nonce=chal_1["nonce"],
        domain=chal_1["domain"],
        t_now=chal_1["t_now"],
        active_revocation_epoch=chal_1["active_revocation_epoch"],
    )
    proof_2 = prover.generate_proof(
        credential=adult_cred,
        device_keypair=device_kp,
        session_id=chal_2["session_id"],
        nonce=chal_2["nonce"],
        domain=chal_2["domain"],
        t_now=chal_2["t_now"],
        active_revocation_epoch=chal_2["active_revocation_epoch"],
    )

    payload_1 = proof_1.to_verify_request_dict()
    payload_2 = proof_2.to_verify_request_dict()

    assert client.post("/verifier/verify", json=payload_1).status_code == 200
    assert client.post("/verifier/verify", json=payload_2).status_code == 200

    json_1 = json.dumps(payload_1)
    json_2 = json.dumps(payload_2)

    # 5a. Ensure NO private attribute, key, commitment, ID, or raw signature string appears in JSON
    forbidden_strings = [
        "Jan Kowalski",
        str(adult_cred["dob_timestamp"]),
        hex(adult_cred["dob_timestamp"]),
        adult_cred["secret_salt"],
        adult_cred["device_pub_key"],
        hex(device_kp.priv_key),
        hex(device_kp.pub_key.x),
        hex(device_kp.pub_key.y),
        adult_cred["commitment"],
        adult_cred["credential_id"],
        adult_cred["signature"]["rx"],
        adult_cred["signature"]["ry"],
        adult_cred["signature"]["s"],
    ]
    for secret_str in forbidden_strings:
        assert secret_str not in json_1, f"Leaked {secret_str} in transcript 1"
        assert secret_str not in json_2, f"Leaked {secret_str} in transcript 2"

    # 5b. Unpack EVERY binary Base64url F_p field element inside both transcripts and ensure
    #     no private credential scalar appears even inside packed binary arrays
    forbidden_field_ints = {
        adult_cred["dob_timestamp"] % FIELD_PRIME,
        int(adult_cred["secret_salt"], 16),
        int(adult_cred["device_pub_key"], 16),
        device_kp.priv_key,
        device_kp.pub_key.x,
        device_kp.pub_key.y,
        int(adult_cred["commitment"], 16),
        int(adult_cred["signature"]["rx"], 16),
        int(adult_cred["signature"]["ry"], 16),
        int(adult_cred["signature"]["s"], 16),
    }
    fields_1 = _extract_all_transcript_field_elements(payload_1["zkp_transcript"])
    fields_2 = _extract_all_transcript_field_elements(payload_2["zkp_transcript"])
    assert forbidden_field_ints.isdisjoint(fields_1)
    assert forbidden_field_ints.isdisjoint(fields_2)

    # 5c. Verify zero linkable static identifiers across the two transcripts
    assert payload_1["session_tag"] != payload_2["session_tag"]
    t1 = payload_1["zkp_transcript"]
    t2 = payload_2["zkp_transcript"]
    assert t1["ligero_root"] != t2["ligero_root"]
    assert t1["zk_mask_sum"] != t2["zk_mask_sum"]
    assert t1["final_evals"] != t2["final_evals"]
    assert t1["p_code"] != t2["p_code"]
    assert t1["p_dot"] != t2["p_dot"]
    assert set(t1["sumcheck_rounds"]).isdisjoint(set(t2["sumcheck_rounds"]))
    # Even unpacked field elements across both masked transcripts are completely disjoint
    assert fields_1.isdisjoint(fields_2)


# ===========================================================================
# Additional Algebraic & CLI Integration Verification Tests
# ===========================================================================


def test_poseidon_circuit_gadget_exact_equivalence() -> None:
    """Verify `QuadraticCircuit.poseidon_hash_gadget` matches `poseidon_hash` bit-for-bit."""
    inputs = [1115683200, 1794000000, 1825536000, 999888777, 1234567890123, 1]
    expected = poseidon_hash(inputs, domain_tag=DOMAIN_CREDENTIAL)

    c = QuadraticCircuit()
    wires = [c.alloc_private_wire() for _ in inputs]
    out_lc = c.poseidon_hash_gadget(
        [LinearComb.from_wire(w) for w in wires], domain_tag=DOMAIN_CREDENTIAL
    )

    wit = [0] * c.num_wires
    wit[0] = 1
    for w, val in zip(wires, inputs):
        wit[w] = val
    for op in c._witness_ops:
        op(wit)

    ok, failed = c.is_satisfied(wit)
    assert ok, f"Poseidon gadget failed at gate {failed}"
    assert out_lc.eval(wit) == expected


def test_pedersen_commitment_homomorphism() -> None:
    """Verify BabyJubjub Pedersen commitment C(v1, r1) + C(v2, r2) == C(v1+v2, r1+r2)."""
    from zkp_engine.crypto_primitives import point_add

    c1 = pedersen_commit(18, 1234567)
    c2 = pedersen_commit(25, 7654321)
    c_sum = pedersen_commit(18 + 25, 1234567 + 7654321)
    assert point_add(c1, c2) == c_sum


def test_cli_end_to_end_workflow(tmp_path: Path) -> None:
    """Verify `cli.py init-wallet`, `issue`, and `verify-age` commands end-to-end."""
    runner = CliRunner()
    wallet_arg = str(tmp_path / "wallet")

    res_init = runner.invoke(app_cli, ["init-wallet", "--wallet-dir", wallet_arg])
    assert res_init.exit_code == 0, res_init.output
    assert (Path(wallet_arg) / "device_key.json").exists()

    res_issue = runner.invoke(
        app_cli,
        [
            "issue",
            "--name",
            "Jan Kowalski",
            "--dob",
            "2005-05-10",
            "--wallet-dir",
            wallet_arg,
        ],
    )
    assert res_issue.exit_code == 0, res_issue.output
    assert (Path(wallet_arg) / "credential.json").exists()

    res_verify = runner.invoke(
        app_cli,
        [
            "verify-age",
            "--domain",
            "adult-portal.pl",
            "--wallet-dir",
            wallet_arg,
        ],
    )
    assert res_verify.exit_code == 0, res_verify.output
    assert "18+ AGE VERIFIED IN ZERO KNOWLEDGE" in res_verify.output
