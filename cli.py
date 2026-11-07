"""ZeroAge Terminal MVP Client (`cli.py`) built with `typer` and `rich`.

Provides:
- `APIClient`: Clean HTTP/ASGI service layer ready for Stage 3 Web UI integration.
- `init-wallet`: Generates BabyJubjub device keypair in `~/.zkp_wallet/device_key.json`.
- `issue`: Requests a Poseidon-committed Schnorr credential into `~/.zkp_wallet/credential.json`.
- `verify-age`: Requests a live challenge, builds the Poseidon + ZK-Sumcheck + OTP Ligero
  proof locally, prints constraint & timing telemetry in Rich tables, submits to `/verifier/verify`,
  and displays the signed ES256 JWT session token.
- `demo-all`: Interactive colorized end-to-end showcase of issuance, valid verification, and
  all 5 adversarial security attack simulations.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any

import httpx
from fastapi.testclient import TestClient
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

from app.issuer import parse_dob_to_timestamp
from app.main import create_app
from zkp_engine.circuit import FIELD_PRIME
from zkp_engine.crypto_primitives import (
    KeyPair,
    Point,
    compute_credential_commitment,
    compute_device_pub_key_tag,
    generate_keypair,
    schnorr_sign,
)
from zkp_engine.prover import AgeProver, GeneratedAgeProof

# Ensure UTF-8 output on Windows consoles and piped subprocesses
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

console = Console()
app_cli = typer.Typer(
    name="zeroage",
    help="ZeroAge — 100% Pure-Python Zero-Knowledge Age Verification CLI (Poseidon + Sumcheck + OTP Ligero)",
    add_completion=False,
)


def resolve_wallet_dir(explicit_dir: Path | None = None) -> Path:
    """Resolve `~/.zkp_wallet` (or `ZKP_WALLET_DIR`), falling back safely if home is read-only."""
    if explicit_dir is not None:
        explicit_dir.mkdir(parents=True, exist_ok=True)
        return explicit_dir

    env_dir = os.environ.get("ZKP_WALLET_DIR")
    if env_dir:
        target = Path(env_dir).expanduser()
        target.mkdir(parents=True, exist_ok=True)
        return target

    default_home_wallet = Path.home() / ".zkp_wallet"
    try:
        default_home_wallet.mkdir(parents=True, exist_ok=True)
        probe = default_home_wallet / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return default_home_wallet
    except OSError:
        fallback = Path.cwd() / ".zkp_wallet"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


class APIClient:
    """Clean HTTP service layer decoupling client workflows from FastAPI transport.

    Connects to a live Uvicorn server (`http://127.0.0.1:8000` or `api_url`) when available,
    or transparently mounts the FastAPI application in-process for zero-setup CLI usage.
    """

    def __init__(
        self,
        api_url: str | None = None,
        wallet_dir: Path | None = None,
        isolated_in_memory: bool = False,
    ) -> None:
        self._client: httpx.Client | TestClient
        self.mode: str

        configured_url = api_url or os.environ.get("ZKP_API_URL")
        if isolated_in_memory:
            asgi_app = create_app()
            self._client = TestClient(asgi_app)
            self.mode = "in-process-isolated"
            return

        if configured_url:
            self._client = httpx.Client(base_url=configured_url.rstrip("/"), timeout=30.0)
            self.mode = f"http ({configured_url})"
            return

        # Probe local uvicorn server first
        default_url = "http://127.0.0.1:8000"
        try:
            with httpx.Client(base_url=default_url, timeout=0.3) as probe:
                resp = probe.get("/health")
                if resp.status_code == 200:
                    self._client = httpx.Client(base_url=default_url, timeout=30.0)
                    self.mode = f"http ({default_url})"
                    return
        except Exception:
            pass

        state_dir = wallet_dir or resolve_wallet_dir()
        asgi_app = create_app(issuer_state_file=state_dir / "issuer_registry.json")
        self._client = TestClient(asgi_app)
        self.mode = "in-process-asgi"

    def close(self) -> None:
        self._client.close()

    def get_issuer_public_key(self) -> dict[str, Any]:
        resp = self._client.get("/issuer/public-key")
        resp.raise_for_status()
        return dict(resp.json())

    def issue_credential(
        self,
        *,
        holder_name: str,
        device_pub_key_hex: str,
        dob: str | None = None,
        dob_timestamp: int | None = None,
        valid_from: int | None = None,
        valid_until: int | None = None,
        validity_days: int = 365,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "holder_name": holder_name,
            "device_pub_key": device_pub_key_hex,
            "validity_days": validity_days,
        }
        if dob is not None:
            payload["dob"] = dob
        if dob_timestamp is not None:
            payload["dob_timestamp"] = dob_timestamp
        if valid_from is not None:
            payload["valid_from"] = valid_from
        if valid_until is not None:
            payload["valid_until"] = valid_until

        resp = self._client.post("/issuer/issue", json=payload)
        if resp.status_code >= 400:
            raise RuntimeError(f"Issuance failed ({resp.status_code}): {resp.text}")
        return dict(resp.json())

    def revoke_credential(self, credential_id: str, reason: str = "Revoked") -> dict[str, Any]:
        resp = self._client.post(
            "/issuer/revoke",
            json={"credential_id": credential_id, "reason": reason},
        )
        resp.raise_for_status()
        return dict(resp.json())

    def request_challenge(self, domain: str) -> dict[str, Any]:
        resp = self._client.post("/verifier/challenge", json={"domain": domain})
        resp.raise_for_status()
        return dict(resp.json())

    def submit_proof(self, proof_payload: dict[str, Any]) -> httpx.Response:
        return self._client.post("/verifier/verify", json=proof_payload)

    def access_protected_resource(self, domain: str, jwt_token: str) -> httpx.Response:
        return self._client.get(
            "/verifier/protected",
            params={"domain": domain},
            headers={"Authorization": f"Bearer {jwt_token}"},
        )


def _render_proof_metrics_table(proof: GeneratedAgeProof, verify_ms: float | None = None) -> Table:
    m = proof.metrics
    table = Table(
        title="Poseidon + ZK-Sumcheck + OTP Ligero Telemetry",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("Metric", style="bold white")
    table.add_column("Value", justify="right", style="bright_green")
    table.add_column("Cryptographic Role", style="dim")

    table.add_row(
        "Proving Time",
        f"{m.proving_time_ms:.2f} ms",
        "100% pure-Python witness synthesis + 13-round Sumcheck + 512-col NTT",
    )
    if verify_ms is not None:
        table.add_row(
            "Server Verify Time",
            f"{verify_ms:.2f} ms",
            "Stateless Fiat-Shamir Sumcheck + 20-column Merkle & RS proximity check",
        )
    table.add_row(
        "Poseidon Constraints",
        f"{m.poseidon_constraints:,}",
        "9 algebraic permutations over BN254 F_p (width t=3, R_F=8, R_P=56, x^5)",
    )
    table.add_row(
        "Bit-Decomposition Gates",
        f"{m.bit_decomposition_gates:,}",
        "Three 64-bit underflow range checks + scalar/challenge bit constraints",
    )
    table.add_row(
        "BabyJubjub Curve Gates",
        f"{m.curve_auth_gates:,}",
        "2-bit windowed complete Twisted Edwards Schnorr & device-key auth",
    )
    table.add_row(
        "Total Circuit Size",
        f"{m.total_active_gates:,} / {m.padded_hypercube_gates:,}",
        f"Active quadratic gates / 2^{m.padded_hypercube_gates.bit_length()-1} Sumcheck hypercube ({m.num_wires:,} wires)",
    )
    table.add_row(
        "ZKP Network Payload",
        f"{m.proof_size_bytes:,} bytes ({m.proof_size_bytes / 1024:.1f} KB)",
        "Zero-knowledge unlinkable JSON transcript",
    )
    return table


@app_cli.command("init-wallet")
def init_wallet(
    wallet_dir: Path | None = typer.Option(
        None, "--wallet-dir", help="Custom wallet directory (defaults to ~/.zkp_wallet)"
    ),
) -> None:
    """Generate user's local BabyJubjub device keypair in `~/.zkp_wallet/device_key.json`."""
    w_dir = resolve_wallet_dir(wallet_dir)
    key_file = w_dir / "device_key.json"

    kp = generate_keypair()
    dev_pk_tag = compute_device_pub_key_tag(kp.pub_key)
    wallet_data = {
        **kp.to_dict(),
        "device_pub_key_tag": hex(dev_pk_tag),
        "curve": "BabyJubjub-BN254",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    key_file.write_text(json.dumps(wallet_data, indent=2), encoding="utf-8")

    table = Table(title="Local ZKP Wallet Initialized", box=box.ROUNDED, header_style="bold green")
    table.add_column("Field", style="bold")
    table.add_column("Value", style="cyan")
    table.add_row("Wallet Path", str(key_file))
    table.add_row("Curve / Field", "BabyJubjub over BN254 Scalar Field F_p")
    table.add_row("Public Key X", f"{hex(kp.pub_key.x)[:26]}...")
    table.add_row("Public Key Y", f"{hex(kp.pub_key.y)[:26]}...")
    table.add_row("Poseidon PK Tag", f"{hex(dev_pk_tag)[:26]}...")
    console.print(table)


@app_cli.command("issue")
def issue_credential_cmd(
    name: str = typer.Option(..., "--name", help="Citizen full name for KYC check"),
    dob: str = typer.Option(..., "--dob", help="Date of birth in YYYY-MM-DD format"),
    api_url: str | None = typer.Option(None, "--api-url", help="Optional FastAPI base URL"),
    wallet_dir: Path | None = typer.Option(None, "--wallet-dir", help="Custom wallet directory"),
) -> None:
    """Request a signed Poseidon credential from the Issuer and save to `~/.zkp_wallet/credential.json`."""
    w_dir = resolve_wallet_dir(wallet_dir)
    key_file = w_dir / "device_key.json"
    if not key_file.exists():
        console.print("[yellow]Device key not found; initializing wallet automatically...[/yellow]")
        init_wallet(wallet_dir=w_dir)

    key_data = json.loads(key_file.read_text(encoding="utf-8"))
    kp = KeyPair.from_dict(key_data)
    dev_pk_tag = hex(compute_device_pub_key_tag(kp.pub_key))

    client = APIClient(api_url=api_url, wallet_dir=w_dir)
    try:
        cred = client.issue_credential(
            holder_name=name,
            dob=dob,
            device_pub_key_hex=dev_pk_tag,
        )
    finally:
        client.close()

    cred_file = w_dir / "credential.json"
    cred_file.write_text(json.dumps(cred, indent=2), encoding="utf-8")

    table = Table(
        title="Signed Poseidon Age Credential Issued",
        box=box.ROUNDED,
        header_style="bold magenta",
    )
    table.add_column("Attribute", style="bold")
    table.add_column("Stored Value", style="bright_white")
    table.add_row("Holder (KYC-only, omitted from credential)", name)
    table.add_row("Credential File", str(cred_file))
    table.add_row("Credential Registry ID", cred["credential_id"])
    table.add_row("DOB Timestamp (Private)", f"{cred['dob_timestamp']} ({dob})")
    table.add_row("Revocation Epoch", str(cred["revocation_epoch"]))
    table.add_row("Poseidon Commitment C", f"{cred['commitment'][:30]}...")
    table.add_row("Schnorr Signature (R_x, s)", f"({cred['signature']['rx'][:18]}..., {cred['signature']['s'][:18]}...)")
    console.print(table)


@app_cli.command("verify-age")
def verify_age_cmd(
    domain: str = typer.Option(..., "--domain", help="Target 18+ relying party domain"),
    api_url: str | None = typer.Option(None, "--api-url", help="Optional FastAPI base URL"),
    wallet_dir: Path | None = typer.Option(None, "--wallet-dir", help="Custom wallet directory"),
) -> None:
    """Prove `age >= 18` in zero-knowledge to `/verifier/verify` and obtain an ES256 JWT token."""
    w_dir = resolve_wallet_dir(wallet_dir)
    key_file = w_dir / "device_key.json"
    cred_file = w_dir / "credential.json"

    if not key_file.exists() or not cred_file.exists():
        console.print(
            "[bold red]Error:[/bold red] Missing wallet files. Run `python cli.py init-wallet` "
            "and `python cli.py issue` first."
        )
        raise typer.Exit(code=1)

    kp = KeyPair.from_dict(json.loads(key_file.read_text(encoding="utf-8")))
    cred = json.loads(cred_file.read_text(encoding="utf-8"))

    client = APIClient(api_url=api_url, wallet_dir=w_dir)
    try:
        issuer_info = client.get_issuer_public_key()
        issuer_pk = Point.from_dict(issuer_info["issuer_pub_key"])
        challenge = client.request_challenge(domain=domain)

        prover = AgeProver(issuer_pk)
        proof = prover.generate_proof(
            credential=cred,
            device_keypair=kp,
            session_id=challenge["session_id"],
            nonce=challenge["nonce"],
            domain=challenge["domain"],
            t_now=challenge["t_now"],
            active_revocation_epoch=challenge["active_revocation_epoch"],
        )

        resp = client.submit_proof(proof.to_verify_request_dict())
        if resp.status_code != 200:
            console.print(
                f"[bold red]Verification Rejected ({resp.status_code}):[/bold red] {resp.text}"
            )
            raise typer.Exit(code=1)

        result = resp.json()
        console.print(_render_proof_metrics_table(proof, verify_ms=result["verify_time_ms"]))
        console.print(
            Panel(
                f"[bold green]18+ AGE VERIFIED IN ZERO KNOWLEDGE[/bold green]\n"
                f"[bold]Domain:[/bold] {result['domain']}\n"
                f"[bold]Session Tag (Unlinkable):[/bold] {proof.session_tag[:34]}...\n"
                f"[bold]JWT Session Token (ES256):[/bold]\n[cyan]{result['access_token']}[/cyan]",
                title="Verifier Authorization Granted",
                border_style="green",
            )
        )
    finally:
        client.close()


@app_cli.command("demo-all")
def demo_all_cmd() -> None:
    """Run an end-to-end colorized showcase of issuance, valid ZKP verification, and all 5 attack simulations."""
    console.print(
        Panel(
            "[bold bright_cyan]ZeroAge — Pure-Python Zero-Knowledge Age Verification MVP[/bold bright_cyan]\n"
            "Algebraic Poseidon Sponge (BN254 F_p) + BabyJubjub Schnorr + 13-Round ZK-Sumcheck + OTP Ligero",
            border_style="bright_cyan",
        )
    )

    with tempfile.TemporaryDirectory(prefix="zeroage_demo_") as tmp_dir_str:
        demo_dir = Path(tmp_dir_str)
        client = APIClient(isolated_in_memory=True)

        try:
            # 1. Wallet & Adult Issuance
            console.rule("[bold cyan]Stage 1 & 2: Device Wallet Generation & Credential Issuance")
            adult_kp = generate_keypair()
            adult_pk_tag = hex(compute_device_pub_key_tag(adult_kp.pub_key))
            (demo_dir / "device_key.json").write_text(
                json.dumps(adult_kp.to_dict(), indent=2), encoding="utf-8"
            )

            adult_cred = client.issue_credential(
                holder_name="Jan Kowalski",
                dob="2005-05-10",
                device_pub_key_hex=adult_pk_tag,
            )
            (demo_dir / "credential.json").write_text(
                json.dumps(adult_cred, indent=2), encoding="utf-8"
            )

            issuer_info = client.get_issuer_public_key()
            issuer_pk = Point.from_dict(issuer_info["issuer_pub_key"])
            prover = AgeProver(issuer_pk)

            console.print(
                f"[green]OK[/green] Generated BabyJubjub wallet & issued Poseidon credential "
                f"[bold]{adult_cred['credential_id']}[/bold] for [bold]Jan Kowalski[/bold] (DOB: 2005-05-10)"
            )

            # 2. Valid ZKP Verification
            console.rule("[bold green]Stage 3: Valid Anonymous 18+ Verification (`adult-portal.pl`)")
            chal_valid = client.request_challenge("adult-portal.pl")
            valid_proof = prover.generate_proof(
                credential=adult_cred,
                device_keypair=adult_kp,
                session_id=chal_valid["session_id"],
                nonce=chal_valid["nonce"],
                domain=chal_valid["domain"],
                t_now=chal_valid["t_now"],
                active_revocation_epoch=chal_valid["active_revocation_epoch"],
            )
            resp_valid = client.submit_proof(valid_proof.to_verify_request_dict())
            assert resp_valid.status_code == 200, resp_valid.text
            res_json = resp_valid.json()

            res_prot = client.access_protected_resource(
                "adult-portal.pl", res_json["access_token"]
            )
            assert res_prot.status_code == 200

            console.print(
                _render_proof_metrics_table(
                    valid_proof, verify_ms=res_json["verify_time_ms"]
                )
            )
            console.print(
                f"[bold green]AUTHORIZED![/bold green] ES256 JWT issued (`{res_json['access_token'][:44]}...`) "
                f"and verified on `/verifier/protected`."
            )

            # 3. Run All 5 Security Attack Simulations
            console.rule("[bold yellow]Stage 4: Live Adversarial Security Suite (5 Attack Simulations)")
            audit_rows: list[tuple[str, str, str, str]] = []

            # --- Attack 1: Finite Field Modular Underflow (17-year-old) ---
            chal_1 = client.request_challenge("adult-portal.pl")
            dob_17yo = chal_1["t_now"] - (17 * 365 * 86400)
            minor_cred = client.issue_credential(
                holder_name="Minor 17yo",
                dob_timestamp=dob_17yo,
                device_pub_key_hex=adult_pk_tag,
            )
            # Adversarial prover bypasses client checks and attempts p - |deficit| wrap-around
            forged_underflow_proof = prover.generate_proof(
                credential=minor_cred,
                device_keypair=adult_kp,
                session_id=chal_1["session_id"],
                nonce=chal_1["nonce"],
                domain=chal_1["domain"],
                t_now=chal_1["t_now"],
                active_revocation_epoch=chal_1["active_revocation_epoch"],
                allow_invalid_witness=True,
            )
            r_atk1 = client.submit_proof(forged_underflow_proof.to_verify_request_dict())
            assert r_atk1.status_code == 403
            audit_rows.append(
                (
                    "Test 1: Modular Underflow (17yo)",
                    "17 - 18 == p - 1 (mod p) bypass attempt",
                    f"HTTP {r_atk1.status_code} Rejected",
                    "BLOCKED (64-bit range check)",
                )
            )

            # --- Attack 2: Replay & Cross-Domain Attack ---
            r_atk2_replay = client.submit_proof(valid_proof.to_verify_request_dict())
            assert r_atk2_replay.status_code == 401
            chal_other = client.request_challenge("other-service.pl")
            cross_payload = valid_proof.to_verify_request_dict()
            cross_payload["session_id"] = chal_other["session_id"]
            cross_payload["nonce"] = chal_other["nonce"]
            cross_payload["domain"] = "other-service.pl"
            cross_payload["t_now"] = chal_other["t_now"]
            r_atk2_cross = client.submit_proof(cross_payload)
            assert r_atk2_cross.status_code == 403
            audit_rows.append(
                (
                    "Test 2: Replay & Cross-Domain",
                    "Resubmit valid proof & swap domain/nonce",
                    f"HTTP {r_atk2_replay.status_code} / {r_atk2_cross.status_code} Rejected",
                    "BLOCKED (Nonce TTL + Fiat-Shamir)",
                )
            )

            # --- Attack 3: Credential Tampering & Rogue Issuer Key ---
            tampered_cred = dict(adult_cred)
            tampered_cred["dob_timestamp"] = parse_dob_to_timestamp("1990-01-01")
            chal_3a = client.request_challenge("adult-portal.pl")
            tampered_proof = prover.generate_proof(
                credential=tampered_cred,
                device_keypair=adult_kp,
                session_id=chal_3a["session_id"],
                nonce=chal_3a["nonce"],
                domain=chal_3a["domain"],
                t_now=chal_3a["t_now"],
                active_revocation_epoch=chal_3a["active_revocation_epoch"],
                allow_invalid_witness=True,
            )
            r_atk3a = client.submit_proof(tampered_proof.to_verify_request_dict())
            assert r_atk3a.status_code == 403

            fake_issuer = generate_keypair()
            fake_comm = compute_credential_commitment(
                dob_timestamp=parse_dob_to_timestamp("1995-05-05"),
                valid_from=adult_cred["valid_from"],
                valid_until=adult_cred["valid_until"],
                device_pub_key=int(adult_pk_tag, 16),
                secret_salt=int(adult_cred["secret_salt"], 16),
                revocation_epoch=adult_cred["revocation_epoch"],
            )
            fake_sig = schnorr_sign(fake_issuer.priv_key, fake_comm)
            rogue_cred = {
                **adult_cred,
                "dob_timestamp": parse_dob_to_timestamp("1995-05-05"),
                "signature": fake_sig.to_dict(),
            }
            chal_3b = client.request_challenge("adult-portal.pl")
            rogue_proof = prover.generate_proof(
                credential=rogue_cred,
                device_keypair=adult_kp,
                session_id=chal_3b["session_id"],
                nonce=chal_3b["nonce"],
                domain=chal_3b["domain"],
                t_now=chal_3b["t_now"],
                active_revocation_epoch=chal_3b["active_revocation_epoch"],
                allow_invalid_witness=True,
            )
            r_atk3b = client.submit_proof(rogue_proof.to_verify_request_dict())
            assert r_atk3b.status_code == 403
            audit_rows.append(
                (
                    "Test 3: DOB Tampering & Rogue Key",
                    "Modified local JSON + forged SK_issuer sig",
                    f"HTTP {r_atk3a.status_code} / {r_atk3b.status_code} Rejected",
                    "BLOCKED (In-circuit Schnorr)",
                )
            )

            # --- Attack 4: Expiration & Issuer Revocation ---
            chal_4a = client.request_challenge("adult-portal.pl")
            expired_cred = client.issue_credential(
                holder_name="Expired Holder",
                dob="2000-01-01",
                device_pub_key_hex=adult_pk_tag,
                valid_from=chal_4a["t_now"] - 7200,
                valid_until=chal_4a["t_now"] - 60,
            )
            expired_proof = prover.generate_proof(
                credential=expired_cred,
                device_keypair=adult_kp,
                session_id=chal_4a["session_id"],
                nonce=chal_4a["nonce"],
                domain=chal_4a["domain"],
                t_now=chal_4a["t_now"],
                active_revocation_epoch=chal_4a["active_revocation_epoch"],
                allow_invalid_witness=True,
            )
            r_atk4a = client.submit_proof(expired_proof.to_verify_request_dict())
            assert r_atk4a.status_code == 403

            # Revoke adult_cred in Issuer registry -> bumps active_revocation_epoch
            client.revoke_credential(adult_cred["credential_id"])
            chal_4b = client.request_challenge("adult-portal.pl")
            revoked_proof = prover.generate_proof(
                credential=adult_cred,
                device_keypair=adult_kp,
                session_id=chal_4b["session_id"],
                nonce=chal_4b["nonce"],
                domain=chal_4b["domain"],
                t_now=chal_4b["t_now"],
                active_revocation_epoch=chal_4b["active_revocation_epoch"],
                allow_invalid_witness=True,
            )
            r_atk4b = client.submit_proof(revoked_proof.to_verify_request_dict())
            assert r_atk4b.status_code == 403
            audit_rows.append(
                (
                    "Test 4: Expired & Revoked Cred",
                    "valid_until < t_now & revoked epoch",
                    f"HTTP {r_atk4a.status_code} / {r_atk4b.status_code} Rejected",
                    "BLOCKED (Window + Epoch check)",
                )
            )

            # --- Attack 5: Zero-Knowledge & Unlinkability Audit ---
            fresh_cred = client.issue_credential(
                holder_name="Jan Kowalski",
                dob="2005-05-10",
                device_pub_key_hex=adult_pk_tag,
            )
            c5_1 = client.request_challenge("portal-one.pl")
            c5_2 = client.request_challenge("portal-two.pl")
            p5_1 = prover.generate_proof(
                credential=fresh_cred,
                device_keypair=adult_kp,
                session_id=c5_1["session_id"],
                nonce=c5_1["nonce"],
                domain=c5_1["domain"],
                t_now=c5_1["t_now"],
                active_revocation_epoch=c5_1["active_revocation_epoch"],
            )
            p5_2 = prover.generate_proof(
                credential=fresh_cred,
                device_keypair=adult_kp,
                session_id=c5_2["session_id"],
                nonce=c5_2["nonce"],
                domain=c5_2["domain"],
                t_now=c5_2["t_now"],
                active_revocation_epoch=c5_2["active_revocation_epoch"],
            )
            assert client.submit_proof(p5_1.to_verify_request_dict()).status_code == 200
            assert client.submit_proof(p5_2.to_verify_request_dict()).status_code == 200

            raw_1 = json.dumps(p5_1.to_verify_request_dict())
            raw_2 = json.dumps(p5_2.to_verify_request_dict())
            forbidden_secrets = [
                str(fresh_cred["dob_timestamp"]),
                fresh_cred["secret_salt"],
                fresh_cred["device_pub_key"],
                fresh_cred["commitment"],
                fresh_cred["signature"]["rx"],
                fresh_cred["signature"]["ry"],
                fresh_cred["signature"]["s"],
                fresh_cred["credential_id"],
            ]
            for sec in forbidden_secrets:
                assert sec not in raw_1 and sec not in raw_2
            assert p5_1.session_tag != p5_2.session_tag
            assert (
                p5_1.zkp_transcript["ligero_root"]
                != p5_2.zkp_transcript["ligero_root"]
            )
            audit_rows.append(
                (
                    "Test 5: ZK & Unlinkability Audit",
                    "Inspect 2 transcripts from same citizen",
                    "0 secrets / 0 static IDs",
                    "VERIFIED (100% Unlinkable)",
                )
            )

            sec_table = Table(
                title="Automated Adversarial Security Suite Results (5 / 5 Passed)",
                box=box.DOUBLE_EDGE,
                header_style="bold yellow",
            )
            sec_table.add_column("Security Test", style="bold white")
            sec_table.add_column("Simulated Vector", style="cyan")
            sec_table.add_column("Verifier Response", style="magenta")
            sec_table.add_column("Status", style="bold bright_green")
            for row in audit_rows:
                sec_table.add_row(*row)
            console.print(sec_table)
            console.print(
                Panel(
                    "[bold bright_green]ALL END-TO-END & SECURITY DEMONSTRATIONS COMPLETED FLAWLESSLY![/bold bright_green]",
                    border_style="bright_green",
                )
            )
        finally:
            client.close()


if __name__ == "__main__":
    app_cli()
