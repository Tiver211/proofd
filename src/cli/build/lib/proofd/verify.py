import base64
import secrets
import logging
import requests
from rich.console import Console
from rich.table import Table

from .crypto import verify_vc_signature, verify_ac_signature
from .hashing import calc_hash
from .format import load_verify

log = logging.getLogger("proofd.verify")
console = Console()


def verify_document(document_path, verify_path, ac_url, ac_pub_key_b64=None, ac_timeout=3, vc_timeout=3):
    data = load_verify(verify_path)

    algo = data["hash"]["algorithm"]
    expected_hash = data["hash"]["value"]
    verifiers = data.get("verifiers", [])

    log.info("Starting verification")
    log.debug(f"Using AC: {ac_url}")

    actual_hash = calc_hash(document_path, algo)["value"]

    if actual_hash != expected_hash:
        console.print("[bold red]✘ Hash mismatch[/bold red]")
        return False

    console.print("[green]✔ Hash matches[/green]")

    table = Table(title="Verification result")
    table.add_column("Verifier")
    table.add_column("VC endpoint")
    table.add_column("Status")

    all_ok = True

    for vc_name in verifiers:
        log.info(f"Resolving VC via AC: {vc_name}")

        try:
            vc_resp = requests.get(
                f"{ac_url}/api/v1/vc/{vc_name}",
                timeout=ac_timeout,
            )

            if vc_resp.status_code == 404:
                table.add_row(
                    vc_name,
                    "-",
                    "[bold red]VC DOESN'T EXIST[/bold red]",
                )
                all_ok = False
                continue

            if vc_resp.status_code != 200:
                table.add_row(
                    vc_name,
                    "-",
                    "[red]AC ERROR[/red]",
                )
                all_ok = False
                continue

            vc = vc_resp.json()

            if ac_pub_key_b64:
                signature_b64 = vc.get("ac_signature_b64")
                if not verify_ac_signature(
                    public_key_pem_b64=ac_pub_key_b64,
                    signature_b64=signature_b64,
                    name=vc.get("name"),
                    fingerprint=vc.get("key_fingerprint"),
                    valid_from=vc.get("valid_from"),
                    valid_to=vc.get("valid_to"),
                ):
                    console.print("[bold red]AC Signature is not correct[/bold red]")
                    console.print("If you sure that AC is not compromised update public key in config")
                    return False


            if vc.get("revoked"):
                table.add_row(
                    vc_name,
                    "-",
                    "[bold red]VC REVOKED[/bold red]",
                )
                all_ok = False
                continue

            endpoint = vc.get("endpoint")
            if not endpoint:
                raise RuntimeError("VC endpoint missing")

            nonce = secrets.token_hex(16)

            challenge_resp = requests.post(
                f"{endpoint}/api/v1/challenge",
                json={
                    "document_hash": actual_hash,
                    "hash_algo": algo,
                    "nonce": nonce,
                },
                timeout=vc_timeout,
            )

            status = challenge_resp.status_code

            if status == 404:
                table.add_row(
                    vc_name,
                    endpoint,
                    "[red]NOT CONFIRMED[/red]",
                )
                all_ok = False
                continue

            if status == 410:
                table.add_row(
                    vc_name,
                    endpoint,
                    "[bold red]REVOKED[/bold red]",
                )
                all_ok = False
                continue

            if status != 200:
                raise RuntimeError(f"Unexpected VC status {status}")

            payload = challenge_resp.json()

            signature_ok = verify_vc_signature(
                public_key_pem_b64=vc["public_key_b64"],
                signature_b64=payload["response"],
                nonce=nonce,
                document_hash=actual_hash,
                hash_algo=algo
            )

            if not signature_ok:
                table.add_row(
                    vc_name,
                    endpoint,
                    "[bold red]INVALID SIGNATURE[/bold red]",
                )
                all_ok = False
                continue

            table.add_row(
                vc_name,
                endpoint,
                "[green]CONFIRMED[/green]",
            )


        except Exception as e:
            log.error(f"Verification failed for {vc_name}: {e}")
            table.add_row(
                vc_name,
                "-",
                "[red]FAILED[/red]",
            )
            all_ok = False

    console.print(table)

    if all_ok:
        console.print("\n[bold green]✔ DOCUMENT VERIFIED[/bold green]")
    else:
        console.print("\n[bold red]✘ VERIFICATION FAILED[/bold red]")

    return all_ok
