import logging
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import click
import requests
import tomli_w
from rich.console import Console
from rich.panel import Panel

from proofd.crypto import calc_fingerprint

CONFIG_PATH = Path.home() / ".config" / "proofd" / "config.toml"

console = Console()

@dataclass()
class AC:
    endpoint: str
    public_key_b64: str

@dataclass()
class VC:
    id: str
    endpoint: str
    public_key_b64: str

@dataclass()
class Timeouts:
    ac_request_timeout: int = 3000
    vc_request_timeout: int = 3000

@dataclass()
class Config:
    ac: Optional[AC]
    trusted_vc: list[VC]
    timeouts: Timeouts

    @classmethod
    def default(cls) -> "Config":
        return cls(
            ac=None,
            trusted_vc=[],
            timeouts=Timeouts(),
        )

    @classmethod
    def load_from_toml(cls, toml_path: Path) -> "Config":
        logger = logging.getLogger("proofd.config")
        logger.debug(f"Loading config from toml: {toml_path}")
        if not toml_path.exists():
            logger.warning(f"toml file {toml_path} does not exist, using default config")
            return cls.default()

        data = tomllib.loads(toml_path.read_text())

        # ---- AC ----
        ac: Optional[AC] = None
        if "ac" in data:
            ac_data = data["ac"]
            ac = AC(
                endpoint=ac_data["endpoint"],
                public_key_b64=ac_data.get("public_key_b64"),
            )

        # ---- trusted VC ----
        trusted_vc: list[VC] = []
        if "trusted_vc" in data:
            trusted_vc = [
                VC(
                    id=vc["id"],
                    endpoint=vc["endpoint"],
                    public_key_b64=vc["public_key_b64"],
                )
                for vc in data["trusted_vc"]
            ]

        # ---- timeouts ----
        timeouts_data = data.get("timeouts", {})
        timeouts = Timeouts(
            ac_request_timeout=timeouts_data.get("ac_request_timeout", 3000),
            vc_request_timeout=timeouts_data.get("vc_request_timeout", 3000),
        )

        return cls(
            ac=ac,
            trusted_vc=trusted_vc,
            timeouts=timeouts,
        )

    def write_config(self, path: Path):
        data = {}

        if self.ac:
            data["ac"] = {
                "endpoint": self.ac.endpoint,
                "public_key_b64": self.ac.public_key_b64,
            }

        if self.trusted_vc:
            data["trusted_vc"] = [
                {
                    "id": vc.id,
                    "endpoint": vc.endpoint,
                    "public_key_b64": vc.public_key_b64,
                }
                for vc in self.trusted_vc
            ]

        data["timeouts"] = {
            "ac_request_timeout": self.timeouts.ac_request_timeout,
            "vc_request_timeout": self.timeouts.vc_request_timeout,
        }

        path.write_text(tomli_w.dumps(data))

def fetch_ac_public_key(endpoint: str) -> str:
    with console.status(
            "[cyan]Fetching AC public key...[/cyan]",
            spinner="dots"
    ):
        url = endpoint.rstrip("/") + "/api/v1/ac/public-key"

        resp = requests.get(url, timeout=3)
        resp.raise_for_status()

        data = resp.json()
        if "public_key_b64" not in data:
            raise ValueError("Invalid AC response")

        pub = data["public_key_b64"]
        fp = calc_fingerprint(pub)

    console.print(Panel.fit(
        f"[bold]AC public key fingerprint[/bold]\n\n"
        f"[cyan]{fp}[/cyan]",
        title="Security check",
        border_style="yellow"
    ))

    if not click.confirm("Do you trust this AC key?", default=False):
        raise click.Abort()

    return pub
