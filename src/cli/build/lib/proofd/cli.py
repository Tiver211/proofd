import sys
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import Config, Timeouts, AC, CONFIG_PATH, fetch_ac_public_key
from .config import CONFIG_PATH as DEFAULT_CONFIG_PATH
from .format import (
    load_verify,
    save_verify,
    create_verify,
    validate_verify,
    VerifyFormatError,
)

from .constraints import FORMAT_VERSION, SUPPORTED_HASHES
from .verify import verify_document
from .log_config import setup_logging
from .hashing import calc_hash
import logging
from pathlib import Path

console = Console()

# ==========
# GLOBAL STATE
# ==========
class Ctx:
    debug: bool = False
    quiet: bool = False
    no_color: bool = False
    config: Config = None


pass_ctx = click.make_pass_decorator(Ctx, ensure=True)

# ==========
# ROOT COMMAND
# ==========
@click.group(
    context_settings=dict(help_option_names=["-h", "--help"])
)
@click.option("-d", "--debug", is_flag=True, help="Enable debug output")
@click.option("-q", "--quiet", is_flag=True, help="Suppress non-critical output")
@click.option("--config_path", "-c", help="Path to config file", type=click.Path(exists=True))
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.version_option("0.1.0", "-v", "--version", prog_name="proofd")
@pass_ctx
def app(ctx: Ctx, debug: bool, quiet: bool, config_path: str, no_color: bool):
    """
    proofd — distributed proof verification CLI
    """
    ctx.debug = debug
    ctx.quiet = quiet
    ctx.no_color = no_color

    ctx.config = Config.load_from_toml(config_path or DEFAULT_CONFIG_PATH)

    log = setup_logging(
        debug=debug,
        quiet=quiet,
        no_color=no_color
    )

    log.debug("proofd CLI started")


@app.command()
@click.option("-c", "--clear", is_flag=True, help="initialization with empty config")
@pass_ctx
def init(ctx: Ctx, clear: bool):
    """Creating user config file"""

    config_path = CONFIG_PATH
    config_path.parent.mkdir(parents=True, exist_ok=True)

    console.print(Panel.fit(
        "[bold cyan]proofd interactive init[/bold cyan]\n"
        "This wizard will create a local user configuration",
        title="init",
        border_style="cyan"
    ))

    # --- clear / default ---
    if clear:
        config = Config.default()
        config.write_config(config_path)

        console.print(Panel.fit(
            f"[bold green]✔ Configuration reset[/bold green]\n"
            f"Path: {config_path}",
            title="init",
            border_style="green"
        ))
        return

    # --- AC ---
    ac = None
    console.print("\n[bold]Authority Center (AC)[/bold]")

    if click.confirm("Configure AC?", default=True):
        endpoint = click.prompt(
            "AC endpoint",
            default="https://localhost:8443",
            show_default=True,
        )


        try:
            public_key_b64 = fetch_ac_public_key(endpoint)
        except Exception as e:
            console.print(
                f"[bold red]✘ Failed to fetch AC public key[/bold red]\n{e}"
            )
            raise click.Abort()

        console.print("[green]✔ AC public key fetched[/green]")

        ac = AC(
            endpoint=endpoint,
            public_key_b64=public_key_b64,
        )
    else:
        console.print(
            "[yellow]⚠ AC not configured[/yellow]\n"
            "AC endpoint and public key must be provided via CLI flags"
        )

    # --- trusted VC ---
    console.print("\n[bold]Verification Centers (VC)[/bold]")
    console.print(
        "[yellow]Trusted VC list is empty by default[/yellow]\n"
        "You can add trusted VC manually to config later"
    )

    # --- timeouts ---
    console.print("\n[bold]Timeouts[/bold]")
    timeouts = Timeouts()
    console.print(
        f"AC request timeout: {timeouts.ac_request_timeout} ms\n"
        f"VC request timeout: {timeouts.vc_request_timeout} ms"
    )

    # --- summary ---
    table = Table(title="Configuration summary", show_header=True)
    table.add_column("Section", style="cyan")
    table.add_column("Value", style="white")

    table.add_row(
        "AC",
        ac.endpoint if ac else "—"
    )
    table.add_row(
        "Trusted VC",
        "0"
    )
    table.add_row(
        "Timeouts",
        f"AC={timeouts.ac_request_timeout}ms, VC={timeouts.vc_request_timeout}ms"
    )

    console.print("\n")
    console.print(table)

    # --- write config ---
    config = Config(
        ac=ac,
        trusted_vc=[],
        timeouts=timeouts,
    )

    config.write_config(config_path)

    console.print(Panel.fit(
        f"[bold green]✔ Configuration written successfully[/bold green]\n"
        f"Path: {config_path}",
        title="init complete",
        border_style="green"
    ))



# ==========
# CREATE
# ==========
@app.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("-a", "--alg", default="sha256", show_default=True)
@click.option("-o", "--out", type=click.Path())
@click.option("-f", "--force", is_flag=True)
@click.option(
    "-V", "--verifier",
    "verifiers",
    multiple=True,
    help="Add verifier ID (can be used multiple times)"
)
@pass_ctx
def create(ctx: Ctx, file, alg, out, force, verifiers):
    """Create .verify file for document"""
    log = logging.getLogger("proofd.cli.create")

    file_path = Path(file)
    verify_path = Path(out) if out else file_path.with_suffix(file_path.suffix + ".verify")

    log.info("Creating proof file")
    log.debug(f"Input file: {file_path}")
    log.debug(f"Output verify file: {verify_path}")
    log.debug(f"Adding verifiers: {list(verifiers)}")

    try:
        hash_info = calc_hash(file_path, algorithm=alg)
        data = create_verify(
            hash_info=hash_info,
            verifiers=list(verifiers),
        )
        save_verify(verify_path, data, force=force)
    except Exception as e:
        log.error(str(e))
        raise click.Abort()

    console.print(Panel.fit(
        f"[bold green]✔ Proof file created[/bold green]\n"
        f"File: {file_path}\n"
        f"Verify: {verify_path}\n"
        f"Verifiers: {', '.join(verifiers) if verifiers else '—'}",
        title="proofd create"
    ))


@app.command()
@click.argument("document", type=click.Path(exists=True, dir_okay=False))
@click.argument("verify_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--ac", "ac_endpoint", help="Authority Center base URL")
@click.option("--timeout-ac", "ac_timeout", default=None, show_default=True)
@click.option("--timeout-vc", "vc_timeout", default=None, show_default=True)
@click.option("--ignore-ac-public", is_flag=True, default=False, show_default=True)
@click.option("--ac-public-key-b64", default=None, show_default=True)
@pass_ctx
def verify(ctx: Ctx, document, verify_file, ac_endpoint, ac_timeout, vc_timeout, ignore_ac_public, ac_public_key_b64):
    """
    Verify document using AC-resolved Verification Centers
    """
    log = logging.getLogger("proofd.cli.verify")

    config = ctx.config
    if not ac_endpoint:
        if not config.ac:
            log.error("AC endpoint not set")
            return
        ac_endpoint = config.ac.endpoint
        if not ac_endpoint:
            log.error("AC endpoint not set")
            return

    if not vc_timeout:
        vc_timeout = config.timeouts.vc_request_timeout
        if not vc_timeout:
            log.error("VC timeout not set nowhere")
            return

    if not ac_timeout:
        ac_timeout = config.timeouts.ac_request_timeout
        if not ac_timeout:
            log.error("AC timeout not set nowhere")
            return

    if not ac_public_key_b64 and config.ac:
        ac_public_key_b64 = config.ac.public_key_b64

    if ignore_ac_public:
        ac_public_key_b64 = None

    elif not ac_public_key_b64:
        log.error("AC public key requested, but doesn't specified")
        return

    verify_document(
        document_path=document,
        verify_path=verify_file,
        ac_url=ac_endpoint,
        ac_timeout=ac_timeout,
        vc_timeout=vc_timeout,
        ac_pub_key_b64=ac_public_key_b64
    )



# ==========
# INSPECT
# ==========
@app.command()
@click.argument("verify_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--raw", is_flag=True)
@click.option("--schema", is_flag=True)
@pass_ctx
def inspect(ctx: Ctx, verify_file, raw, schema):
    """Inspect .verify file"""
    log = logging.getLogger("proofd.cli.inspect")

    try:
        data = load_verify(verify_file)
        validate_verify(data)
    except VerifyFormatError as e:
        log.error(str(e))
        raise click.Abort()

    if raw:
        console.print_json(data)
        return

    table = Table(title="Proof file contents", show_header=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("version", data["version"])
    table.add_row("hash.algorithm", data["hash"]["algorithm"])
    table.add_row("hash.value", data["hash"]["value"])
    table.add_row("verifiers", ", ".join(data["verifiers"]) or "—")

    console.print(table)

    if schema:
        console.print(Panel.fit(
            "Fields:\n"
            "- version: string\n"
            "- hash.algorithm: string\n"
            "- hash.value: string\n"
            "- verifiers: string[]",
            title="proofd schema"
        ))


# ==========
# VALIDATE
# ==========
@app.command()
@click.argument("verify_file", type=click.Path(exists=True, dir_okay=False))
@pass_ctx
def validate(ctx: Ctx, verify_file):
    """Validate .verify structure"""
    log = logging.getLogger("proofd.cli.validate")

    try:
        data = load_verify(verify_file)
        validate_verify(data)
    except VerifyFormatError as e:
        log.error(str(e))
        console.print("[bold red]✘ Invalid verify file[/bold red]")
        raise click.Abort()

    console.print("[bold green]✔ Verify file is valid[/bold green]")

# ==========
# HASH
# ==========
@app.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("-a", "--alg", default="sha256", show_default=True, help="Hash algorithm")
@click.option("--short", is_flag=True, help="Short output")
@pass_ctx
def hash(ctx: Ctx, file, alg, short):
    """Calculate file hash"""
    log = logging.getLogger("proofd.cli.hash")

    log.info("Starting hash calculation")
    log.debug(f"Input file: {file}")
    log.debug(f"Algorithm: {alg}")

    try:
        result = calc_hash(file, algorithm=alg)
    except Exception as e:
        log.error(f"Hash calculation failed: {e}")
        raise click.Abort()

    value = result["value"]

    if short:
        console.print(value[:8])
        log.debug("Printed short hash")
    else:
        console.print(f"[bold cyan]{result['algorithm']}[/bold cyan]: {value}")
        log.debug("Printed full hash")

    log.info("Hash command completed successfully")



# ==========
# VERIFIER GROUP
# ==========
@app.group()
def verifier():
    """Manage verifiers"""
    pass


@verifier.command("add")
@click.argument("verify_file", type=click.Path(exists=True, dir_okay=False))
@click.argument("verifier_id")
@click.option("-f", "--force", is_flag=True)
@pass_ctx
def verifier_add(ctx: Ctx, verify_file, verifier_id, force):
    log = logging.getLogger("proofd.cli.verifier.add")
    path = Path(verify_file)

    log.info(f"Adding verifier: {verifier_id}")

    data = load_verify(path)
    verifiers = set(data.get("verifiers", []))

    if verifier_id in verifiers and not force:
        log.warning("Verifier already exists")
        console.print("[yellow]Verifier already exists (use --force to ignore)[/yellow]")
        return

    verifiers.add(verifier_id)
    data["verifiers"] = sorted(verifiers)

    save_verify(path, data, force=True)

    console.print(f"[green]✔ Verifier added:[/green] {verifier_id}")


@verifier.command("remove")
@click.argument("verify_file", type=click.Path(exists=True, dir_okay=False))
@click.argument("verifier_id")
@pass_ctx
def verifier_remove(ctx: Ctx, verify_file, verifier_id):
    log = logging.getLogger("proofd.cli.verifier.remove")
    path = Path(verify_file)

    log.info(f"Removing verifier: {verifier_id}")

    data = load_verify(path)
    verifiers = set(data.get("verifiers", []))

    if verifier_id not in verifiers:
        log.warning("Verifier not found")
        console.print("[red]Verifier not found[/red]")
        return

    verifiers.remove(verifier_id)
    data["verifiers"] = sorted(verifiers)

    save_verify(path, data, force=True)

    console.print(f"[green]✔ Verifier removed:[/green] {verifier_id}")


@verifier.command("list")
@click.argument("verify_file", type=click.Path(exists=True, dir_okay=False))
@pass_ctx
def verifier_list(ctx: Ctx, verify_file):
    log = logging.getLogger("proofd.cli.verifier.list")
    path = Path(verify_file)

    log.info("Listing verifiers")
    data = load_verify(path)

    verifiers = data.get("verifiers", [])

    if not verifiers:
        console.print("[yellow]No verifiers defined[/yellow]")
        return

    console.print(Panel(
        "\n".join(f"• {v}" for v in verifiers),
        title="Verifiers",
        border_style="cyan"
    ))


# ==========
# FORMAT GROUP
# ==========
@app.group()
def format():
    """Format operations"""
    pass


@format.command("info")
def format_info():
    console.print(Panel.fit(
        f"Format version: {FORMAT_VERSION}\n"
        f"Supported hashes: {', '.join(SUPPORTED_HASHES)}",
        title="proofd format info"
    ))


@format.command("upgrade")
@click.argument("verify_file", type=click.Path(exists=True, dir_okay=False))
@click.option("-f", "--force", is_flag=True)
def format_upgrade(verify_file, force):
    log = logging.getLogger("proofd.cli.format.upgrade")

    try:
        data = load_verify(verify_file)
        validate_verify(data)
    except VerifyFormatError as e:
        log.error(str(e))
        raise click.Abort()

    console.print(Panel.fit(
        "No upgrade required.\n"
        "Current format is up to date.",
        title="proofd format upgrade"
    ))


# ==========
# DOCTOR
# ==========
@app.command()
def doctor():
    """Environment diagnostics"""
    console.print(Panel.fit(
        f"Python: {sys.version.split()[0]}\n"
        f"proofd: 0.1.0\n"
        f"Colors: {'enabled' if not console.no_color else 'disabled'}",
        title="proofd doctor"
    ))


if __name__ == "__main__":
    app()
