import sys
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .format import (
    load_verify,
    save_verify,
    create_verify,
    validate_verify,
    VerifyFormatError,
)

from .constraints import FORMAT_VERSION, SUPPORTED_HASHES

from .logging import setup_logging
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


pass_ctx = click.make_pass_decorator(Ctx, ensure=True)

# ==========
# ROOT COMMAND
# ==========
@click.group(
    context_settings=dict(help_option_names=["-h", "--help"])
)
@click.option("-d", "--debug", is_flag=True, help="Enable debug output")
@click.option("-q", "--quiet", is_flag=True, help="Suppress non-critical output")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.version_option("0.1.0", "-v", "--version", prog_name="proofd")
@pass_ctx
def app(ctx: Ctx, debug: bool, quiet: bool, no_color: bool):
    """
    proofd — distributed proof verification CLI
    """
    ctx.debug = debug
    ctx.quiet = quiet
    ctx.no_color = no_color

    log = setup_logging(
        debug=debug,
        quiet=quiet,
        no_color=no_color
    )

    log.debug("proofd CLI started")


# ==========
# INIT
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
def init(ctx: Ctx, file, alg, out, force, verifiers):
    """Initialize .verify file for document"""
    log = logging.getLogger("proofd.cli.init")

    file_path = Path(file)
    verify_path = Path(out) if out else file_path.with_suffix(file_path.suffix + ".verify")

    log.info("Initializing proof file")
    log.debug(f"Input file: {file_path}")
    log.debug(f"Output verify file: {verify_path}")
    log.debug(f"Initial verifiers: {list(verifiers)}")

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
        f"[bold green]✔ Proof initialized[/bold green]\n"
        f"File: {file_path}\n"
        f"Verify: {verify_path}\n"
        f"Verifiers: {', '.join(verifiers) if verifiers else '—'}",
        title="proofd init"
    ))


# ==========
# VERIFY
# ==========
@app.command()
@click.argument("file", type=click.Path(exists=True))
@click.argument("verify_file", type=click.Path(exists=True))
@click.option("--strict", is_flag=True, help="Fail on any mismatch")
@click.option("--show-hash", is_flag=True, help="Show calculated hash")
@click.option("--explain", is_flag=True, help="Verbose explanation")
@pass_ctx
def verify(ctx: Ctx, file, verify_file, strict, show_hash, explain):
    """Verify document against .verify"""
    console.print(Panel.fit(
        f"[bold cyan]Verifying document[/bold cyan]\n"
        f"File: {file}\n"
        f"Proof: {verify_file}",
        title="proofd verify"
    ))
    console.print("[green]✔ VALID (mock)[/green]")


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
