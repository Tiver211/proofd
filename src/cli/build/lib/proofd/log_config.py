import logging
from rich.logging import RichHandler
from rich.console import Console

console = Console()

def setup_logging(debug: bool = False, quiet: bool = False, no_color: bool = False):
    """
    Configure global logging for proofd
    """
    level = logging.INFO

    if quiet:
        level = logging.ERROR
    elif debug:
        level = logging.DEBUG

    handlers = [
        RichHandler(
            console=console,
            show_time=True,
            show_level=True,
            show_path=debug,
            rich_tracebacks=True
        )
    ]

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
    )

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    log = logging.getLogger("proofd")
    log.debug("Logging initialized")
    log.debug(f"debug={debug}, quiet={quiet}, no_color={no_color}")

    return log
