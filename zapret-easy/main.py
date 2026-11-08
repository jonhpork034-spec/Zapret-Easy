#!/usr/bin/env python3
"""zapret-easy: лёгкий TUI для управления обходом DPI через zapret2/nfqws2."""

from __future__ import annotations

import sys

from src.logger import install_exception_hook, setup_logging
from src.ui import run_ui


def main() -> int:
    """Запускает приложение и настраивает аварийное логирование."""
    logger = setup_logging()
    install_exception_hook(logger)
    logger.info("Запуск zapret-easy")
    return run_ui()


if __name__ == "__main__":
    sys.exit(main())
