"""Логирование zapret-easy в XDG data-каталог."""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import TracebackType


APP_NAME = "zapret-easy"
_XDG_DATA_HOME = Path(
    os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")
).expanduser()
APP_DATA_DIR = _XDG_DATA_HOME / APP_NAME
LOG_FILE = APP_DATA_DIR / "app.log"

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging() -> logging.Logger:
    """Настраивает файловый лог с ротацией и возвращает общий logger.

    Если каталог данных недоступен, приложение не падает: сообщения уходят
    в stderr, а TUI продолжает работать.
    """
    logger = logging.getLogger(APP_NAME)
    if logger.handlers:
        return logger

    logger.setLevel(
        logging.DEBUG if os.environ.get("ZAPRET_EASY_DEBUG") else logging.INFO
    )
    logger.propagate = False
    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    try:
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=1_048_576,
            backupCount=3,
            encoding="utf-8",
        )
    except OSError as exc:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(logging.WARNING)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.warning("Не удалось открыть %s: %s", LOG_FILE, exc)
        return logger

    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def install_exception_hook(logger: logging.Logger) -> None:
    """Пишет необработанные исключения в лог, не скрывая traceback от TUI."""

    def _hook(
        exc_type: type[BaseException],
        exc_value: BaseException,
        exc_traceback: TracebackType | None,
    ) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        logger.critical(
            "Необработанное исключение",
            exc_info=(exc_type, exc_value, exc_traceback),
        )
        sys.__excepthook__(exc_type, exc_value, exc_traceback)

    sys.excepthook = _hook
