"""Менеджер Lua-стратегий zapret2 и активного профиля."""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

from src.logger import APP_DATA_DIR

logger = logging.getLogger("zapret-easy")

PROJECT_ROOT: Final = Path(__file__).resolve().parent.parent
DEFAULT_STRATEGIES_DIR: Final = PROJECT_ROOT / "strategies"
DEFAULT_CONFIG_FILE: Final = APP_DATA_DIR / "config.json"
MAX_STRATEGY_SIZE: Final = 1024 * 1024
MAX_PROFILE_ARGS: Final = 2048
CONFIG_VERSION: Final = 1
LUAJIT_TIMEOUT: Final = 3.0
COMMUNITY_TIMEOUT: Final = 20.0
COMMUNITY_MAX_FILE: Final = 2 * 1024 * 1024
COMMUNITY_MAX_LIST: Final = 512 * 1024
COMMUNITY_MAX_STRATEGIES: Final = 24
COMMUNITY_MAX_HOSTS: Final = 300
COMMUNITY_PREFIX: Final = "community-"
_COMMUNITY_HOST_RE: Final = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z][a-z0-9-]{0,62}$"
)
_COMMUNITY_STEP_RE: Final = re.compile(
    r"^--lua-desync=[a-z][a-z0-9_]{0,40}"
    r"(:[A-Za-z0-9_.,=+%-]{1,200}){0,40}$"
)
_COMMUNITY_ZEMIDALA_BLOBS: Final = {
    "stun_fake": "/opt/zapret2/files/fake/stun.bin",
    "stun2_fake": "/opt/zapret2/files/fake/stun.bin",
    "tls_clienthello": (
        "/opt/zapret2/files/fake/tls_clienthello_www_google_com.bin"
    ),
}
# Блобы, которые zapret2 предоставляет стандартной библиотекой.
_COMMUNITY_BUILTIN_BLOBS: Final = {"fake_default_tls", "fake_default_http"}

# Эти параметры управляют самим процессом nfqws2, а не стратегией.
# Тестер выставляет их сам, поэтому в профиле они запрещены.
_PROFILE_CONTROL_OPTIONS: Final = (
    "--qnum",
    "--user",
    "--uid",
    "--daemon",
    "--pidfile",
    "--fwmark",
    "--dry-run",
    "--intercept",
    "--chdir",
    "--writable",
    "--debug",
)

_PROFILE_WRAPPER_RE: Final = re.compile(
    r'^\s*(?:NFQWS_ARGS_CUSTOM|NFQWS2_OPT|NFQWS_OPT)\s*=\s*'
    r'(["\'])(.*)\1\s*$',
    re.DOTALL,
)


class StrategyError(Exception):
    """Ошибка выбора или сохранения стратегии."""


@dataclass(frozen=True, slots=True)
class StrategyProfile:
    """Аргументы nfqws2 из sidecar-файла <name>.conf."""

    path: Path
    present: bool
    args: tuple[str, ...]
    placeholder: bool
    error: str | None = None

    @property
    def valid(self) -> bool:
        return self.error is None

    @property
    def runnable(self) -> bool:
        return self.valid and bool(self.args)


@dataclass(frozen=True, slots=True)
class Strategy:
    """Одна Lua-стратегия и её профиль аргументов nfqws2."""

    name: str
    path: Path
    size: int
    placeholder: bool
    profile: StrategyProfile
    error: str | None = None

    @property
    def valid(self) -> bool:
        return self.error is None

    @property
    def ready(self) -> bool:
        return self.valid and self.profile.runnable

    @property
    def size_label(self) -> str:
        if self.size < 1024:
            return f"{self.size} Б"
        if self.size < 1024 * 1024:
            return f"{self.size / 1024:.1f} КиБ"
        return f"{self.size / (1024 * 1024):.1f} МиБ"


@dataclass(frozen=True, slots=True)
class StrategyValidation:
    """Результат полной проверки выбранной стратегии."""

    valid: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    syntax_checked: bool


@dataclass(frozen=True, slots=True)
class CommunitySource:
    """Описание источника готовых стратегий."""

    key: str
    name: str
    url: str
    description: str
    supported: bool = True


@dataclass(frozen=True, slots=True)
class CommunityImportResult:
    """Итог импорта community-стратегий.

    ``skipped`` содержит объяснения, почему конкретный профиль не был
    добавлен.  ``errors`` — сетевые ошибки или ошибки записи.  Ни один
    скачанный файл не выполняется; всё проверяется StrategyManager.
    """

    imported: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def total_imported(self) -> int:
        return len(self.imported)

    @property
    def ok(self) -> bool:
        return bool(self.imported) and not self.errors


COMMUNITY_SOURCES: Final = (
    CommunitySource(
        key="senshu",
        name="YouTube + Discord (nfqws2)",
        url="https://github.com/senshu-dev/nfqws2-linux-youtube-discord",
        description=(
            "Готовый nfqws2-профиль и hostlist; "
            "без Flowseal winws.exe"
        ),
    ),
    CommunitySource(
        key="nzapret",
        name="nzapret: default profile",
        url="https://github.com/nikitos4683/nzapret",
        description=(
            "Готовый .conf nfqws2; Android-пути нормализуются, "
            "списки сохраняются в strategies/"
        ),
    ),
    CommunitySource(
        key="zemidala",
        name="nfqws2-strategies (ASN)",
        url="https://github.com/zemidala/nfqws2-strategies",
        description=(
            "Стратегии сообщества по провайдерам; импортируются только "
            "безопасные --lua-desync с известными блобами"
        ),
    ),
    CommunitySource(
        key="flowseal",
        name="Flowseal: Windows winws",
        url="https://github.com/Flowseal/zapret-discord-youtube",
        description=(
            "Windows .bat и winws.exe. Автоматически в nfqws2 "
            "не конвертируется; исходник оставлен справочно"
        ),
        supported=False,
    ),
)


def _looks_like_placeholder(data: bytes) -> bool:
    """Пустой файл или файл только из Lua-комментариев — заглушка."""
    if not data.strip():
        return True
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("--"):
            return False
    return True


def _safe_strategy_name(name: str) -> bool:
    if not name or Path(name).name != name:
        return False
    if not name.lower().endswith(".lua") or name.startswith("."):
        return False
    return not any(ord(char) < 32 for char in name)


def _profile_error(path: Path, message: str) -> StrategyProfile:
    return StrategyProfile(
        path=path,
        present=path.is_file(),
        args=(),
        placeholder=False,
        error=message,
    )


def _inspect_profile(lua_path: Path) -> StrategyProfile:
    """Читает <name>.conf как набор аргументов nfqws2.

    Строки, начинающиеся с #, игнорируются. Аргументы разделяются
    пробелами и переводами строк, как в командной строке; кавычки
    поддерживаются, но оболочка не используется.
    """
    profile_path = lua_path.with_suffix(".conf")
    if not profile_path.exists():
        return StrategyProfile(
            path=profile_path,
            present=False,
            args=(),
            placeholder=True,
        )
    if not profile_path.is_file():
        return _profile_error(profile_path, "Профиль не является обычным файлом.")

    try:
        stat = profile_path.stat()
    except OSError as exc:
        return _profile_error(
            profile_path,
            f"Не удалось прочитать профиль: {exc}",
        )
    if stat.st_size > MAX_STRATEGY_SIZE:
        return _profile_error(
            profile_path,
            f"Профиль больше {MAX_STRATEGY_SIZE // 1024} КиБ.",
        )

    try:
        raw = profile_path.read_bytes()
    except OSError as exc:
        return _profile_error(
            profile_path,
            f"Не удалось прочитать профиль: {exc}",
        )
    if b"\x00" in raw:
        return _profile_error(profile_path, "Профиль содержит NUL-байты.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        return _profile_error(
            profile_path,
            f"Профиль не является UTF-8-текстом: {exc}",
        )

    # Некоторые наборы Flowseal распространяются как
    # "NFQWS_ARGS_CUSTOM=\"...\"". Оболочку не запускаем, только извлекаем
    # строку аргументов и разбираем её тем же безопасным shlex.
    without_comments = "\n".join(
        line
        for line in text.splitlines()
        if not line.lstrip().startswith("#")
    ).strip()
    wrapper = _PROFILE_WRAPPER_RE.match(without_comments)
    if wrapper is not None:
        text = wrapper.group(2)

    try:
        parsed = shlex.split(text, comments=True, posix=True)
    except ValueError as exc:
        return _profile_error(
            profile_path,
            f"Не удалось разобрать аргументы: {exc}",
        )

    if len(parsed) > MAX_PROFILE_ARGS:
        return _profile_error(
            profile_path,
            f"В профиле больше {MAX_PROFILE_ARGS} аргументов.",
        )

    for arg in parsed:
        if not arg.startswith("--"):
            return _profile_error(
                profile_path,
                f"Аргумент «{arg}» должен начинаться с --.",
            )
        option = arg.split("=", 1)[0].split(":", 1)[0]
        if option in _PROFILE_CONTROL_OPTIONS:
            return _profile_error(
                profile_path,
                f"Параметр {option} задаётся тестером и запрещён в профиле.",
            )

    return StrategyProfile(
        path=profile_path,
        present=True,
        args=tuple(parsed),
        placeholder=not parsed,
    )


class StrategyManager:
    """Сканирует strategies/, проверяет файлы и хранит активный выбор."""

    def __init__(
        self,
        strategies_dir: Path | str | None = None,
        config_file: Path | str | None = None,
    ) -> None:
        env_dir = os.environ.get("ZAPRET_EASY_STRATEGIES_DIR")
        env_config = os.environ.get("ZAPRET_EASY_CONFIG")
        self.strategies_dir = Path(
            strategies_dir or env_dir or DEFAULT_STRATEGIES_DIR
        ).expanduser().resolve()
        self.config_file = Path(
            config_file or env_config or DEFAULT_CONFIG_FILE
        ).expanduser().resolve()
        self._validation_cache: dict[
            tuple[object, ...], StrategyValidation
        ] = {}

    def list_strategies(self) -> list[Strategy]:
        """Возвращает файлы *.lua, отсортированные по имени."""
        if not self.strategies_dir.is_dir():
            logger.warning("Каталог стратегий не найден: %s", self.strategies_dir)
            return []

        strategies: list[Strategy] = []
        for path in sorted(
            self.strategies_dir.iterdir(), key=lambda item: item.name.casefold()
        ):
            if not _safe_strategy_name(path.name) or not path.is_file():
                continue
            strategies.append(self._inspect(path))
        return strategies

    def get(self, name: str) -> Strategy | None:
        """Возвращает стратегию по имени, не выходя за пределы каталога."""
        if not _safe_strategy_name(name):
            return None
        path = self.strategies_dir / name
        if not path.is_file():
            return None
        return self._inspect(path)

    def _inspect(self, path: Path) -> Strategy:
        profile = _inspect_profile(path)
        try:
            stat = path.stat()
        except OSError as exc:
            return Strategy(
                name=path.name,
                path=path,
                size=0,
                placeholder=False,
                profile=profile,
                error=f"Не удалось прочитать файл: {exc}",
            )

        if stat.st_size > MAX_STRATEGY_SIZE:
            return Strategy(
                name=path.name,
                path=path,
                size=stat.st_size,
                placeholder=False,
                profile=profile,
                error=f"Файл больше {MAX_STRATEGY_SIZE // 1024} КиБ",
            )

        try:
            data = path.read_bytes()
        except OSError as exc:
            return Strategy(
                name=path.name,
                path=path,
                size=stat.st_size,
                placeholder=False,
                profile=profile,
                error=f"Не удалось прочитать файл: {exc}",
            )

        if b"\x00" in data:
            return Strategy(
                name=path.name,
                path=path,
                size=stat.st_size,
                placeholder=False,
                profile=profile,
                error="Файл содержит NUL-байты и не похож на Lua-текст",
            )

        return Strategy(
            name=path.name,
            path=path,
            size=stat.st_size,
            placeholder=_looks_like_placeholder(data),
            profile=profile,
        )

    def validate(self, strategy: Strategy) -> StrategyValidation:
        """Проверяет Lua-файл и sidecar-профиль аргументов nfqws2."""
        errors: list[str] = []
        warnings: list[str] = []
        syntax_checked = False

        if strategy.error:
            return StrategyValidation(
                valid=False,
                errors=(strategy.error,),
                warnings=(),
                syntax_checked=False,
            )

        if strategy.profile.error:
            errors.append(
                f"Профиль {strategy.profile.path.name}: "
                f"{strategy.profile.error}"
            )
        elif not strategy.profile.args:
            if strategy.profile.present:
                warnings.append(
                    "В .conf нет аргументов nfqws2: стратегию нельзя запустить."
                )
            else:
                warnings.append(
                    "Нет .conf с аргументами nfqws2: стратегию нельзя запустить."
                )

        if strategy.placeholder:
            if strategy.profile.args:
                warnings.append(
                    "Lua-файл является заглушкой; используются только "
                    "аргументы из .conf."
                )
            return StrategyValidation(
                valid=not errors,
                errors=tuple(errors),
                warnings=tuple(warnings),
                syntax_checked=False,
            )

        try:
            stat = strategy.path.stat()
        except OSError:
            cache_key: tuple[object, ...] | None = None
        else:
            profile_mtime = 0
            profile_size = 0
            if strategy.profile.present:
                try:
                    profile_stat = strategy.profile.path.stat()
                except OSError:
                    pass
                else:
                    profile_mtime = profile_stat.st_mtime_ns
                    profile_size = profile_stat.st_size
            cache_key = (
                str(strategy.path),
                stat.st_mtime_ns,
                stat.st_size,
                str(strategy.profile.path),
                profile_mtime,
                profile_size,
                strategy.profile.present,
                strategy.profile.error,
                strategy.profile.args,
            )

        if cache_key is not None and cache_key in self._validation_cache:
            return self._validation_cache[cache_key]

        luajit = shutil.which("luajit")
        if luajit is None:
            warnings.append("luajit не найден: синтаксис стратегии не проверен.")
        else:
            syntax_checked = True
            try:
                checked = subprocess.run(
                    [luajit, "-b", str(strategy.path), os.devnull],
                    capture_output=True,
                    text=True,
                    timeout=LUAJIT_TIMEOUT,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(f"Не удалось проверить синтаксис Lua: {exc}")
            else:
                if checked.returncode != 0:
                    details = (checked.stderr or checked.stdout).strip()
                    if len(details) > 500:
                        details = details[-500:]
                    errors.append(
                        "Синтаксическая ошибка Lua"
                        + (f": {details}" if details else ".")
                    )

        validation = StrategyValidation(
            valid=not errors,
            errors=tuple(errors),
            warnings=tuple(warnings),
            syntax_checked=syntax_checked,
        )
        if cache_key is not None:
            self._validation_cache[cache_key] = validation
        return validation

    def active_name(self) -> str | None:
        value = self.load_config().get("active_strategy")
        if value is None:
            return None
        if not isinstance(value, str) or not _safe_strategy_name(value):
            logger.warning("Некорректное имя активной стратегии в конфиге: %r", value)
            return None
        return value

    def active_strategy(self) -> Strategy | None:
        name = self.active_name()
        if name is None:
            return None
        strategy = self.get(name)
        if strategy is None:
            logger.warning("Активная стратегия не найдена: %s", name)
        return strategy

    def set_active(self, name: str) -> Strategy:
        """Проверяет стратегию и атомарно сохраняет её как активную."""
        strategy = self.get(name)
        if strategy is None:
            raise StrategyError(f"Стратегия не найдена: {name}")

        validation = self.validate(strategy)
        if not validation.valid:
            raise StrategyError("\n".join(validation.errors))

        for warning in validation.warnings:
            logger.warning("%s: %s", strategy.name, warning)

        config = self.load_config()
        config["version"] = CONFIG_VERSION
        config["active_strategy"] = strategy.name
        config["updated_at"] = datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        )
        self.save_config(config)
        logger.info("Активная стратегия сохранена: %s", strategy.name)
        return strategy

    def load_config(self) -> dict[str, object]:
        """Читает config.json; повреждённый файл сохраняет рядом."""
        if not self.config_file.exists():
            return {"version": CONFIG_VERSION, "active_strategy": None}

        try:
            data = json.loads(self.config_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("Не удалось прочитать %s: %s", self.config_file, exc)
            self._quarantine_config()
            return {"version": CONFIG_VERSION, "active_strategy": None}

        if not isinstance(data, dict):
            logger.warning("Конфиг %s имеет неверный формат", self.config_file)
            self._quarantine_config()
            return {"version": CONFIG_VERSION, "active_strategy": None}
        return data

    def _quarantine_config(self) -> None:
        if not self.config_file.exists():
            return
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        backup = self.config_file.with_name(
            f"{self.config_file.name}.corrupt-{stamp}"
        )
        try:
            os.replace(self.config_file, backup)
            logger.warning("Повреждённый конфиг перемещён в %s", backup)
        except OSError as exc:
            logger.error("Не удалось сохранить повреждённый конфиг: %s", exc)

    def save_config(self, config: dict[str, object]) -> None:
        """Атомарно записывает JSON с правами 0600."""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(
                prefix=f".{self.config_file.name}.",
                suffix=".tmp",
                dir=self.config_file.parent,
            )
        except OSError as exc:
            raise StrategyError(f"Не удалось подготовить конфиг: {exc}") from exc

        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(config, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, self.config_file)
        except (OSError, TypeError, ValueError) as exc:
            temp_path.unlink(missing_ok=True)
            raise StrategyError(f"Не удалось сохранить конфиг: {exc}") from exc


# ---------------------------------------------------------------------------
# Импорт community-стратегий
# ---------------------------------------------------------------------------

def _community_http_text(
    url: str,
    *,
    limit: int = COMMUNITY_MAX_FILE,
    range_end: int | None = None,
) -> str:
    """Скачивает только HTTPS-текст, без shell и без исполнения."""
    if not url.startswith("https://"):
        raise StrategyError("Разрешены только HTTPS-источники.")
    headers = {
        "User-Agent": "zapret-easy/1.0 (+https://github.com/)",
        "Accept": "text/plain, application/json, */*;q=0.1",
    }
    if range_end is not None:
        headers["Range"] = f"bytes=0-{int(range_end)}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(
            request, timeout=COMMUNITY_TIMEOUT
        ) as response:
            final_url = response.geturl()
            if not final_url.startswith("https://"):
                raise StrategyError(
                    f"Редирект на не-HTTPS URL: {final_url}"
                )
            data = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        raise StrategyError(f"HTTP {exc.code} при загрузке {url}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise StrategyError(f"Не удалось скачать {url}: {exc}") from exc

    if len(data) > limit:
        raise StrategyError(
            f"Файл {url} больше {limit // 1024} КиБ."
        )
    if b"\x00" in data:
        raise StrategyError(f"Файл {url} содержит NUL-байты.")
    try:
        # Range-запрос может обрезать файл посреди UTF-8-символа; для
        # hostlist это безопасно, потому что _community_hosts отбросит
        # повреждённую строку.  Конфиги и JSON скачиваются без Range.
        errors = "replace" if range_end is not None else "strict"
        return data.decode("utf-8-sig", errors=errors)
    except UnicodeDecodeError as exc:
        raise StrategyError(f"Файл {url} не является UTF-8-текстом.") from exc


def _community_json(url: str) -> object:
    text = _community_http_text(url)
    try:
        return json.loads(text)
    except ValueError as exc:
        raise StrategyError(f"Некорректный JSON в {url}: {exc}") from exc


def _community_hosts(text: str, *, limit: int = COMMUNITY_MAX_HOSTS) -> list[str]:
    hosts: list[str] = []
    for raw in text.splitlines():
        host = raw.strip().strip("\"'").strip().lower().rstrip(".")
        if not host or host.startswith("#") or host.startswith("^"):
            continue
        if not _COMMUNITY_HOST_RE.fullmatch(host):
            continue
        if host not in hosts:
            hosts.append(host)
        if len(hosts) >= limit:
            break
    return hosts


def _community_write_text(path: Path, text: str) -> None:
    """Создаёт новый текстовый файл, никогда не перезаписывая существующий."""
    if not text or "\x00" in text:
        raise StrategyError(f"Пустой или бинарный файл для {path.name}.")
    data = text.encode("utf-8")
    if len(data) > COMMUNITY_MAX_FILE:
        raise StrategyError(f"{path.name} больше допустимого размера.")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            stream.write(text)
            if not text.endswith("\n"):
                stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o644)
    except FileExistsError as exc:
        raise StrategyError(f"{path.name} уже существует.") from exc
    except OSError as exc:
        raise StrategyError(f"Не удалось записать {path.name}: {exc}") from exc


def _community_read_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    if len(data) > COMMUNITY_MAX_FILE or b"\x00" in data:
        return ""
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return ""


def _community_asset_path(
    destination: Path,
    stem: str,
    suffix: str,
    text: str,
) -> Path:
    """Возвращает путь для hostlist, не затирая чужие файлы."""
    for index in range(1, 32):
        name = stem if index == 1 else f"{stem}-{index}"
        path = destination / f"{name}{suffix}"
        if path.is_symlink():
            continue
        if not path.exists():
            _community_write_text(path, text)
            return path
        if _community_read_text(path) == text:
            return path
    raise StrategyError(f"Не удалось подобрать имя для {stem}{suffix}.")


def _community_placeholder(name: str) -> str:
    return (
        "-- Community profile imported by zapret-easy.\n"
        f"-- nfqws2 arguments are in {name}.conf; "
        "this Lua file is intentionally a placeholder.\n"
    )


def _community_write_pair(
    destination: Path,
    manager: StrategyManager,
    name: str,
    conf_text: str,
) -> str:
    """Записывает .conf + .lua и проверяет профиль через StrategyManager."""
    if not _safe_strategy_name(f"{name}.lua"):
        raise StrategyError(f"Недопустимое имя стратегии: {name}")
    conf_path = destination / f"{name}.conf"
    lua_path = destination / f"{name}.lua"
    if conf_path.exists() or lua_path.exists():
        raise StrategyError(f"Стратегия {name} уже существует.")

    _community_write_text(conf_path, conf_text)
    try:
        _community_write_text(lua_path, _community_placeholder(name))
        strategy = manager.get(lua_path.name)
        if strategy is None:
            raise StrategyError("StrategyManager не увидел новый профиль.")
        validation = manager.validate(strategy)
        if not validation.valid or not strategy.profile.args:
            details = "; ".join(validation.errors) or "нет аргументов"
            raise StrategyError(f"Профиль не прошёл проверку: {details}")
    except Exception:
        conf_path.unlink(missing_ok=True)
        lua_path.unlink(missing_ok=True)
        raise
    return lua_path.name


def _community_step_blobs(steps: list[str]) -> set[str]:
    names: set[str] = set()
    for step in steps:
        for match in re.finditer(
            r"(?:^|:)(?:blob|seqovl_pattern)=([^:]+)", step
        ):
            names.add(match.group(1))
    return names


def _import_senshu(
    destination: Path,
    manager: StrategyManager,
    remaining: int,
) -> tuple[list[str], list[str], list[str], list[str]]:
    base = (
        "https://raw.githubusercontent.com/"
        "senshu-dev/nfqws2-linux-youtube-discord/main"
    )
    script = _community_http_text(f"{base}/install.sh")
    block = re.search(r'NFQWS2_OPT="\n(.*?)\n"', script, re.DOTALL)
    hosts_block = re.search(
        r"cat > \"\$HOSTLIST\" <<'LISTEOF'\n(.*?)\nLISTEOF",
        script,
        re.DOTALL,
    )
    if block is None or hosts_block is None:
        raise StrategyError("В install.sh не найден NFQWS2_OPT/hostlist.")
    hosts = _community_hosts(hosts_block.group(1))
    if not hosts:
        raise StrategyError("В hostlist источника нет допустимых доменов.")

    name = f"{COMMUNITY_PREFIX}senshu-youtube-discord"
    if remaining < 1:
        return [], ["senshu: лимит стратегий исчерпан."], [], []
    if (destination / f"{name}.conf").exists() or (
        destination / f"{name}.lua"
    ).exists():
        return [], [f"{name}: уже существует."], [], []

    hostlist_text = "\n".join(hosts) + "\n"
    hostlist = _community_asset_path(
        destination,
        f"{COMMUNITY_PREFIX}senshu-youtube-discord-hosts",
        ".txt",
        hostlist_text,
    )
    quic = "/opt/zapret2/files/fake/quic_initial_www_google_com.bin"
    tls = "/opt/zapret2/files/fake/tls_clienthello_www_google_com.bin"
    body = block.group(1)
    body = body.replace("{quic_blob}", quic)
    body = body.replace("{tls_blob}", tls)
    body = body.replace("{hostlist}", shlex.quote(str(hostlist)))
    conf = (
        "# Community nfqws2 profile: senshu-dev/nfqws2-linux-youtube-discord\n"
        "# Source is not executed; only nfqws2 arguments were extracted.\n"
        f"{body}\n"
    )
    imported = _community_write_pair(
        destination, manager, name, conf
    )
    note = f"senshu: импортирован {imported}; hostlist: {hostlist.name}"
    return [imported], [], [], [note]


def _import_nzapret(
    destination: Path,
    manager: StrategyManager,
    remaining: int,
) -> tuple[list[str], list[str], list[str], list[str]]:
    base = "https://raw.githubusercontent.com/nikitos4683/nzapret/main"
    conf_raw = _community_http_text(f"{base}/profiles/default.conf")
    names = ("general", "google", "user")
    list_texts: dict[str, str] = {}
    for key in names:
        # list-general.txt у nzapret весит ~24 МиБ.  Берём только начало
        # через Range; даже если сервер игнорирует Range, read() остановится
        # на лимите и не будет держать огромный файл в памяти.
        list_url = f"{base}/lists/list-{key}.txt"
        if key == "general":
            text = _community_http_text(
                list_url,
                limit=COMMUNITY_MAX_LIST,
                range_end=COMMUNITY_MAX_LIST - 1,
            )
        else:
            text = _community_http_text(list_url)
        hosts = _community_hosts(text)
        list_texts[key] = "\n".join(hosts) + ("\n" if hosts else "")

    name = f"{COMMUNITY_PREFIX}nzapret-default"
    if remaining < 1:
        return [], ["nzapret: лимит стратегий исчерпан."], [], []
    if (destination / f"{name}.conf").exists() or (
        destination / f"{name}.lua"
    ).exists():
        return [], [f"{name}: уже существует."], [], []

    list_paths: dict[str, Path] = {}
    for key in names:
        text = list_texts[key]
        if not text.strip():
            continue
        list_paths[key] = _community_asset_path(
            destination,
            f"{COMMUNITY_PREFIX}nzapret-list-{key}",
            ".txt",
            text,
        )
    if not list_paths:
        raise StrategyError(
            "Списки nzapret пусты; профиль без hostlist не импортируется."
        )

    lines = [
        "# Community nfqws2 profile: nikitos4683/nzapret",
        "# Android paths normalized; source is not executed.",
    ]
    for raw in conf_raw.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("--uid=", "--qnum=", "--lua-init=")):
            continue
        line = line.replace(
            "/data/adb/modules/nzapret/payloads/",
            "/opt/zapret2/files/fake/",
        )
        line = line.replace(
            "/data/adb/modules/nzapret/lua/",
            "/opt/zapret2/lua/",
        )
        for key, path in list_paths.items():
            source_path = f"/data/adb/modules/nzapret/lists/list-{key}.txt"
            line = line.replace(
                f"--hostlist={source_path}",
                "--hostlist=" + shlex.quote(str(path)),
            )
        if "list-" in line and "/data/adb/modules/nzapret/" in line:
            # Пустой список не создаём: убираем только его hostlist-строку.
            if stripped.startswith("--hostlist="):
                continue
        if "/data/adb/modules/nzapret/" in line:
            raise StrategyError(
                f"В профиле остался Android-путь: {line[:120]}"
            )
        lines.append(line)

    if len(lines) <= 2:
        raise StrategyError("После нормализации профиль nzapret пуст.")
    imported = _community_write_pair(
        destination,
        manager,
        name,
        "\n".join(lines) + "\n",
    )
    note = f"nzapret: импортирован {imported}"
    if list_paths:
        note += "; списки: " + ", ".join(
            path.name for path in list_paths.values()
        )
    return [imported], [], [], [note]


def _zemidala_lines(item: dict[str, object], provider_asn: int) -> list[str]:
    raw_steps = item.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise StrategyError("нет шагов")
    steps: list[str] = []
    for raw in raw_steps:
        if not isinstance(raw, str):
            raise StrategyError("шаг не является строкой")
        step = raw.strip()
        if not _COMMUNITY_STEP_RE.fullmatch(step):
            raise StrategyError("шаг содержит путь или недопустимые символы")
        steps.append(step)
    if len(steps) > 8:
        raise StrategyError("больше 8 шагов")

    proto = str(item.get("proto", "")).lower()
    if proto == "tls":
        filters = ("--filter-tcp=443", "--filter-l7=tls")
        payload = "--payload=tls_client_hello"
    elif proto == "http":
        filters = ("--filter-tcp=80", "--filter-l7=http")
        payload = "--payload=http_req"
    elif proto == "quic":
        filters = ("--filter-udp=443", "--filter-l7=quic")
        payload = "--payload=quic_initial"
    else:
        raise StrategyError(f"неизвестный протокол: {proto or '—'}")

    raw_targets = item.get("targets")
    if not isinstance(raw_targets, list):
        raise StrategyError("нет targets")
    host_text = "\n".join(
        str(target.get("host", ""))
        for target in raw_targets
        if isinstance(target, dict) and target.get("host")
    )
    hosts = _community_hosts(host_text)
    if not hosts:
        raise StrategyError("нет домена для hostlist; пропущено")

    blob_names = _community_step_blobs(steps)
    blob_lines: list[str] = []
    for blob_name in sorted(blob_names):
        if blob_name.startswith("0x"):
            continue
        if blob_name in _COMMUNITY_BUILTIN_BLOBS:
            continue
        path = _COMMUNITY_ZEMIDALA_BLOBS.get(blob_name)
        if path is None:
            raise StrategyError(f"неизвестный блоб {blob_name}")
        blob_lines.append(f"--blob={blob_name}:@{path}")

    return [
        "# Community nfqws2 profile: zemidala/nfqws2-strategies",
        f"# Provider AS{provider_asn}; source is not executed.",
        *blob_lines,
        *filters,
        f"--hostlist-domains={','.join(hosts)}",
        payload,
        *steps,
    ]


def _import_zemidala(
    destination: Path,
    manager: StrategyManager,
    remaining: int,
) -> tuple[list[str], list[str], list[str], list[str]]:
    base = (
        "https://raw.githubusercontent.com/"
        "zemidala/nfqws2-strategies/main"
    )
    index = _community_json(f"{base}/index.json")
    if not isinstance(index, dict):
        raise StrategyError("index.json имеет неверный формат.")
    providers = index.get("providers")
    if not isinstance(providers, list):
        raise StrategyError("В index.json нет списка providers.")

    imported: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []
    notes: list[str] = []
    for provider in providers:
        if len(imported) >= remaining:
            notes.append("zemidala: лимит стратегий исчерпан.")
            break
        if not isinstance(provider, dict):
            continue
        asn = provider.get("asn")
        if not isinstance(asn, int) or asn <= 0:
            continue
        try:
            data = _community_json(f"{base}/data/AS{asn}.json")
        except StrategyError as exc:
            errors.append(f"zemidala AS{asn}: {exc}")
            continue
        if not isinstance(data, dict):
            errors.append(f"zemidala AS{asn}: неверный JSON.")
            continue
        items = data.get("items")
        if not isinstance(items, list):
            continue
        for item in items:
            if len(imported) >= remaining:
                break
            if not isinstance(item, dict):
                continue
            item_id = re.sub(
                r"[^a-f0-9]", "", str(item.get("id", "")).lower()
            )
            if not item_id:
                continue
            proto = str(item.get("proto", "")).lower()
            name = (
                f"{COMMUNITY_PREFIX}zemidala-asn{asn}-"
                f"{item_id[:16]}-{proto}"
            )
            if (destination / f"{name}.conf").exists() or (
                destination / f"{name}.lua"
            ).exists():
                skipped.append(f"{name}: уже существует.")
                continue
            try:
                lines = _zemidala_lines(item, asn)
            except StrategyError as exc:
                skipped.append(f"{name}: {exc}.")
                continue
            try:
                imported_name = _community_write_pair(
                    destination, manager, name, "\n".join(lines) + "\n"
                )
            except StrategyError as exc:
                skipped.append(f"{name}: {exc}.")
                continue
            imported.append(imported_name)
    if imported:
        notes.append(
            "zemidala: импортированы только профили с известными блобами "
            "и доменными фильтрами."
        )
    return imported, skipped, errors, notes


def fetch_community_strategies(
    destination: Path | str | None = None,
    *,
    source_keys: tuple[str, ...] | list[str] | None = None,
    max_strategies: int = COMMUNITY_MAX_STRATEGIES,
) -> CommunityImportResult:
    """Скачивает готовые nfqws2-профили в папку стратегий.

    Источники фиксированы в :data:`COMMUNITY_SOURCES`.  Скачиваются только
    HTTPS-текстовые файлы и hostlists; shell-скрипты, ``.bat`` и бинарники не
    исполняются.  Каждый сгенерированный ``.conf`` проверяется через
    :class:`StrategyManager`; при ошибке файлы удаляются.

    Активная стратегия не меняется: пользователь выбирает её в TUI отдельно.
    """
    target_dir = Path(
        destination or DEFAULT_STRATEGIES_DIR
    ).expanduser().resolve()
    if target_dir.exists() and not target_dir.is_dir():
        raise StrategyError(f"{target_dir} не является каталогом.")
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StrategyError(
            f"Не удалось создать каталог стратегий {target_dir}: {exc}"
        ) from exc

    catalog = {source.key: source for source in COMMUNITY_SOURCES}
    if source_keys is None:
        selected = [source for source in COMMUNITY_SOURCES if source.supported]
    else:
        selected = []
        for key in source_keys:
            source = catalog.get(str(key))
            if source is None:
                raise StrategyError(f"Неизвестный источник стратегий: {key}")
            selected.append(source)

    manager = StrategyManager(target_dir)
    imported: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []
    notes: list[str] = []
    remaining = max(0, int(max_strategies))

    for source in selected:
        if not source.supported:
            notes.append(
                f"{source.name}: пропущен — это Windows winws.exe, "
                "автоматическая конвертация в nfqws2 не выполняется."
            )
            continue
        if remaining <= 0:
            notes.append("Достигнут лимит импортированных стратегий.")
            break
        try:
            if source.key == "senshu":
                got, was_skipped, source_errors, source_notes = _import_senshu(
                    target_dir, manager, remaining
                )
            elif source.key == "nzapret":
                got, was_skipped, source_errors, source_notes = _import_nzapret(
                    target_dir, manager, remaining
                )
            elif source.key == "zemidala":
                got, was_skipped, source_errors, source_notes = _import_zemidala(
                    target_dir, manager, remaining
                )
            else:
                raise StrategyError(f"Источник {source.key} не реализован.")
        except StrategyError as exc:
            errors.append(f"{source.name}: {exc}")
            continue
        imported.extend(got)
        skipped.extend(was_skipped)
        errors.extend(source_errors)
        notes.extend(source_notes)
        remaining = max(0, remaining - len(got))

    if not any(source.key == "flowseal" for source in selected):
        notes.append(
            "Flowseal/zapret-discord-youtube — Windows winws.exe; "
            "его .bat не конвертируется в nfqws2 автоматически."
        )

    return CommunityImportResult(
        imported=tuple(imported),
        skipped=tuple(skipped),
        errors=tuple(errors),
        notes=tuple(notes),
    )
