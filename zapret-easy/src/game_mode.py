"""Игровой режим zapret-easy.

Режим работает *поверх* уже выбранной стратегии nfqws2: он не заменяет
активный профиль, не отключает службу и не пишет собственных правил
nftables.  К ``active.conf`` добавляются только UDP-профили для DBD,
Discord, STUN и стандартных игровых портов, после чего служба
перезапускается (если была запущена).

Дополнительно применяются временные системные бусты:

* CPU governor ``performance`` через ``cpupower``;
* ``net.core.rmem_max`` / ``net.core.wmem_max``;
* ``fq_codel`` на интерфейсе маршрута по умолчанию;
* остановка watchdog-таймера, если он установлен.

Все изменения выполняет root-worker через ``pkexec``.  Перед изменениями
сохраняются исходные значения, а при ошибке выполняется откат.  Кроме
``active.conf`` обновляется ``zapret2.conf`` (``NFQWS2_PORTS_UDP``), иначе
nftables не направит игровые UDP-порты в NFQUEUE.  Состояние хранится в
``/var/lib/zapret-easy/game_mode.json`` вместе с boot-id, чтобы после
перезагрузки не показывать ложный «Game Mode Active».
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from src.service import (
    ACTIVE_CONF,
    SERVICE_NAME,
    STATE_DIR,
    ZAPRET_CONF,
    ServiceError,
    derive_firewall_ports,
)

logger = logging.getLogger("zapret-easy.game_mode")

PROJECT_ROOT: Final = Path(__file__).resolve().parent.parent
GAME_CONF: Final = PROJECT_ROOT / "strategies" / "game_and_voice.conf"
GAME_STATE_FILE: Final = STATE_DIR / "game_mode.json"
GAME_BACKUP_DIR: Final = STATE_DIR / "game_mode"
ACTIVE_CONF_BACKUP: Final = GAME_BACKUP_DIR / "active.conf.bak"
ZAPRET_CONF_BACKUP: Final = GAME_BACKUP_DIR / "zapret2.conf.bak"

GAME_QDISC: Final = "fq_codel"
GAME_GOVERNOR: Final = "performance"
WATCHDOG_TIMERS: Final = (
    "zapret-easy-watchdog.timer",
    "zapret-easy.timer",
)

GAME_SYSCTLS: Final = (
    ("net.core.rmem_max", "net/core/rmem_max", 26214400),
    ("net.core.wmem_max", "net/core/wmem_max", 26214400),
)

SYSTEM_PATH: Final = (
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)
_TOOL_FALLBACKS: Final = {
    "sysctl": ("/usr/sbin/sysctl", "/sbin/sysctl", "/usr/bin/sysctl"),
    "tc": ("/usr/sbin/tc", "/sbin/tc", "/usr/bin/tc"),
    "ip": ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"),
    "cpupower": (
        "/usr/bin/cpupower",
        "/usr/sbin/cpupower",
        "/sbin/cpupower",
    ),
    "systemctl": ("/usr/bin/systemctl", "/bin/systemctl"),
}

MAX_WORKER_LINE: Final = 64 * 1024
MAX_ACTIVE_CONF_BYTES: Final = 2 * 1024 * 1024
MAX_GAME_ARGS: Final = 256
COMMAND_TIMEOUT: Final = 30.0
SERVICE_TIMEOUT: Final = 150.0

# Только безопасные элементы игрового профиля.  Управляющие опции
# (--qnum, --daemon, --user, --lua-init и т.п.) сюда намеренно не входят.
ALLOWED_GAME_OPTIONS: Final = frozenset(
    {
        "--filter-udp",
        "--filter-tcp",
        "--filter-l7",
        "--payload",
        "--lua-desync",
        "--new",
        "--blob",
        "--hostlist",
        "--hostlist-domains",
        "--out-range",
        "--in-range",
    }
)
CONTROL_OPTIONS: Final = frozenset(
    {
        "--qnum",
        "--user",
        "--uid",
        "--gid",
        "--daemon",
        "--pidfile",
        "--fwmark",
        "--intercept",
        "--chdir",
        "--writable",
        "--debug",
        "--dry-run",
        "--lua-init",
        "--skip",
        "--template",
        "--import",
        "--name",
        "--server",
        "--comment",
    }
)

_IFACE_RE: Final = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
_QDISC_RE: Final = re.compile(r"^qdisc\s+([A-Za-z0-9_.-]+)")
_ROOT_RE: Final = re.compile(r"\broot\b")


class GameModeError(Exception):
    """Ошибка применения или отката игрового режима."""


@dataclass(frozen=True, slots=True)
class GameModeStatus:
    """Состояние режима, читаемое без root из state-файла."""

    active: bool
    interface: str | None = None
    qdisc: str | None = None
    governor: str | None = None
    watchdog_stopped: bool = False
    applied_at: str | None = None
    notes: tuple[str, ...] = ()
    stale: bool = False


@dataclass(frozen=True, slots=True)
class GameModeResult:
    """Результат root-операции."""

    ok: bool
    active: bool
    message: str
    details: tuple[str, ...] = ()
    output: str = ""
    returncode: int | None = None


# ---------------------------------------------------------------------------
# Вспомогательные команды и файлы
# ---------------------------------------------------------------------------


def _base_env() -> dict[str, str]:
    """Минимальное предсказуемое окружение для pkexec-потомка."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key in {"LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM"}
        or key.startswith("LC_")
    }
    env["PATH"] = SYSTEM_PATH
    env.setdefault("LC_ALL", "C.UTF-8")
    return env


def _run(
    command: list[str],
    *,
    timeout: float = COMMAND_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=PROJECT_ROOT,
            env=_base_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GameModeError(
            f"Не удалось выполнить {command[0]}: {exc}"
        ) from exc


def _command_output(completed: subprocess.CompletedProcess[str]) -> str:
    parts = [completed.stdout.strip(), completed.stderr.strip()]
    return "\n".join(part for part in parts if part)


def _tool(name: str) -> str | None:
    found = shutil.which(name, path=SYSTEM_PATH)
    if found:
        return found
    for candidate in _TOOL_FALLBACKS.get(name, ()):
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def _boot_id() -> str:
    try:
        return (
            Path("/proc/sys/kernel/random/boot_id")
            .read_text(encoding="utf-8")
            .strip()
        )
    except OSError:
        return ""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _write_atomic_bytes(path: Path, data: bytes, mode: int) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
    except OSError as exc:
        raise GameModeError(
            f"Не удалось подготовить {path}: {exc}"
        ) from exc

    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    except OSError as exc:
        temp_path.unlink(missing_ok=True)
        raise GameModeError(f"Не удалось записать {path}: {exc}") from exc


def _write_atomic_text(path: Path, text: str, mode: int) -> None:
    data = text.encode("utf-8")
    if not data.endswith(b"\n"):
        data += b"\n"
    _write_atomic_bytes(path, data, mode)


def _write_json_atomic(path: Path, payload: dict[str, Any], mode: int) -> None:
    _write_atomic_text(
        path,
        json.dumps(payload, ensure_ascii=False, indent=2),
        mode,
    )


def _ensure_state_dirs() -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(STATE_DIR, 0o711)
        GAME_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(GAME_BACKUP_DIR, 0o700)
    except OSError as exc:
        raise GameModeError(
            f"Не удалось создать каталог состояния: {exc}"
        ) from exc


def _load_state() -> dict[str, Any] | None:
    try:
        raw = GAME_STATE_FILE.read_text(encoding="utf-8")
    except OSError:
        return None
    except UnicodeDecodeError:
        logger.warning("Повреждён state-файл игрового режима")
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        logger.warning("Повреждён state-файл игрового режима")
        return None
    if not isinstance(data, dict) or data.get("version") != 1:
        return None
    return data


def _state_current(state: dict[str, Any] | None) -> bool:
    if not state or not bool(state.get("active")):
        return False
    return state.get("boot_id") == _boot_id()


def _save_state(state: dict[str, Any]) -> None:
    _ensure_state_dirs()
    _write_json_atomic(GAME_STATE_FILE, state, 0o644)


def _remove_state() -> None:
    try:
        GAME_STATE_FILE.unlink(missing_ok=True)
    except OSError as exc:
        raise GameModeError(
            f"Не удалось удалить state-файл игрового режима: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Игровой профиль nfqws2
# ---------------------------------------------------------------------------


def _read_game_args() -> tuple[str, ...]:
    """Читает и валидирует UDP-профили из strategies/game_and_voice.conf."""
    try:
        raw = GAME_CONF.read_text(encoding="utf-8")
    except OSError as exc:
        raise GameModeError(
            f"Не найден игровой профиль {GAME_CONF}: {exc}"
        ) from exc
    except UnicodeDecodeError as exc:
        raise GameModeError(
            f"Игровой профиль {GAME_CONF} не является UTF-8-текстом: {exc}"
        ) from exc

    try:
        args = shlex.split(raw, comments=True, posix=True)
    except ValueError as exc:
        raise GameModeError(
            f"Некорректный синтаксис {GAME_CONF}: {exc}"
        ) from exc

    if not args:
        raise GameModeError(f"Игровой профиль {GAME_CONF} пуст.")
    if len(args) > MAX_GAME_ARGS:
        raise GameModeError("Игровой профиль содержит слишком много опций.")

    for arg in args:
        if not arg.startswith("--"):
            raise GameModeError(
                f"Недопустимый аргумент игрового профиля: {arg!r}"
            )
        name, separator, value = arg.partition("=")
        if name in CONTROL_OPTIONS:
            raise GameModeError(
                f"Управляющая опция {name} запрещена в игровом профиле."
            )
        if name not in ALLOWED_GAME_OPTIONS:
            raise GameModeError(
                f"Опция {name} не разрешена в игровом профиле."
            )
        if not separator:
            # Без значения допустим только --new.
            if name != "--new":
                raise GameModeError(
                    f"Опция {name} требует значения."
                )
        elif not value:
            raise GameModeError(f"Пустое значение опции {name}.")
        if name == "--blob" and "@" in value:
            raise GameModeError(
                "В игровом профиле разрешены только hex-блобы."
            )
    return tuple(args)


def _read_active_args() -> list[str] | None:
    if not ACTIVE_CONF.is_file():
        return None
    try:
        if ACTIVE_CONF.stat().st_size > MAX_ACTIVE_CONF_BYTES:
            raise GameModeError("active.conf слишком большой.")
        raw = ACTIVE_CONF.read_text(encoding="utf-8")
        return shlex.split(raw, comments=True, posix=True)
    except OSError as exc:
        raise GameModeError(f"Не удалось прочитать {ACTIVE_CONF}: {exc}") from exc
    except ValueError as exc:
        raise GameModeError(
            f"Некорректный active.conf: {exc}"
        ) from exc


def _backup_active_conf() -> Path:
    try:
        data = ACTIVE_CONF.read_bytes()
    except OSError as exc:
        raise GameModeError(
            f"Не удалось прочитать active.conf для backup: {exc}"
        ) from exc
    _ensure_state_dirs()
    _write_atomic_bytes(ACTIVE_CONF_BACKUP, data, 0o600)
    return ACTIVE_CONF_BACKUP


def _game_args_present(
    active_args: list[str],
    game_args: tuple[str, ...],
) -> bool:
    """Проверяет, есть ли игровой блок в active.conf."""
    if not game_args or len(active_args) < len(game_args):
        return False
    size = len(game_args)
    for index in range(len(active_args) - size + 1):
        if tuple(active_args[index:index + size]) == game_args:
            return True
    return False


def _inject_game_args(game_args: tuple[str, ...]) -> tuple[bool, str]:
    """Добавляет игровые профили к active.conf, сохраняя основной профиль."""
    active_args = _read_active_args()
    if active_args is None:
        return (
            False,
            "active.conf не найден: nfqws2-профиль не изменён.",
        )
    if not active_args:
        raise GameModeError("active.conf пуст: нечего дополнять.")

    # Профиль игры может заканчиваться на --new. В combined-файле этот
    # разделитель уже не нужен: иначе nfqws2 получает лишний пустой профиль.
    effective_args = (
        game_args[:-1]
        if game_args and game_args[-1] == "--new"
        else game_args
    )

    if _game_args_present(active_args, effective_args):
        # Возможен повторный вход после reboot: state уже stale, но
        # active.conf сохранил игровой блок.  Backup с исходником мог
        # остаться с прошлого включения — тогда disable сможет откатиться.
        if ACTIVE_CONF_BACKUP.is_file():
            return (
                True,
                "Игровые UDP-правила уже присутствуют; исходный backup active.conf сохранён.",
            )
        return (
            False,
            "Игровые UDP-правила уже присутствуют, но backup active.conf не найден: повторно не добавляю.",
        )

    _backup_active_conf()
    combined = list(active_args)
    if combined[-1] != "--new":
        combined.append("--new")
    combined.extend(effective_args)
    _write_atomic_text(ACTIVE_CONF, shlex.join(combined), 0o600)
    return (
        True,
        "Игровые UDP-правила добавлены; основной профиль сохранён.",
    )


def _restore_active_conf() -> None:
    if not ACTIVE_CONF_BACKUP.is_file():
        raise GameModeError("Backup active.conf не найден.")
    try:
        data = ACTIVE_CONF_BACKUP.read_bytes()
    except OSError as exc:
        raise GameModeError(
            f"Не удалось прочитать backup active.conf: {exc}"
        ) from exc
    _write_atomic_bytes(ACTIVE_CONF, data, 0o600)


# ---------------------------------------------------------------------------
# Порты nftables
# ---------------------------------------------------------------------------


def _shell_assignment_value(line: str) -> str:
    """Читает значение из строки вида NFQWS2_PORTS_UDP='...'."""
    _name, separator, raw = line.partition("=")
    if not separator:
        return ""
    try:
        parts = shlex.split(raw.strip(), comments=True, posix=True)
    except ValueError:
        return ""
    return parts[0] if parts else ""


def _merge_udp_ports(existing: str, addition: str) -> str:
    """Объединяет списки портов zapret2 без дублей."""
    values: list[str] = []
    seen: set[str] = set()
    for source in (existing, addition):
        for item in source.split(","):
            item = item.strip()
            if not item:
                continue
            if item == "*":
                # Если firewall уже слушает все UDP-порты, ничего добавлять
                # не нужно; сохраняем звёздочку как есть.
                return "*"
            if not re.fullmatch(r"~?[0-9]+(?:-[0-9]+)?", item):
                raise GameModeError(
                    f"Некорректный UDP-порт в firewall-конфиге: {item!r}"
                )
            if item not in seen:
                seen.add(item)
                values.append(item)
    return ",".join(values)


def _inject_zapret_ports(game_args: tuple[str, ...]) -> tuple[bool, str]:
    """Добавляет игровые UDP-порты в NFQWS2_PORTS_UDP.

    nfqws2 не увидит пакеты, если firewall zapret2 не направит их в
    NFQUEUE.  Поэтому активный профиль и firewall-конфиг обновляются парой.
    """
    if not ZAPRET_CONF.is_file():
        raise GameModeError(
            f"Не найден {ZAPRET_CONF}: нельзя добавить игровые UDP-порты "
            "в firewall zapret2."
        )

    try:
        text = ZAPRET_CONF.read_text(encoding="utf-8")
    except OSError as exc:
        raise GameModeError(
            f"Не удалось прочитать {ZAPRET_CONF}: {exc}"
        ) from exc
    except UnicodeDecodeError as exc:
        raise GameModeError(
            f"{ZAPRET_CONF} не является UTF-8-текстом: {exc}"
        ) from exc

    try:
        _tcp, game_udp = derive_firewall_ports(game_args)
    except ServiceError as exc:
        raise GameModeError(
            f"Не удалось определить UDP-порты игрового профиля: {exc}"
        ) from exc
    if not game_udp:
        return False, "В игровом профиле нет UDP-портов для nftables."

    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if not line.startswith("NFQWS2_PORTS_UDP="):
            continue
        current = _shell_assignment_value(line)
        merged = _merge_udp_ports(current, game_udp)
        if merged == current:
            if ZAPRET_CONF_BACKUP.is_file():
                return (
                    True,
                    "Игровые UDP-порты уже в firewall zapret2; исходный backup сохранён.",
                )
            return (
                False,
                "Игровые UDP-порты уже присутствуют в firewall zapret2.",
            )
        try:
            data = ZAPRET_CONF.read_bytes()
        except OSError as exc:
            raise GameModeError(
                f"Не удалось сохранить backup {ZAPRET_CONF}: {exc}"
            ) from exc
        _ensure_state_dirs()
        _write_atomic_bytes(ZAPRET_CONF_BACKUP, data, 0o600)
        ending = "\n" if line.endswith("\n") else ""
        lines[index] = (
            f"NFQWS2_PORTS_UDP={shlex.quote(merged)}{ending}"
        )
        _write_atomic_text(ZAPRET_CONF, "".join(lines), 0o600)
        return (
            True,
            f"Firewall zapret2: добавлены UDP-порты {game_udp}.",
        )

    raise GameModeError(
        f"В {ZAPRET_CONF} нет строки NFQWS2_PORTS_UDP."
    )


def _restore_zapret_conf() -> None:
    if not ZAPRET_CONF_BACKUP.is_file():
        raise GameModeError("Backup zapret2.conf не найден.")
    try:
        data = ZAPRET_CONF_BACKUP.read_bytes()
    except OSError as exc:
        raise GameModeError(
            f"Не удалось прочитать backup zapret2.conf: {exc}"
        ) from exc
    _write_atomic_bytes(ZAPRET_CONF, data, 0o600)


# ---------------------------------------------------------------------------
# CPU governor
# ---------------------------------------------------------------------------


def _governor_paths() -> dict[str, Path]:
    base = Path("/sys/devices/system/cpu")
    paths: dict[str, Path] = {}
    try:
        candidates = sorted(base.glob("cpu[0-9]*/cpufreq/scaling_governor"))
    except OSError:
        return paths
    for path in candidates:
        paths[path.parent.parent.name] = path
    return paths


def _read_governors() -> dict[str, str]:
    values: dict[str, str] = {}
    for cpu, path in _governor_paths().items():
        try:
            values[cpu] = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    return values


def _apply_governor(
    notes: list[str],
    details: list[str],
) -> tuple[dict[str, str], bool]:
    before = _read_governors()
    if not before:
        notes.append("CPU cpufreq недоступен: governor не изменён.")
        return before, False
    if all(value == GAME_GOVERNOR for value in before.values()):
        notes.append("CPU governor уже performance.")
        return before, False

    cpupower = _tool("cpupower")
    if cpupower is None:
        notes.append(
            "cpupower не найден: CPU governor оставлен без изменений."
        )
        return before, False

    completed = _run(
        [cpupower, "frequency-set", "-g", GAME_GOVERNOR],
        timeout=COMMAND_TIMEOUT,
    )
    if completed.returncode != 0:
        current = _read_governors()
        changed = current != before
        notes.append(
            "cpupower frequency-set не сработал"
            + (f": {_command_output(completed)}" if _command_output(completed) else ".")
        )
        return before, changed

    current = _read_governors()
    changed = current != before
    if not current:
        notes.append("Не удалось проверить CPU governor после изменения.")
    elif any(value != GAME_GOVERNOR for value in current.values()):
        notes.append(
            "CPU governor применён не на всех ядрах (частичный результат)."
        )
    if changed:
        old = ", ".join(sorted(set(before.values())))
        details.append(f"CPU governor: {old} → {GAME_GOVERNOR}.")
    return before, changed


def _restore_governor(before: dict[str, str]) -> None:
    if not before:
        return

    unique = sorted(set(before.values()))
    errors: list[str] = []
    if len(unique) == 1:
        cpupower = _tool("cpupower")
        if cpupower is not None:
            completed = _run(
                [cpupower, "frequency-set", "-g", unique[0]],
                timeout=COMMAND_TIMEOUT,
            )
            if completed.returncode != 0:
                errors.append(_command_output(completed))
    else:
        errors.append("Исходные governor различались; восстанавливаю по ядрам.")

    # Для смешанных политик и как fallback используем sysfs.
    for cpu, governor in before.items():
        path = _governor_paths().get(cpu)
        if path is None:
            errors.append(f"Ядро {cpu}: cpufreq больше недоступен.")
            continue
        try:
            path.write_text(governor + "\n", encoding="utf-8")
        except OSError as exc:
            errors.append(f"Ядро {cpu}: {exc}")

    current = _read_governors()
    if current != before:
        details = ", ".join(
            f"{cpu}={current.get(cpu, '?')}" for cpu in sorted(before)
        )
        raise GameModeError(
            "Не удалось восстановить CPU governor"
            + (f": {'; '.join(errors)}" if errors else "")
            + f" (сейчас: {details})."
        )


# ---------------------------------------------------------------------------
# Sysctl
# ---------------------------------------------------------------------------


def _sysctl_path(relative: str) -> Path:
    return Path("/proc/sys") / relative


def _read_sysctl(relative: str) -> str | None:
    try:
        return _sysctl_path(relative).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _apply_sysctls(
    before: dict[str, str],
    changed: list[str],
    notes: list[str],
    details: list[str],
) -> None:
    sysctl = _tool("sysctl")

    for key, relative, target in GAME_SYSCTLS:
        current = _read_sysctl(relative)
        if current is None:
            raise GameModeError(f"Не удалось прочитать {key}.")
        before[key] = current
        try:
            current_int = int(current)
        except ValueError as exc:
            raise GameModeError(
                f"Некорректное текущее значение {key}: {current!r}"
            ) from exc
        if current_int >= target:
            notes.append(f"{key} уже ≥ {target}: значение не понижаю.")
            continue

        if sysctl is None:
            raise GameModeError("sysctl не найден: нельзя применить буферы.")
        completed = _run(
            [sysctl, "-w", f"{key}={target}"],
            timeout=COMMAND_TIMEOUT,
        )
        if completed.returncode != 0:
            raise GameModeError(
                f"Не удалось применить {key}={target}: "
                f"{_command_output(completed)}"
            )
        actual = _read_sysctl(relative)
        if actual != str(target):
            raise GameModeError(
                f"Проверка {key} не прошла: ожидалось {target}, "
                f"получено {actual!r}."
            )
        changed.append(key)
        details.append(f"{key}: {current} → {target}.")


def _restore_sysctls(before: dict[str, str], changed: list[str]) -> None:
    sysctl = _tool("sysctl")
    if sysctl is None:
        raise GameModeError("sysctl не найден: нельзя откатить буферы.")
    errors: list[str] = []
    relative_by_key = {key: relative for key, relative, _ in GAME_SYSCTLS}
    for key in changed:
        value = before.get(key)
        relative = relative_by_key.get(key)
        if value is None or relative is None:
            errors.append(f"{key}: нет сохранённого значения.")
            continue
        completed = _run(
            [sysctl, "-w", f"{key}={value}"],
            timeout=COMMAND_TIMEOUT,
        )
        if completed.returncode != 0:
            errors.append(
                f"{key}: {_command_output(completed)}"
            )
            continue
        actual = _read_sysctl(relative)
        if actual != value:
            errors.append(
                f"{key}: ожидалось {value}, получено {actual!r}."
            )
    if errors:
        raise GameModeError(
            "Не удалось восстановить sysctl: " + "; ".join(errors)
        )


# ---------------------------------------------------------------------------
# Qdisc
# ---------------------------------------------------------------------------


def _detect_interface() -> str | None:
    ip = _tool("ip")
    if ip is not None:
        for arguments in (
            ["-4", "route", "show", "default"],
            ["route", "show", "default"],
            ["route", "get", "1.1.1.1"],
        ):
            try:
                completed = _run([ip, *arguments], timeout=10.0)
            except GameModeError:
                continue
            if completed.returncode != 0:
                continue
            match = re.search(
                r"\bdev\s+([A-Za-z0-9_.:-]+)",
                completed.stdout,
            )
            if match and match.group(1) != "lo":
                return match.group(1)

    # Fallback без iproute2: default route из /proc/net/route.
    try:
        lines = Path("/proc/net/route").read_text(
            encoding="utf-8"
        ).splitlines()
    except OSError:
        return None
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 4:
            continue
        interface, destination, _gateway, flags = fields[:4]
        if interface == "lo" or destination != "00000000":
            continue
        try:
            if int(flags, 16) & 0x0001:
                return interface
        except ValueError:
            continue
    return None


def _root_qdisc(interface: str) -> str | None:
    tc = _tool("tc")
    if tc is None:
        return None
    completed = _run([tc, "qdisc", "show", "dev", interface])
    if completed.returncode != 0:
        raise GameModeError(
            f"Не удалось прочитать qdisc {interface}: "
            f"{_command_output(completed)}"
        )
    for line in completed.stdout.splitlines():
        if not _ROOT_RE.search(line):
            continue
        match = _QDISC_RE.match(line.strip())
        if match:
            return match.group(1)
    return None


def _apply_qdisc(
    notes: list[str],
    details: list[str],
) -> tuple[str | None, str | None, bool]:
    interface = _detect_interface()
    if interface is None:
        notes.append(
            "Не удалось определить интерфейс по умолчанию: qdisc не изменён."
        )
        return None, None, False
    if not _IFACE_RE.match(interface):
        notes.append(f"Подозрительное имя интерфейса {interface!r}: qdisc не изменён.")
        return None, None, False

    current = _root_qdisc(interface)
    if current is None:
        notes.append(f"Не удалось определить текущий qdisc {interface}: пропущено.")
        return interface, None, False
    if current in {"fq_codel", "cake"}:
        notes.append(f"qdisc {interface} уже {current}: оставлен без изменений.")
        return interface, current, False
    if current == "noqueue":
        notes.append(
            f"qdisc {interface} — noqueue: для этого интерфейса замена пропущена."
        )
        return interface, current, False

    tc = _tool("tc")
    if tc is None:
        notes.append("tc не найден: qdisc не изменён.")
        return interface, current, False

    completed = _run(
        [tc, "qdisc", "replace", "dev", interface, "root", GAME_QDISC],
        timeout=COMMAND_TIMEOUT,
    )
    if completed.returncode != 0:
        raise GameModeError(
            f"Не удалось применить qdisc {GAME_QDISC} на {interface}: "
            f"{_command_output(completed)}"
        )
    actual = _root_qdisc(interface)
    if actual != GAME_QDISC:
        # Команда могла частично применить qdisc — пробуем сразу вернуть.
        try:
            _restore_qdisc(interface, current)
        except GameModeError:
            logger.exception("Не удалось вернуть qdisc после ошибки проверки")
        raise GameModeError(
            f"Проверка qdisc {interface} не прошла: ожидалось "
            f"{GAME_QDISC}, получено {actual!r}."
        )
    details.append(f"qdisc {interface}: {current} → {GAME_QDISC}.")
    return interface, current, True


def _restore_qdisc(interface: str, original: str) -> None:
    tc = _tool("tc")
    if tc is None:
        raise GameModeError("tc не найден: нельзя восстановить qdisc.")
    completed = _run(
        [tc, "qdisc", "replace", "dev", interface, "root", original],
        timeout=COMMAND_TIMEOUT,
    )
    if completed.returncode != 0:
        raise GameModeError(
            f"Не удалось восстановить qdisc {interface} ({original}): "
            f"{_command_output(completed)}"
        )
    actual = _root_qdisc(interface)
    if actual != original:
        raise GameModeError(
            f"Проверка восстановления qdisc {interface} не прошла: "
            f"ожидалось {original}, получено {actual!r}."
        )


# ---------------------------------------------------------------------------
# Watchdog
# ---------------------------------------------------------------------------


def _find_watchdog_timer() -> str | None:
    systemctl = _tool("systemctl")
    if systemctl is None:
        return None
    for timer in WATCHDOG_TIMERS:
        completed = _run(
            [systemctl, "show", "-p", "LoadState", "--value", timer],
            timeout=10.0,
        )
        if (
            completed.returncode == 0
            and completed.stdout.strip() == "loaded"
        ):
            return timer
    return None


def _timer_active(timer: str) -> bool:
    systemctl = _tool("systemctl")
    if systemctl is None:
        return False
    completed = _run([systemctl, "is-active", timer], timeout=10.0)
    return (
        completed.returncode == 0
        and completed.stdout.strip() == "active"
    )


def _apply_watchdog(
    notes: list[str],
    details: list[str],
) -> tuple[str | None, bool]:
    timer = _find_watchdog_timer()
    if timer is None:
        notes.append(
            "watchdog-таймер не найден: остановка пропущена."
        )
        return None, False
    if not _timer_active(timer):
        notes.append(f"watchdog {timer} уже неактивен.")
        return timer, False

    systemctl = _tool("systemctl")
    if systemctl is None:
        raise GameModeError("systemctl не найден: нельзя остановить watchdog.")
    completed = _run([systemctl, "stop", timer], timeout=COMMAND_TIMEOUT)
    if completed.returncode != 0:
        raise GameModeError(
            f"Не удалось остановить {timer}: {_command_output(completed)}"
        )
    if _timer_active(timer):
        try:
            _run([systemctl, "start", timer], timeout=COMMAND_TIMEOUT)
        except GameModeError:
            logger.exception("Не удалось вернуть watchdog после ошибки")
        raise GameModeError(f"watchdog {timer} остался активным после stop.")
    details.append(f"watchdog {timer}: остановлен на время матча.")
    return timer, True


def _restore_watchdog(timer: str | None) -> None:
    if timer is None:
        return
    systemctl = _tool("systemctl")
    if systemctl is None:
        raise GameModeError("systemctl не найден: нельзя запустить watchdog.")
    completed = _run([systemctl, "start", timer], timeout=COMMAND_TIMEOUT)
    if completed.returncode != 0:
        raise GameModeError(
            f"Не удалось запустить {timer}: {_command_output(completed)}"
        )
    if not _timer_active(timer):
        raise GameModeError(
            f"Проверка watchdog {timer} не прошла: таймер не активен."
        )


# ---------------------------------------------------------------------------
# nfqws2 service
# ---------------------------------------------------------------------------


def _service_active() -> bool:
    systemctl = _tool("systemctl")
    if systemctl is None:
        return False
    completed = _run(
        [systemctl, "is-active", SERVICE_NAME],
        timeout=10.0,
    )
    return (
        completed.returncode == 0
        and completed.stdout.strip() == "active"
    )


def _restart_service() -> None:
    systemctl = _tool("systemctl")
    if systemctl is None:
        raise GameModeError(
            "systemctl не найден: нельзя перезапустить nfqws2."
        )
    completed = _run(
        [systemctl, "restart", SERVICE_NAME],
        timeout=SERVICE_TIMEOUT,
    )
    if completed.returncode != 0:
        raise GameModeError(
            f"Не удалось перезапустить {SERVICE_NAME}: "
            f"{_command_output(completed)}"
        )


# ---------------------------------------------------------------------------
# Включение / выключение
# ---------------------------------------------------------------------------


def _rollback_enable(
    *,
    governor_before: dict[str, str],
    governor_changed: bool,
    sysctl_before: dict[str, str],
    sysctl_changed: list[str],
    interface: str | None,
    qdisc_original: str | None,
    qdisc_changed: bool,
    watchdog_timer: str | None,
    watchdog_stopped: bool,
    active_conf_injected: bool,
    zapret_conf_injected: bool,
    service_was_active: bool,
) -> list[str]:
    errors: list[str] = []

    if active_conf_injected:
        try:
            _restore_active_conf()
        except GameModeError as exc:
            errors.append(f"active.conf: {exc}")
    if zapret_conf_injected:
        try:
            _restore_zapret_conf()
        except GameModeError as exc:
            errors.append(f"zapret2.conf: {exc}")
    if (active_conf_injected or zapret_conf_injected) and service_was_active:
        try:
            _restart_service()
        except GameModeError as exc:
            errors.append(f"service: {exc}")

    if watchdog_stopped and watchdog_timer is not None:
        try:
            _restore_watchdog(watchdog_timer)
        except GameModeError as exc:
            errors.append(f"watchdog: {exc}")

    if qdisc_changed and interface is not None and qdisc_original is not None:
        try:
            _restore_qdisc(interface, qdisc_original)
        except GameModeError as exc:
            errors.append(f"qdisc: {exc}")

    if sysctl_changed:
        try:
            _restore_sysctls(sysctl_before, sysctl_changed)
        except GameModeError as exc:
            errors.append(f"sysctl: {exc}")

    if governor_changed:
        try:
            _restore_governor(governor_before)
        except GameModeError as exc:
            errors.append(f"governor: {exc}")

    return errors


def _enable() -> GameModeResult:
    state = _load_state()
    if _state_current(state):
        details = tuple(str(item) for item in state.get("details", ()))
        return GameModeResult(
            True,
            True,
            "Игровой режим уже включён.",
            details=details,
            output="",
        )

    game_args = _read_game_args()
    active_conf_existed = ACTIVE_CONF.is_file()
    service_was_active = _service_active() if active_conf_existed else False

    notes: list[str] = []
    details: list[str] = []

    governor_before: dict[str, str] = {}
    governor_changed = False
    sysctl_before: dict[str, str] = {}
    sysctl_changed: list[str] = []
    interface: str | None = None
    qdisc_original: str | None = None
    qdisc_changed = False
    watchdog_timer: str | None = None
    watchdog_stopped = False
    active_conf_injected = False
    zapret_conf_injected = False

    try:
        governor_before, governor_changed = _apply_governor(notes, details)
        _apply_sysctls(sysctl_before, sysctl_changed, notes, details)
        interface, qdisc_original, qdisc_changed = _apply_qdisc(notes, details)
        watchdog_timer, watchdog_stopped = _apply_watchdog(notes, details)

        if active_conf_existed:
            active_conf_injected, note = _inject_game_args(game_args)
            notes.append(note)
            zapret_conf_injected, note = _inject_zapret_ports(game_args)
            notes.append(note)
            if service_was_active and (
                active_conf_injected or zapret_conf_injected
            ):
                _restart_service()
                details.append(
                    f"{SERVICE_NAME}: перезапущен с игровыми UDP-правилами."
                )
            elif active_conf_injected or zapret_conf_injected:
                notes.append(
                    f"{SERVICE_NAME} не был активен: правила применятся "
                    "при следующем запуске."
                )
        else:
            notes.append(
                "active.conf отсутствует: nfqws2-служба не изменена."
            )

        state = {
            "version": 1,
            "active": True,
            "boot_id": _boot_id(),
            "applied_at": _now_iso(),
            "interface": interface,
            "qdisc": GAME_QDISC if qdisc_changed else qdisc_original,
            "governor": GAME_GOVERNOR if governor_changed else None,
            "watchdog_timer": watchdog_timer,
            "watchdog_stopped": watchdog_stopped,
            "governor_before": governor_before,
            "governor_changed": governor_changed,
            "sysctl_before": sysctl_before,
            "sysctl_changed": sysctl_changed,
            "qdisc_original": qdisc_original,
            "qdisc_changed": qdisc_changed,
            "active_conf_injected": active_conf_injected,
            "zapret_conf_injected": zapret_conf_injected,
            "active_conf_existed": active_conf_existed,
            "service_was_active": service_was_active,
            "notes": notes,
            "details": details,
        }
        _save_state(state)
    except GameModeError as exc:
        rollback_errors = _rollback_enable(
            governor_before=governor_before,
            governor_changed=governor_changed,
            sysctl_before=sysctl_before,
            sysctl_changed=sysctl_changed,
            interface=interface,
            qdisc_original=qdisc_original,
            qdisc_changed=qdisc_changed,
            watchdog_timer=watchdog_timer,
            watchdog_stopped=watchdog_stopped,
            active_conf_injected=active_conf_injected,
            zapret_conf_injected=zapret_conf_injected,
            service_was_active=service_was_active,
        )
        message = f"Игровой режим не включён: {exc}"
        if rollback_errors:
            message += (
                "\nОткат выполнен не полностью:\n- "
                + "\n- ".join(rollback_errors)
            )
        return GameModeResult(
            False,
            False,
            message,
            details=tuple(notes + details + rollback_errors),
        )
    except OSError as exc:
        rollback_errors = _rollback_enable(
            governor_before=governor_before,
            governor_changed=governor_changed,
            sysctl_before=sysctl_before,
            sysctl_changed=sysctl_changed,
            interface=interface,
            qdisc_original=qdisc_original,
            qdisc_changed=qdisc_changed,
            watchdog_timer=watchdog_timer,
            watchdog_stopped=watchdog_stopped,
            active_conf_injected=active_conf_injected,
            zapret_conf_injected=zapret_conf_injected,
            service_was_active=service_was_active,
        )
        error_text = f"Ошибка файловой системы: {exc}"
        if rollback_errors:
            error_text += (
                "\nОткат выполнен не полностью:\n- "
                + "\n- ".join(rollback_errors)
            )
        return GameModeResult(
            False,
            False,
            error_text,
            details=tuple(notes + details + rollback_errors),
        )

    if not details:
        details.append("Системные бусты уже были применены.")
    return GameModeResult(
        True,
        True,
        "Игровой режим включён. YouTube-профиль не заменён.",
        details=tuple(details + notes),
    )


def _disable() -> GameModeResult:
    state = _load_state()
    if not state or not bool(state.get("active")):
        return GameModeResult(
            False,
            False,
            "Игровой режим не активен.",
        )
    if state.get("boot_id") != _boot_id():
        return GameModeResult(
            False,
            False,
            "Найдено состояние от прошлой загрузки; "
            "текущие системные настройки не изменялись.",
        )

    errors: list[str] = []
    details: list[str] = []

    active_conf_injected = bool(state.get("active_conf_injected"))
    zapret_conf_injected = bool(state.get("zapret_conf_injected"))
    if active_conf_injected:
        try:
            _restore_active_conf()
            details.append("active.conf: восстановлен исходный профиль.")
        except GameModeError as exc:
            errors.append(f"active.conf: {exc}")
    if zapret_conf_injected:
        try:
            _restore_zapret_conf()
            details.append(
                "zapret2.conf: восстановлен исходный список UDP-портов."
            )
        except GameModeError as exc:
            errors.append(f"zapret2.conf: {exc}")
    if active_conf_injected or zapret_conf_injected:
        if _service_active():
            try:
                _restart_service()
                details.append(f"{SERVICE_NAME}: перезапущен.")
            except GameModeError as exc:
                errors.append(f"service: {exc}")
        else:
            details.append(
                f"{SERVICE_NAME} не запущен: исходный профиль "
                "применится при следующем старте."
            )

    if bool(state.get("watchdog_stopped")):
        timer = state.get("watchdog_timer")
        if isinstance(timer, str) and timer:
            try:
                _restore_watchdog(timer)
                details.append(f"watchdog {timer}: снова запущен.")
            except GameModeError as exc:
                errors.append(f"watchdog: {exc}")
        else:
            errors.append("watchdog: не сохранено имя таймера.")

    if bool(state.get("qdisc_changed")):
        interface = state.get("interface")
        original = state.get("qdisc_original")
        if isinstance(interface, str) and isinstance(original, str):
            try:
                _restore_qdisc(interface, original)
                details.append(
                    f"qdisc {interface}: возвращён {original}."
                )
            except GameModeError as exc:
                errors.append(f"qdisc: {exc}")
        else:
            errors.append("qdisc: не сохранены параметры отката.")

    sysctl_changed = state.get("sysctl_changed")
    sysctl_before = state.get("sysctl_before")
    if isinstance(sysctl_changed, list) and sysctl_changed:
        if isinstance(sysctl_before, dict):
            try:
                _restore_sysctls(sysctl_before, sysctl_changed)
                details.append("sysctl-буферы: возвращены исходные значения.")
            except GameModeError as exc:
                errors.append(f"sysctl: {exc}")
        else:
            errors.append("sysctl: не сохранены исходные значения.")

    if bool(state.get("governor_changed")):
        governor_before = state.get("governor_before")
        if isinstance(governor_before, dict):
            try:
                _restore_governor(governor_before)
                details.append("CPU governor: восстановлен.")
            except GameModeError as exc:
                errors.append(f"governor: {exc}")
        else:
            errors.append("governor: не сохранены исходные значения.")

    if errors:
        return GameModeResult(
            False,
            True,
            "Игровой режим выключен не полностью:\n- "
            + "\n- ".join(errors),
            details=tuple(details),
        )

    try:
        _remove_state()
    except GameModeError as exc:
        return GameModeResult(
            False,
            True,
            f"Настройки восстановлены, но state не удалён: {exc}",
            details=tuple(details),
        )

    return GameModeResult(
        True,
        False,
        "Игровой режим выключен. Исходные настройки восстановлены.",
        details=tuple(details),
    )


# ---------------------------------------------------------------------------
# Root-worker и публичный API
# ---------------------------------------------------------------------------


def _ensure_root() -> None:
    if os.geteuid() != 0:
        raise GameModeError(
            "Root-worker игрового режима должен запускаться через pkexec."
        )


def _execute_plan(payload: dict[str, Any]) -> GameModeResult:
    _ensure_root()
    action = payload.get("action")
    if action == "enable":
        return _enable()
    if action == "disable":
        return _disable()
    raise GameModeError(f"Неизвестное действие игрового режима: {action!r}")


def _parse_worker_result(stdout: str) -> GameModeResult | None:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if not isinstance(data, dict) or "ok" not in data:
            continue
        details = data.get("details", ())
        if not isinstance(details, (list, tuple)):
            details = ()
        return GameModeResult(
            ok=bool(data.get("ok")),
            active=bool(data.get("active")),
            message=str(data.get("message", "")),
            details=tuple(str(item) for item in details),
            output=str(data.get("output", "")),
            returncode=data.get("returncode")
            if isinstance(data.get("returncode"), int)
            else None,
        )
    return None


class GameModeManager:
    """Пользовательский API TUI: статус, включение и выключение."""

    def status(self) -> GameModeStatus:
        state = _load_state()
        if not state or not bool(state.get("active")):
            return GameModeStatus(active=False)
        if state.get("boot_id") != _boot_id():
            return GameModeStatus(
                active=False,
                stale=True,
                notes=(
                    "Найдено состояние Game Mode от прошлой загрузки; системные бусты после reboot не действуют.",
                ),
            )
        notes = state.get("notes", ())
        if not isinstance(notes, (list, tuple)):
            notes = ()
        return GameModeStatus(
            active=True,
            interface=state.get("interface")
            if isinstance(state.get("interface"), str)
            else None,
            qdisc=state.get("qdisc")
            if isinstance(state.get("qdisc"), str)
            else None,
            governor=state.get("governor")
            if isinstance(state.get("governor"), str)
            else None,
            watchdog_stopped=bool(state.get("watchdog_stopped")),
            applied_at=state.get("applied_at")
            if isinstance(state.get("applied_at"), str)
            else None,
            notes=tuple(str(item) for item in notes),
        )

    def enable(self) -> GameModeResult:
        return _run_root({"version": 1, "action": "enable"})

    def disable(self) -> GameModeResult:
        return _run_root({"version": 1, "action": "disable"})


def _run_root(payload: dict[str, Any]) -> GameModeResult:
    if os.geteuid() == 0:
        try:
            return _execute_plan(payload)
        except GameModeError as exc:
            return GameModeResult(False, False, str(exc))
        except Exception as exc:  # TUI не должен падать
            logger.exception("Ошибка игрового режима")
            return GameModeResult(
                False,
                False,
                f"Внутренняя ошибка игрового режима: {exc}",
            )

    pkexec = shutil.which("pkexec")
    if pkexec is None:
        return GameModeResult(
            False,
            False,
            "pkexec не найден: нельзя применить игровой режим.",
        )

    python = Path(sys.executable)
    if not python.is_absolute():
        python = Path("/usr/bin/python3")
    project = str(PROJECT_ROOT)
    bootstrap = (
        "import sys;"
        f"sys.path.insert(0, {project!r});"
        "from src.game_mode import worker_main;"
        "raise SystemExit(worker_main())"
    )
    try:
        completed = subprocess.run(
            [pkexec, str(python), "-c", bootstrap, "--worker"],
            input=json.dumps(payload, ensure_ascii=False) + "\n",
            capture_output=True,
            text=True,
            timeout=180.0,
            check=False,
            cwd=PROJECT_ROOT,
            env=_base_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return GameModeResult(
            False,
            False,
            f"Не удалось запустить pkexec: {exc}",
        )

    result = _parse_worker_result(completed.stdout)
    if result is not None:
        return result

    stderr = completed.stderr.strip()
    if completed.returncode == 126:
        message = "Авторизация pkexec отменена или недоступна."
    elif completed.returncode == 127:
        message = "pkexec не разрешил выполнение root-операции."
    else:
        message = (
            "root-worker игрового режима завершился без результата "
            f"(код {completed.returncode})."
        )
    if stderr:
        message += f"\n{stderr}"
    return GameModeResult(
        False,
        False,
        message,
        output=stderr,
        returncode=completed.returncode,
    )


def _emit_result(result: GameModeResult) -> None:
    sys.stdout.write(
        json.dumps(asdict(result), ensure_ascii=False) + "\n"
    )
    sys.stdout.flush()


def worker_main() -> int:
    """Точка входа root-worker-а: одна JSON-строка на stdin."""
    try:
        raw = sys.stdin.buffer.readline(MAX_WORKER_LINE + 1)
        if not raw:
            raise GameModeError("Не получен план игрового режима.")
        if len(raw) > MAX_WORKER_LINE:
            raise GameModeError("План игрового режима слишком большой.")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise GameModeError(
                f"Некорректный JSON плана: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise GameModeError(
                "План игрового режима должен быть JSON-объектом."
            )
        result = _execute_plan(payload)
    except GameModeError as exc:
        result = GameModeResult(False, False, str(exc))
    except Exception as exc:  # worker обязан вернуть JSON
        logger.exception("Ошибка root-worker-а игрового режима")
        result = GameModeResult(
            False,
            False,
            f"Внутренняя ошибка игрового режима: {exc}",
        )
    _emit_result(result)
    return 0 if result.ok else 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--worker" in args:
        return worker_main()

    manager = GameModeManager()
    if "--enable" in args:
        result = manager.enable()
        print(result.message)
        for detail in result.details:
            print(f"  • {detail}")
        return 0 if result.ok else 1
    if "--disable" in args:
        result = manager.disable()
        print(result.message)
        for detail in result.details:
            print(f"  • {detail}")
        return 0 if result.ok else 1

    status = manager.status()
    if status.active:
        print("🎮 Game Mode Active")
        if status.interface:
            print(f"  Интерфейс: {status.interface}")
        if status.qdisc:
            print(f"  qdisc: {status.qdisc}")
        if status.governor:
            print(f"  governor: {status.governor}")
        if status.watchdog_stopped:
            print("  watchdog: остановлен")
        for note in status.notes:
            print(f"  • {note}")
    else:
        print("Game Mode выключен.")
        for note in status.notes:
            print(f"  • {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
