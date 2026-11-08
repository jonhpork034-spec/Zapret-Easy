"""Интеграция с современным blockcheckw (Rust).

Модуль намеренно не использует старые shell-скрипты ``blockcheck.sh`` и
``blockcheck2.sh``.  Он запускает только бинарник ``blockcheckw`` и
сохраняет найденную готовую строку аргументов nfqws2 в
``strategies/auto_best.conf``.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import signal
import statistics
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

import psutil

from src.logger import APP_DATA_DIR

logger = logging.getLogger("zapret-easy.blockcheck")

PROJECT_ROOT: Final = Path(__file__).resolve().parent.parent
SUDO_HINT: Final = (
    "Для работы без ввода пароля настройте /etc/sudoers.d/zapret-easy"
)


class SudoError(OSError):
    """sudo не установлен или не настроен для неинтерактивного запуска."""


def _sudo_auth_failed(text: str | None) -> bool:
    """Понятная проверка сообщений sudo -n вместо зависания на пароле."""
    value = (text or "").lower()
    return any(
        marker in value
        for marker in (
            "password is required",
            "a terminal is required",
            "no tty present",
            "askpass",
            "not allowed to execute",
        )
    )


def _sudo_prefix() -> list[str]:
    """Возвращает ['sudo', '-n'] для обычного пользователя."""
    if os.geteuid() == 0:
        return []
    if shutil.which("sudo") is None:
        raise SudoError(
            "sudo не найден; неинтерактивный запуск blockcheckw невозможен. "
            + SUDO_HINT
        )
    return ["sudo", "-n"]


DEFAULT_STRATEGIES_DIR: Final = PROJECT_ROOT / "strategies"
AUTO_BEST_NAME: Final = "auto_best.conf"
AUTO_BEST_META_NAME: Final = "auto_best.meta.json"
AUTO_BEST_LUA_NAME: Final = "auto_best.lua"
AUTO_BEST_BACKUP_NAME: Final = f"{AUTO_BEST_NAME}.bak"
AUTO_BEST_META_BACKUP_NAME: Final = f"{AUTO_BEST_META_NAME}.bak"
AUTO_BEST_REPORT_NAME: Final = "auto_best.report.json"
CHECK_CACHE_NAME: Final = "check_cache.json"
CHECK_CACHE_TTL: Final = 24 * 60 * 60
GOOGLE_DOMAINS: Final = (
    "youtube.com",
    "googlevideo.com",
    "google.com",
    "ytimg.com",
)
CLOUDFLARE_DOMAINS: Final = (
    "cloudflare.com",
    "cloudflare-ech.com",
    "cloudflare-dns.com",
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "discordcdn.com",
)
AMAZON_DOMAINS: Final = (
    "amazon.com",
    "amazonaws.com",
    "cloudfront.net",
    "awsstatic.com",
    "signin.aws.amazon.com",
    "s3.amazonaws.com",
    "twitch.tv",
)
OTHER_DOMAINS: Final = (
    "github.com",
    "githubusercontent.com",
    "soundcloud.com",
    "sndcdn.com",
)
STEAM_DOMAINS: Final = (
    "steampowered.com",
    "store.steampowered.com",
    "login.steampowered.com",
    "steamcommunity.com",
    "api.steampowered.com",
    "steamcontent.com",
    "steamstatic.com",
    "steamcdn-a.akamaihd.net",
    "steamusercontent.com",
    "steam-chat.com",
)
# Принудительные цели сканирования: инфраструктура YouTube/Discord,
# Cloudflare и Amazon.  Steam/Twitch убраны: их CDN может резать трафик,
# но сами домены при этом могут открываться.
DEFAULT_SCAN_DOMAINS: Final = (
    "youtube.com,discord.com,cloudflare.com,amazon.com"
)
DEFAULT_DOMAINS: Final = DEFAULT_SCAN_DOMAINS
MAX_LATENCY_TESTS: Final = 15
# Проверять найденные стратегии на всех доменах слишком долго.  Для
# интерактивного поиска достаточно нескольких представителей.
MAX_VERIFY_DOMAINS: Final = 4
LATENCY_TIMEOUT: Final = 240
# Один жёсткий дедлайн на весь поиск: scan + проверка + второй этап.
SEARCH_DEADLINE: Final = 2400.0
# Один домен и один этап. Этап не может съесть весь дедлайн: часть
# остаётся на проверку кандидатов.
SCAN_TIMEOUT: Final = 300
STAGE_SCAN_BUDGET: Final = 600
# Проверка одного этапа ограничена отдельно, иначе первый этап съедает
# весь бюджет и второй уже не запускается.
STAGE_CHECK_BUDGET: Final = 600.0
MIN_SEARCH_SECONDS: Final = 60.0
# Быстрый scan проверяет TLS 1.2: synthetic-отчёт для check всё равно
# помечает стратегии как HTTPS/TLS1.2. Это вдвое сокращает перебор.
SCAN_PROTOCOLS: Final = "tls12"
# Общий лимит проверки кандидатов, если дедлайн не передан явно.
VERIFY_TIMEOUT: Final = 600
MIN_CHECK_SECONDS: Final = 45.0
CHECK_BATCH_ESTIMATE_SECONDS: Final = 30.0
CHECK_DEADLINE: Final = 180
# 0 — проверять всех кандидатов, не останавливаться после первых прошедших.
CHECK_TAKE: Final = 0
# Для автосохранения нужна полная доставка во всех повторах.
CHECK_PASSES: Final = 3
CHECK_TIMEOUT: Final = 3
CHECK_IDLE_MS: Final = 1000
CHECK_PROTOCOL: Final = "HTTPS/TLS1.2"
# На 12-ядерной машине 8 воркеров не успевают перебрать корпус за минуту.
# blockcheckw держит стратегии профилями, поэтому 48 воркеров дешевы по памяти.
BLOCKCHECK_WORKERS: Final = 48
# Свои очередь и nft-таблица: не пересекаемся со службой zapret-easy,
# zapret2.service и параллельно запущенным blockcheckw.
BLOCKCHECK_QNUM: Final = 4510
BLOCKCHECK_NFT_TABLE: Final = "zapret-easy-scan"
BLOCKCHECK_LOCK_FILE: Final = APP_DATA_DIR / "blockcheck.lock"
CHECK_CACHE_FILE: Final = APP_DATA_DIR / CHECK_CACHE_NAME
AUTO_BEST_REPORT_FILE: Final = APP_DATA_DIR / AUTO_BEST_REPORT_NAME
ProgressCallback = Callable[[dict[str, object]], None]


@dataclass(frozen=True, slots=True)
class DomainCheckResult:
    """Результат check для одной пары «стратегия — домен».

    ``working`` — сырое поле отчёта blockcheckw.  Для выбора стратегии
    используется :attr:`confirmed`: он дополнительно требует полную
    доставку во всех повторах, положительную задержку и отсутствие
    ошибки.  Круг ``admits`` может содержать Mirage вместе с Good:
    это широкий, не суженный круг, а не доказанный Mirage; отсекается
    только круг, сузившийся ровно до ``["Mirage"]``.
    """

    domain: str
    working: bool
    passes_ok: int
    passes_total: int
    median_latency_ms: int | None
    observed: str
    admits: tuple[str, ...]
    error: str | None = None

    @property
    def confirmed(self) -> bool:
        """Стратегия действительно подтверждена для этого домена."""
        if not self.working or self.error is not None:
            return False
        if self.passes_total <= 0 or self.passes_ok != self.passes_total:
            return False
        if self.median_latency_ms is None or self.median_latency_ms <= 0:
            return False
        names = {name.casefold() for name in self.admits}
        # blockcheckw считает Mirage доказанным только когда круг сузился
        # ровно до [Mirage]. Широкий круг [Mirage, Grinding, Good] — это
        # «подлинность не установлена», а не приговор стратегии.
        if names == {"mirage"} or self.observed.casefold() == "mirage":
            return False
        return True


@dataclass(frozen=True, slots=True)
class VerifiedCandidate:
    """Кандидат с результатами проверки по всем доменам.

    Пока используется как промежуточная модель Этапа A; выбор лучшей
    стратегии для каждого домена появится на Этапе B.
    """

    args: tuple[str, ...]
    protocol: str
    complexity: int
    domains: dict[str, DomainCheckResult]


@dataclass(frozen=True, slots=True)
class DomainProfile:
    """Итоговый профиль для группы доменов (Этап C)."""

    domains: tuple[str, ...]
    args: tuple[str, ...]
    latency_ms: int | None
    complexity: int


# Стратегия -> домен -> результат check.
CheckMatrix = dict[str, dict[str, DomainCheckResult]]

# Строка стратегии от blockcheckw: начинается с -- и идёт до конца строки.
_STRATEGY_LINE_RE: Final = re.compile(r"(?m)^\s*(--[^\r\n]+?)\s*$")
# Человеческий вывод scan: "  #1 nfqws2 --filter-tcp=..." (stderr).
_NFQWS2_LINE_RE: Final = re.compile(
    r"(?m)^\s*(?:#\d+\s+)?nfqws2\s+(--[^\r\n]+?)\s*$"
)


def _strategies_dir() -> Path:
    """Возвращает каталог strategies с поддержкой тестового override."""
    override = os.environ.get("ZAPRET_EASY_STRATEGIES_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return DEFAULT_STRATEGIES_DIR


def auto_best_path() -> Path:
    """Путь к auto_best.conf; удобно для UI и тестов."""
    return _strategies_dir() / AUTO_BEST_NAME


def _json_payload(stdout: str) -> dict[str, object] | None:
    """Разбирает итоговый JSON blockcheckw, если он есть в stdout."""
    try:
        payload = json.loads(stdout)
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _json_strategies(stdout: str) -> list[str]:
    """Все стратегии из JSON-отчёта в порядке отчёта."""
    payload = _json_payload(stdout)
    if payload is None:
        return []

    found: list[str] = []
    strategies = payload.get("strategies")
    if isinstance(strategies, list):
        for entry in strategies:
            if isinstance(entry, dict):
                entry = entry.get("args")
            if isinstance(entry, str):
                line = entry.strip()
                if line.startswith("nfqws2 "):
                    line = line[len("nfqws2 ") :].strip()
                if line.startswith("--") and "\n" not in line:
                    found.append(line)

    protocols = payload.get("protocols")
    if isinstance(protocols, list):
        for protocol in protocols:
            if not isinstance(protocol, dict):
                continue
            entries = protocol.get("strategies")
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if isinstance(entry, dict):
                    entry = entry.get("args")
                if isinstance(entry, str):
                    line = entry.strip()
                    if line.startswith("nfqws2 "):
                        line = line[len("nfqws2 ") :].strip()
                    if line.startswith("--") and "\n" not in line:
                        found.append(line)

    # Сохраняем порядок отчёта, убирая повторы.
    return list(dict.fromkeys(found))


def _extract_strategies(stdout: str) -> list[str]:
    """Ищет все строки стратегий в stdout (JSON или человеческий вывод)."""
    json_lines = _json_strategies(stdout)
    if json_lines:
        return json_lines

    found = [match.strip() for match in _STRATEGY_LINE_RE.findall(stdout)]
    found.extend(match.strip() for match in _NFQWS2_LINE_RE.findall(stdout))
    return list(dict.fromkeys(found))


def _backup_auto_best(strategies_dir: Path) -> None:
    """Сохраняет текущий auto_best.conf и meta перед заменой.

    Бэкап нужен для отката, если новый конфиг не пройдёт dry-run,
    служба не запустится или hash/meta окажутся неверными.
    """
    conf_path = strategies_dir / AUTO_BEST_NAME
    meta_path = strategies_dir / AUTO_BEST_META_NAME
    backup_path = strategies_dir / AUTO_BEST_BACKUP_NAME
    meta_backup_path = strategies_dir / AUTO_BEST_META_BACKUP_NAME

    if not conf_path.is_file():
        backup_path.unlink(missing_ok=True)
        meta_backup_path.unlink(missing_ok=True)
        return

    shutil.copy2(conf_path, backup_path)
    if meta_path.is_file():
        shutil.copy2(meta_path, meta_backup_path)
    else:
        # Не оставляем старый meta-бэкап от предыдущего конфига.
        meta_backup_path.unlink(missing_ok=True)


def _restore_auto_best_backup(strategies_dir: Path) -> bool:
    """Восстанавливает auto_best.conf и meta из .bak. True — успех."""
    backup_path = strategies_dir / AUTO_BEST_BACKUP_NAME
    if not backup_path.is_file():
        return False

    conf_path = strategies_dir / AUTO_BEST_NAME
    meta_path = strategies_dir / AUTO_BEST_META_NAME
    meta_backup_path = strategies_dir / AUTO_BEST_META_BACKUP_NAME

    shutil.copy2(backup_path, conf_path)
    if meta_backup_path.is_file():
        shutil.copy2(meta_backup_path, meta_path)
    else:
        meta_path.unlink(missing_ok=True)
    return True


def _save_strategy(
    strategy_line: str,
    *,
    profiles: dict[str, VerifiedCandidate] | None = None,
) -> tuple[bool, str]:
    strategies_dir = _strategies_dir()
    if profiles is None:
        # Сохраняем уже готовую для службы строку: фильтр портов
        # добавляется здесь, а не при каждом применении.
        strategy_line = _with_firewall_filters(strategy_line)

    config_text = strategy_line.rstrip("\n") + "\n"
    try:
        _backup_auto_best(strategies_dir)
        strategies_dir.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{AUTO_BEST_NAME}.",
            suffix=".tmp",
            dir=strategies_dir,
        )
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(config_text)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_path, 0o644)
            os.replace(temp_path, strategies_dir / AUTO_BEST_NAME)
        except OSError:
            temp_path.unlink(missing_ok=True)
            raise

        if profiles is None:
            meta = {
                "verified": True,
                "strategy": config_text.strip(),
                "saved_at": time.time(),
            }
            meta_path = strategies_dir / AUTO_BEST_META_NAME
            meta_path.write_text(
                json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            os.chmod(meta_path, 0o644)
        else:
            _save_auto_best_meta(
                profiles,
                config_text,
                strategies_dir / AUTO_BEST_NAME,
            )
    except OSError as exc:
        logger.warning("Не удалось сохранить auto_best.conf: %s", exc)
        return False, f"Не удалось сохранить auto_best.conf: {exc}"

    if profiles is None:
        logger.info(
            "blockcheckw сохранил подтверждённую стратегию в auto_best.conf"
        )
        return (
            True,
            "Подтверждённая стратегия сохранена в auto_best.conf",
        )

    logger.info(
        "blockcheckw сохранил composite-конфиг в auto_best.conf "
        "(доменов: %d)",
        len(profiles),
    )
    return (
        True,
        "Composite-конфиг сохранён в auto_best.conf",
    )


def _common_command() -> list[str]:
    """Чистая команда blockcheckw через неинтерактивный sudo -n."""
    binary = shutil.which("blockcheckw") or "blockcheckw"
    return [
        *_sudo_prefix(),
        binary,
        "--embedded",
        "--auto",
        "--progress",
        "--workers",
        str(BLOCKCHECK_WORKERS),
        "--qnum",
        str(BLOCKCHECK_QNUM),
        "--nft-table",
        BLOCKCHECK_NFT_TABLE,
    ]


def _status_command(domain_list: str) -> list[str]:
    """Чистая команда blockcheckw status через sudo -n."""
    return [
        *_common_command(),
        "status",
        "--domain-list",
        domain_list,
    ]


def _universal_command(domain_list: str) -> list[str]:
    """Чистая команда blockcheckw universal через sudo -n."""
    return [
        *_common_command(),
        "universal",
        "--domain-list",
        domain_list,
    ]


def _scan_command(domains: str, timeout_secs: int) -> list[str]:
    """Команда blockcheckw scan с внутренним лимитом времени.

    ``--timeout`` важен не только для скорости: blockcheckw сам завершает
    скан и пишет частичный JSON.  Внешний kill через sudo -n ненадёжен, если
    дочерний процесс уже работает от root.
    """
    return [
        *_common_command(),
        "scan",
        "-d",
        domains,
        "--protocols",
        SCAN_PROTOCOLS,
        "--timeout",
        str(max(1, timeout_secs)),
    ]


def _check_command(
    report_path: Path,
    domain: str,
    *,
    deadline_secs: int = CHECK_DEADLINE,
    take: int = CHECK_TAKE,
) -> list[str]:
    """Команда blockcheckw check для проверки стратегий реальной загрузкой."""
    return [
        *_common_command(),
        "check",
        "--from-file",
        str(report_path),
        "-d",
        domain,
        "--timeout",
        str(CHECK_TIMEOUT),
        "--idle-ms",
        str(CHECK_IDLE_MS),
        "--passes",
        str(CHECK_PASSES),
        "--take",
        str(max(0, take)),
        "--deadline",
        str(max(1, deadline_secs)),
    ]


class BlockcheckBusy(RuntimeError):
    """Автопоиск уже выполняется в этом или другом процессе."""


@contextlib.contextmanager
def _blockcheck_lock():
    """Не даёт двум TUI одновременно запустить сканирование."""
    try:
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        handle = BLOCKCHECK_LOCK_FILE.open("a+", encoding="utf-8")
    except OSError as exc:
        raise BlockcheckBusy(
            f"Не удалось открыть lock-файл автопоиска: {exc}"
        ) from exc
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BlockcheckBusy(
                "Автопоиск уже выполняется в другом окне zapret-easy."
            ) from exc
        except OSError as exc:
            raise BlockcheckBusy(
                f"Не удалось заблокировать автопоиск: {exc}"
            ) from exc
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _other_blockcheck_process() -> tuple[int, str] | None:
    """Ищет уже запущенный blockcheckw, чтобы не конфликтовать за NFQUEUE."""
    try:
        processes = psutil.process_iter(["pid", "name", "cmdline"])
    except (psutil.Error, OSError):
        return None
    for process in processes:
        try:
            info = process.info
            name = (info.get("name") or "").lower()
            cmdline = info.get("cmdline") or []
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        argv0 = Path(str(cmdline[0])).name.lower() if cmdline else ""
        if name != "blockcheckw" and argv0 != "blockcheckw":
            continue
        arguments = {str(part) for part in cmdline[1:]}
        if not arguments & {"scan", "check", "status", "universal", "benchmark"}:
            # --version/--help не занимают NFQUEUE и не конфликтуют.
            continue
        pid = int(info.get("pid") or process.pid)
        command = " ".join(str(part) for part in cmdline[:3])
        return pid, command
    return None


class ScanCancelled(Exception):
    """Пользователь прервал сканирование через Ctrl+C."""


def _emit_progress(
    on_progress: ProgressCallback | None,
    **event: object,
) -> None:
    if on_progress is None:
        return
    try:
        on_progress(event)
    except Exception:
        logger.exception("Ошибка обработчика прогресса blockcheckw")


def _terminate_process(proc: subprocess.Popen[str]) -> None:
    """Останавливает sudo -n и его дочерний blockcheckw."""
    with contextlib.suppress(OSError, ProcessLookupError):
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    with contextlib.suppress(OSError, ProcessLookupError):
        proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError, ProcessLookupError):
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        with contextlib.suppress(OSError, ProcessLookupError):
            proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=2)


_ANSI_RE: Final = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_PERCENT_RE: Final = re.compile(r"(?<!\d)(\d{1,3})\s*%")


def _progress_int(value: object) -> int:
    """Безопасно приводит поле прогресса blockcheckw к int."""
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _handle_progress_line(
    raw_line: str,
    on_progress: ProgressCallback | None,
) -> None:
    """Преобразует строку stderr blockcheckw в событие прогресса."""
    line = _ANSI_RE.sub("", raw_line).replace("\r", "").strip()
    if not line:
        return

    if line.startswith("{"):
        try:
            payload = json.loads(line)
        except ValueError:
            payload = None
        if isinstance(payload, dict) and payload.get("event") == "progress":
            done = _progress_int(payload.get("done"))
            total = _progress_int(payload.get("total"))
            percent = min(100, max(0, int(done * 100 / total))) if total else None
            _emit_progress(
                on_progress,
                event="progress",
                done=done,
                total=total,
                percent=percent,
                phase=str(payload.get("phase") or "scan"),
                message=f"Сканирование: {percent}%" if percent is not None else "",
            )
            return

    match = _PERCENT_RE.search(line)
    if match is not None:
        percent = min(100, max(0, int(match.group(1))))
        _emit_progress(
            on_progress,
            event="progress",
            percent=percent,
            message=f"Сканирование: {percent}%",
        )
        return

    interesting = (
        "Scanning",
        "[START]",
        "strategies",
        "Baseline",
        "Summary",
        "timed out",
        "prerequisites",
        "DNS",
        "progress",
    )
    if any(marker in line for marker in interesting):
        _emit_progress(
            on_progress,
            event="status",
            message=line[:240],
        )


def _run_blockcheck_command(
    command: list[str],
    on_progress: ProgressCallback | None = None,
    *,
    timeout: float = SCAN_TIMEOUT + 30,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    logger.debug("Запуск blockcheckw: %s", shlex.join(command))
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        bufsize=1,
        start_new_session=True,
        cwd=cwd,
    )

    assert proc.stdout is not None
    assert proc.stderr is not None
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    timed_out = threading.Event()

    def read_stdout() -> None:
        try:
            stdout_chunks.extend(proc.stdout)
        except (OSError, ValueError):
            pass

    def stop_on_timeout() -> None:
        timed_out.set()
        _terminate_process(proc)

    stdout_thread = threading.Thread(
        target=read_stdout,
        name="blockcheckw-stdout",
        daemon=True,
    )
    stdout_thread.start()
    watchdog = threading.Timer(timeout, stop_on_timeout)
    watchdog.daemon = True
    watchdog.start()

    _emit_progress(
        on_progress,
        event="status",
        message="Запуск blockcheckw...",
    )
    try:
        for line in iter(proc.stderr.readline, ""):
            stderr_chunks.append(line)
            _handle_progress_line(line, on_progress)
        proc.wait(timeout=5)
    except KeyboardInterrupt:
        _terminate_process(proc)
        raise ScanCancelled from None
    except subprocess.TimeoutExpired:
        _terminate_process(proc)
    finally:
        watchdog.cancel()
        if proc.poll() is None:
            _terminate_process(proc)
        with contextlib.suppress(OSError):
            proc.stderr.close()
        stdout_thread.join(timeout=5)
        with contextlib.suppress(OSError):
            proc.stdout.close()

    if timed_out.is_set():
        raise subprocess.TimeoutExpired(command, timeout)

    stderr_text = "".join(stderr_chunks)
    if _sudo_auth_failed(stderr_text):
        raise SudoError(SUDO_HINT)

    return subprocess.CompletedProcess(
        command,
        proc.returncode if proc.returncode is not None else -1,
        "".join(stdout_chunks),
        stderr_text,
    )


def _scan_once(
    domain: str,
    on_progress: ProgressCallback | None = None,
    *,
    timeout_secs: int = SCAN_TIMEOUT,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Один ограниченный по времени скан домена."""
    return _run_blockcheck_command(
        _scan_command(domain, timeout_secs),
        on_progress,
        timeout=timeout_secs + 30,
        cwd=cwd,
    )


def _scan_for_strategies(
    domains: list[str],
    directory: Path,
    on_progress: ProgressCallback | None = None,
    *,
    budget_secs: float = STAGE_SCAN_BUDGET,
) -> tuple[
    list[str],
    subprocess.CompletedProcess[str] | None,
    dict[str, object] | None,
]:
    """Ограниченный по времени поиск стратегий по списку доменов.

    Используется обычный ``scan`` с внутренним ``--timeout``: он умеет
    завершаться сам и отдавать частичный JSON. Домены не пропускаются по
    числу найденных стратегий: после сканирования кандидаты сортируются по
    покрытию доменов, чтобы в проверку попали лучшие представители.
    """
    deadline = time.monotonic() + budget_secs
    found_by_domain: list[list[str]] = []
    last_completed: subprocess.CompletedProcess[str] | None = None
    last_payload: dict[str, object] | None = None
    scanned = 0

    for index, domain in enumerate(domains, start=1):
        remaining = deadline - time.monotonic()
        if remaining < 10:
            logger.info(
                "Поиск стратегий остановлен по общему дедлайну: "
                "проверено доменов: %d",
                scanned,
            )
            break

        timeout_secs = max(1, min(SCAN_TIMEOUT, int(remaining)))
        _emit_progress(
            on_progress,
            event="status",
            message=(
                f"Сканирую {domain} ({index}/{len(domains)}, "
                f"лимит {timeout_secs} с)..."
            ),
        )
        try:
            completed = _scan_once(
                domain,
                on_progress,
                timeout_secs=timeout_secs,
                cwd=directory,
            )
        except subprocess.TimeoutExpired:
            # Внутренний --timeout должен был сработать раньше; сюда
            # попадаем только при зависании процесса.
            scanned += 1
            logger.warning(
                "blockcheckw scan для %s не завершился за %d с",
                domain,
                timeout_secs + 30,
            )
            continue

        scanned += 1
        if completed.returncode != 0:
            logger.warning(
                "blockcheckw scan для %s завершился с кодом %s: %s",
                domain,
                completed.returncode,
                _output_tail(completed, limit=500),
            )

        last_completed = completed
        report_text = completed.stdout or ""
        last_payload = _json_payload(report_text)
        domain_seen: set[str] = set()
        domain_found: list[str] = []
        for strategy in _extract_strategies(report_text):
            if strategy in domain_seen:
                continue
            domain_seen.add(strategy)
            domain_found.append(strategy)
        found_by_domain.append(domain_found)

        _emit_progress(
            on_progress,
            event="status",
            message=(
                f"{domain}: найдено уникальных стратегий: "
                f"{sum(len(items) for items in found_by_domain)}"
            ),
        )

    # Чередуем кандидатов: первый из каждого домена, затем второй и т.д.
    interleaved: list[str] = []
    longest = max((len(items) for items in found_by_domain), default=0)
    for offset in range(longest):
        for items in found_by_domain:
            if offset < len(items):
                interleaved.append(items[offset])

    # Стратегии, найденные сразу на нескольких доменах, проверяем первыми:
    # именно они чаще всего оказываются реально универсальными. При равном
    # покрытии сохраняется исходный порядок сканирования.
    coverage: dict[str, int] = {}
    for items in found_by_domain:
        for strategy in items:
            coverage[strategy] = coverage.get(strategy, 0) + 1
    unique_interleaved = list(dict.fromkeys(interleaved))
    order = {
        strategy: index
        for index, strategy in enumerate(unique_interleaved)
    }
    found = sorted(
        unique_interleaved,
        key=lambda strategy: (-coverage[strategy], order[strategy]),
    )

    logger.info(
        "blockcheckw scan: доменов: %d, уникальных стратегий: %d, "
        "максимальное покрытие: %d/%d",
        scanned,
        len(found),
        max(coverage.values(), default=0),
        max(len(found_by_domain), 1),
    )
    return found, last_completed, last_payload


def _output_tail(
    completed: subprocess.CompletedProcess[str],
    limit: int = 1200,
) -> str:
    """Короткий хвост stderr/stdout для сообщения об ошибке."""
    text = (completed.stderr or "").strip() or (completed.stdout or "").strip()
    text = _ANSI_RE.sub("", text)
    if len(text) > limit:
        text = "…" + text[-limit:]
    return text


def _payload_outcome(payload: dict[str, object]) -> str:
    """Достаёт outcome из нового и старого формата blockcheckw."""
    outcome = payload.get("outcome")
    if isinstance(outcome, dict):
        outcome = outcome.get("outcome")
    return str(outcome or "")


def _payload_is_not_blocked(payload: object) -> bool:
    """True, если отчёт говорит «контроль без десинка прошёл»."""
    if not isinstance(payload, dict):
        return False
    return (
        _payload_outcome(payload) == "not_blocked"
        or payload.get("block_type") == "not_blocked"
    )


def _final_stage_message(
    stage_results: list[tuple[tuple[str, ...], str, bool]],
    default: str,
) -> str:
    """Не даёт «сайт не заблокирован» перекрыть реальную ошибку этапа."""
    blocked_results = [item for item in stage_results if not item[2]]
    accessible_results = [item for item in stage_results if item[2]]
    if blocked_results:
        blocked_domains = ", ".join(blocked_results[0][0])
        message = blocked_results[0][1]
        if blocked_domains:
            message += (
                f"\n\nНе удалось подтвердить стратегии для: {blocked_domains}."
            )
        if accessible_results:
            accessible_domains = ", ".join(
                domain
                for domains, _message, _flag in accessible_results
                for domain in domains
            )
            message += (
                f"\n\nДля {accessible_domains} blockcheckw не обнаружил "
                "блокировку — стратегия для них не требуется."
            )
        return message
    if accessible_results:
        return accessible_results[-1][1]
    return default


def _json_no_strategy_message(
    payload: dict[str, object],
) -> str | None:
    """Объясняет пустой strategies[] по полям отчёта blockcheckw."""
    outcome = _payload_outcome(payload)
    block_type = payload.get("block_type")
    block_label = {
        "ip_blocked": "IP-адрес заблокирован",
        "not_blocked": "сайт не заблокирован",
        "sni_blocked": "блокировка SNI/TLS",
        "dns_failed": "DNS не разрешил домен",
    }.get(str(block_type), str(block_type or "тип блокировки неизвестен"))

    if _payload_is_not_blocked(payload):
        return (
            "blockcheckw не обнаружил блокировку: "
            "сайт доступен без обхода. Стратегия не требуется."
        )

    if outcome == "censored":
        limit_name = payload.get("limit")
        if limit_name == "deadline":
            return (
                f"blockcheckw не успел перебрать стратегии за "
                f"{SCAN_TIMEOUT} секунд и вернул частичный отчёт. "
                "Рабочих стратегий в нём пока нет. Попробуйте запустить "
                "поиск ещё раз — возможно, в этот раз сканирование успеет."
            )
        return (
            "blockcheckw остановил подбор раньше времени "
            f"(предел: {limit_name or 'неизвестен'}), рабочих стратегий "
            "в отчёте нет."
        )

    if outcome == "nothing_works":
        candidates = payload.get("candidates") or payload.get("total")
        suffix = f" (проверено {candidates})" if candidates else ""
        return (
            f"blockcheckw перебрал доступные стратегии{suffix}, но ни одна "
            f"не прошла проверку. Диагноз: {block_label}."
        )

    if outcome == "broken":
        reason = payload.get("reason")
        if isinstance(reason, dict):
            reason = next(iter(reason), None)
        reason_text = {
            "dns_failed": "DNS не смог разрешить домен.",
            "no_cap_net_admin": "нет прав CAP_NET_ADMIN (нужен root).",
            "engine_start": "nfqws2 не запустился или не занял NFQUEUE.",
            "nft": "nftables отклонил правила сканера.",
            "input_unreadable": "не удалось прочитать входной файл стратегий.",
        }.get(str(reason))
        if str(reason).startswith("queue_busy"):
            reason_text = "очередь NFQUEUE занята другим процессом."
        return (
            "blockcheckw не смог выполнить сканирование: "
            f"{reason_text or reason or 'неизвестная ошибка инструмента'}"
        )

    return None


def _no_strategy_message(
    completed: subprocess.CompletedProcess[str],
    *,
    payload: dict[str, object] | None = None,
) -> str:
    """Понятное объяснение вместо общего «стратегия не найдена»."""
    if payload is None:
        payload = _json_payload(completed.stdout or "")
    if payload is not None:
        message = _json_no_strategy_message(payload)
        if message is not None:
            return message

    stderr = completed.stderr or ""
    if _sudo_auth_failed(stderr) or completed.returncode in (126, 127):
        return SUDO_HINT
    if "root is required" in stderr or "sudo:" in stderr:
        return (
            "blockcheckw не смог получить root-права через sudo -n. "
            + SUDO_HINT
        )

    details = _output_tail(completed)
    message = (
        f"blockcheckw завершился с кодом {completed.returncode}, "
        "но не вернул стратегию."
    )
    if details:
        message += f"\n\nВывод blockcheckw:\n{details}"
    return message


def _control_names(value: object) -> set[str]:
    """Приводит ``fate``/``admits``/``observed`` к набору имён в нижнем регистре."""
    names: set[str] = set()
    if isinstance(value, str):
        names.add(value.strip().lower())
    elif isinstance(value, dict):
        for key, item in value.items():
            if item is False or item is None:
                continue
            names.add(str(key).strip().lower())
            names.update(_control_names(item))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            names.update(_control_names(item))
    return names


def _is_mirage(entry: dict[str, object]) -> bool:
    """Отсекает доказанный Mirage: круг сузился ровно до ``["Mirage"]``.

    В актуальной схеме ``check`` ``admits`` — это КРУГ возможных судеб.
    Широкий круг ``["Mirage", "Grinding", "Good"]`` означает, что
    подлинность не установлена, и не должен хоронить рабочую стратегию.
    Булев ``admits == false`` и старое поле ``fate`` поддерживаем для
    совместимости.
    """
    admits = entry.get("admits")
    if admits is False:
        return True

    names = _control_names(admits)
    if names:
        return names == {"mirage"}

    fate = _control_names(entry.get("fate"))
    observed = _control_names(entry.get("observed"))
    return fate == {"mirage"} or observed == {"mirage"}


def _entry_int(
    entry: dict[str, object],
    key: str,
    default: int = 0,
) -> int:
    """Читает целое поле отчёта, не падая на неожиданном типе."""
    value = entry.get(key)
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def _entry_str(entry: dict[str, object], key: str, default: str = "") -> str:
    value = entry.get(key)
    return value if isinstance(value, str) else default


def _entry_admits(entry: dict[str, object]) -> tuple[str, ...]:
    """Возвращает admits строки check, добавляя Mirage для старых схем."""
    raw = entry.get("admits")
    if isinstance(raw, str):
        names = [raw]
    elif isinstance(raw, (list, tuple)):
        names = [item for item in raw if isinstance(item, str)]
    elif isinstance(raw, dict):
        names = [str(key) for key, value in raw.items() if value]
    else:
        names = []

    if _is_mirage(entry) and "mirage" not in {
        name.casefold() for name in names
    }:
        names.append("Mirage")
    return tuple(names)


def _parse_domain_result(
    domain: str,
    entry: object,
) -> DomainCheckResult:
    """Преобразует строку check в результат для одного домена."""
    if not isinstance(entry, dict):
        return DomainCheckResult(
            domain=domain,
            working=False,
            passes_ok=0,
            passes_total=0,
            median_latency_ms=None,
            observed="",
            admits=(),
            error="стратегия отсутствует в отчёте check",
        )

    raw_working = entry.get("working")
    working = raw_working is True or (
        isinstance(raw_working, int)
        and not isinstance(raw_working, bool)
        and raw_working != 0
    )
    latency = _entry_int(entry, "median_latency_ms", 0)
    raw_error = entry.get("error")
    error = (
        raw_error.strip()
        if isinstance(raw_error, str) and raw_error.strip()
        else None
    )

    return DomainCheckResult(
        domain=domain,
        working=working,
        passes_ok=_entry_int(entry, "passes_ok", 0),
        passes_total=_entry_int(entry, "passes_total", 0),
        median_latency_ms=latency if latency > 0 else None,
        observed=_entry_str(entry, "observed"),
        admits=_entry_admits(entry),
        error=error,
    )


def _failed_domain_result(
    domain: str,
    message: str,
) -> DomainCheckResult:
    """Результат-ошибка для домена, который не удалось проверить."""
    return DomainCheckResult(
        domain=domain,
        working=False,
        passes_ok=0,
        passes_total=0,
        median_latency_ms=None,
        observed="",
        admits=(),
        error=message,
    )


def _log_matrix_preview(matrix: CheckMatrix, *, limit: int = 3) -> None:
    """Пишет в лог первые строки матрицы — для отладки Этапа A."""
    if not matrix:
        logger.info("Матрица check: пусто")
        return

    lines: list[str] = []
    for strategy, by_domain in list(matrix.items())[:limit]:
        short = strategy if len(strategy) <= 160 else strategy[:160] + "…"
        parts = [
            (
                f"{domain}: working={result.working} "
                f"passes={result.passes_ok}/{result.passes_total} "
                f"latency={result.median_latency_ms} "
                f"admits={','.join(result.admits) or '—'} "
                f"confirmed={result.confirmed}"
            )
            for domain, result in by_domain.items()
        ]
        lines.append(f"{short} -> " + "; ".join(parts))

    logger.info(
        "Матрица check: стратегий %d, первые %d:\n%s",
        len(matrix),
        len(lines),
        "\n".join(lines),
    )


def _aggregate_measurements(
    matrix: CheckMatrix,
    domains: list[str],
) -> list[tuple[int, list[int], str]]:
    """Переводит матрицу в старый агрегат для текущего выбора победителя.

    Это временный мост Этапа A: сохранение auto_best.conf не меняется.
    На Этапе B выбор станет per-domain и этот агрегат будет удалён.
    """
    verify_domains = list(dict.fromkeys(domains))
    measured: list[tuple[int, list[int], str]] = []
    for strategy, by_domain in matrix.items():
        latencies: list[int] = []
        for domain in verify_domains:
            result = by_domain.get(domain)
            if result is None or not result.confirmed:
                continue
            latency = result.median_latency_ms
            if latency is not None and latency > 0:
                latencies.append(latency)
        if not latencies:
            continue
        failed = len(verify_domains) - len(latencies)
        measured.append((failed, latencies, strategy))
    return measured


def _cache_key(strategy: str, domain: str) -> str:
    return f"{strategy}||{domain}"


def _load_check_cache() -> dict[str, object]:
    """Читает check_cache.json. Любая ошибка означает пустой кэш."""
    try:
        payload = json.loads(
            CHECK_CACHE_FILE.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _save_check_cache(cache: dict[str, object]) -> None:
    """Атомарно пишет кэш; ошибки записи игнорируются."""
    try:
        CHECK_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{CHECK_CACHE_FILE.name}.",
            suffix=".tmp",
            dir=CHECK_CACHE_FILE.parent,
        )
    except OSError as exc:
        logger.debug("Не удалось подготовить кэш check: %s", exc)
        return

    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(cache, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, CHECK_CACHE_FILE)
    except (OSError, TypeError, ValueError) as exc:
        temp_path.unlink(missing_ok=True)
        logger.debug("Не удалось записать кэш check: %s", exc)


def _cached_domain_result(
    domain: str,
    entry: object,
    now: float,
) -> DomainCheckResult | None:
    """Возвращает свежий подтверждённый результат из кэша, если он есть."""
    if not isinstance(entry, dict):
        return None

    raw_timestamp = entry.get("timestamp")
    if isinstance(raw_timestamp, bool) or not isinstance(
        raw_timestamp, (int, float)
    ):
        return None
    age = now - float(raw_timestamp)
    if age > CHECK_CACHE_TTL:
        return None

    if entry.get("working") is not True:
        return None

    passes_ok = _entry_int(entry, "passes_ok", 0)
    passes_total = _entry_int(entry, "passes_total", passes_ok)
    latency = _entry_int(entry, "median_latency_ms", 0)
    if (
        passes_ok <= 0
        or passes_total != passes_ok
        or latency <= 0
    ):
        return None

    result = DomainCheckResult(
        domain=domain,
        working=True,
        passes_ok=passes_ok,
        passes_total=passes_total,
        median_latency_ms=latency,
        observed=_entry_str(entry, "observed", "cache"),
        admits=_entry_admits(entry),
        error=None,
    )
    return result if result.confirmed else None


def _store_check_cache_result(
    cache: dict[str, object],
    strategy: str,
    domain: str,
    result: DomainCheckResult,
) -> None:
    """Кладёт в кэш только подтверждённые результаты."""
    if not result.confirmed:
        return
    cache[_cache_key(strategy, domain)] = {
        "working": True,
        "passes_ok": result.passes_ok,
        "passes_total": result.passes_total,
        "median_latency_ms": result.median_latency_ms,
        "observed": result.observed,
        "admits": list(result.admits),
        "timestamp": time.time(),
    }


def measure_latency(
    strategies: list[str],
    domains: list[str],
    on_progress: ProgressCallback | None = None,
    *,
    deadline: float | None = None,
) -> CheckMatrix:
    """Меряет задержки через blockcheckw check с общим дедлайном.

    Проверяются только первые ``MAX_VERIFY_DOMAINS`` доменов.  Если
    передан общий ``deadline``, он ограничивает и весь этот вызов;
    иначе используется ``VERIFY_TIMEOUT``.

    Свежие подтверждённые результаты берутся из check_cache.json и не
    отправляются в blockcheckw повторно.  Возвращает матрицу
    ``стратегия -> домен -> DomainCheckResult``.  Если один из доменов
    не успел провериться, его клетки получают ``error``, а
    подтверждённые результаты остальных доменов сохраняются для
    per-domain выбора.
    """
    candidates = list(dict.fromkeys(strategies))[:MAX_LATENCY_TESTS]
    verify_domains = list(dict.fromkeys(domains))[:MAX_VERIFY_DOMAINS]
    if not candidates or not verify_domains:
        return {}
    if deadline is None:
        deadline = time.monotonic() + VERIFY_TIMEOUT

    cache = _load_check_cache()
    matrix: CheckMatrix = {strategy: {} for strategy in candidates}
    checked_domains = 0
    domain_errors: list[str] = []
    try:
        for index, domain in enumerate(verify_domains, start=1):
            remaining = deadline - time.monotonic()
            if remaining < 10:
                logger.info(
                    "Проверка стратегий остановлена по дедлайну: "
                    "проверено доменов: %d",
                    checked_domains,
                )
                break

            probe_deadline = max(5, min(CHECK_DEADLINE, int(remaining)))
            _emit_progress(
                on_progress,
                event="latency",
                done=index - 1,
                total=len(verify_domains),
                message=f"Замер {index}/{len(verify_domains)}: {domain}",
            )

            now = time.time()
            pending: list[str] = []
            cached_count = 0
            for strategy in candidates:
                cached = _cached_domain_result(
                    domain,
                    cache.get(_cache_key(strategy, domain)),
                    now,
                )
                if cached is not None:
                    matrix[strategy][domain] = cached
                    cached_count += 1
                else:
                    pending.append(strategy)

            if cached_count:
                logger.info(
                    "check для %s: из кэша %d/%d стратегий",
                    domain,
                    cached_count,
                    len(candidates),
                )

            if not pending:
                checked_domains += 1
                _emit_progress(
                    on_progress,
                    event="latency",
                    done=index,
                    total=len(verify_domains),
                    message=f"Замер {index}/{len(verify_domains)} завершён",
                )
                continue

            report = {
                "schema": 1,
                "strategies": [
                    {
                        "protocol": CHECK_PROTOCOL,
                        "args": strategy,
                        "coverage": 1,
                    }
                    for strategy in pending
                ],
            }
            report_path: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    prefix="zapret-easy-latency-",
                    suffix=".json",
                    delete=False,
                    encoding="utf-8",
                ) as report_file:
                    report_path = Path(report_file.name)
                    json.dump(report, report_file, ensure_ascii=False)
            except (OSError, TypeError, ValueError) as exc:
                if report_path is not None:
                    with contextlib.suppress(OSError):
                        report_path.unlink()
                message = (
                    f"не удалось подготовить check для {domain}: {exc}"
                )
                logger.warning(message)
                domain_errors.append(message)
                for strategy in pending:
                    matrix[strategy][domain] = _failed_domain_result(
                        domain,
                        message,
                    )
                continue

            try:
                completed = _run_blockcheck_command(
                    _check_command(
                        report_path,
                        domain,
                        deadline_secs=probe_deadline,
                    ),
                    on_progress,
                    timeout=max(5.0, min(LATENCY_TIMEOUT, remaining)),
                )
            except subprocess.TimeoutExpired:
                message = f"таймаут check для {domain}"
                logger.warning(message)
                domain_errors.append(message)
                for strategy in pending:
                    matrix[strategy][domain] = _failed_domain_result(
                        domain,
                        message,
                    )
                continue
            except OSError as exc:
                message = f"не удалось запустить check для {domain}: {exc}"
                logger.warning(message)
                domain_errors.append(message)
                for strategy in pending:
                    matrix[strategy][domain] = _failed_domain_result(
                        domain,
                        message,
                    )
                continue
            finally:
                with contextlib.suppress(OSError):
                    report_path.unlink()

            payload = _json_payload(completed.stdout or "")
            if payload is None:
                message = f"check для {domain} вернул не JSON"
                logger.warning(message)
                domain_errors.append(message)
                for strategy in pending:
                    matrix[strategy][domain] = _failed_domain_result(
                        domain,
                        message,
                    )
                continue

            if _payload_is_not_blocked(payload) or payload.get(
                "inconclusive"
            ) is True:
                # Контроль без десинка прошёл: домен на этой линии не
                # режется. Его «рабочие» строки ничего не доказывают,
                # поэтому не даём им попасть в профили.
                message = (
                    f"{domain}: blockcheckw не обнаружил блокировку "
                    "(доступен без обхода)"
                )
                logger.info(message)
                for strategy in candidates:
                    matrix[strategy][domain] = _failed_domain_result(
                        domain,
                        message,
                    )
                    cache.pop(_cache_key(strategy, domain), None)
                _save_check_cache(cache)
                checked_domains += 1
                _emit_progress(
                    on_progress,
                    event="latency",
                    done=index,
                    total=len(verify_domains),
                    message=f"Замер {index}/{len(verify_domains)} завершён",
                )
                continue

            checked_domains += 1
            entries = payload.get("strategies")
            by_args: dict[str, dict[str, object]] = {}
            if isinstance(entries, list):
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    args = entry.get("args")
                    if isinstance(args, str):
                        args = args.strip()
                        if args.startswith("nfqws2 "):
                            args = args[len("nfqws2 ") :].strip()
                        by_args[args] = entry

            for strategy in pending:
                result = _parse_domain_result(
                    domain,
                    by_args.get(strategy),
                )
                matrix[strategy][domain] = result
                _store_check_cache_result(
                    cache,
                    strategy,
                    domain,
                    result,
                )
            _save_check_cache(cache)

            _emit_progress(
                on_progress,
                event="latency",
                done=index,
                total=len(verify_domains),
                message=f"Замер {index}/{len(verify_domains)} завершён",
            )
    except KeyboardInterrupt:
        raise ScanCancelled from None

    if domain_errors or checked_domains < len(verify_domains):
        details = (
            " Ошибки: " + "; ".join(domain_errors)
            if domain_errors
            else ""
        )
        logger.warning(
            "Проверка check не завершилась на всех доменах (%d/%d); "
            "подтверждённые per-domain результаты сохранены.%s",
            checked_domains,
            len(verify_domains),
            details,
        )

    _log_matrix_preview(matrix)
    return matrix


def _strategy_args(strategy: str) -> tuple[str, ...]:
    """Разбирает args blockcheckw без shell-интерпретации кавычек.

    blockcheckw формирует строку как ``tokens.join(" ")``; кавычки внутри
    inline-Lua (например ``tls_mod(fake_default_tls,'rnd')``) являются
    частью значения.  ``shlex.split`` их съедает, после чего nfqws2
    получает ``tls_mod(fake_default_tls,rnd)`` и падает с LUA ERROR.
    """
    args = tuple(part for part in strategy.split() if part)
    return args or (strategy,)


def _select_best_per_domain(
    matrix: CheckMatrix,
    domains: list[str],
) -> dict[str, VerifiedCandidate]:
    """Выбирает лучшую подтверждённую стратегию для каждого домена.

    Приоритеты:
    1. больше ``passes_ok`` — стабильность;
    2. меньше ``median_latency_ms`` — скорость;
    3. меньше ``complexity`` (пока ``len(args)``);
    4. лексикографический порядок строки — детерминированность.

    Домены без подтверждённых стратегий в результат не попадают.
    Сохранение auto_best.conf на этом этапе не меняется.
    """
    parsed_args = {
        strategy: _strategy_args(strategy) for strategy in matrix
    }
    selected: dict[str, VerifiedCandidate] = {}

    for domain in dict.fromkeys(domains):
        best_strategy: str | None = None
        best_args: tuple[str, ...] = ()
        best_key: tuple[int, int, int, str] | None = None

        for strategy, by_domain in matrix.items():
            result = by_domain.get(domain)
            if result is None or not result.confirmed:
                continue
            latency = result.median_latency_ms
            if latency is None:
                continue

            args = parsed_args[strategy]
            key = (
                -result.passes_ok,
                latency,
                len(args),
                strategy.casefold(),
            )
            if best_key is None or key < best_key:
                best_key = key
                best_strategy = strategy
                best_args = args

        if best_strategy is None:
            continue

        selected[domain] = VerifiedCandidate(
            args=best_args,
            protocol=CHECK_PROTOCOL,
            complexity=len(best_args),
            domains=dict(matrix[best_strategy]),
        )

    return selected


def _ensure_l7_filter(args: tuple[str, ...]) -> tuple[str, ...]:
    """Добавляет --filter-l7, иначе --hostlist-domains не применяется.

    hostlist в nfqws2 фильтрует уже распознанный L7-протокол. Без
    --filter-l7 профиль с hostlist может не применить десинк вообще.
    """
    if any(arg.startswith("--filter-l7=") for arg in args):
        return args

    joined = " ".join(args)
    if "--payload=http_req" in joined:
        l7 = "http"
    elif re.search(r"--payload=(?:[^ ]*,)?quic", joined):
        l7 = "quic"
    elif "tls_client_hello" in joined:
        l7 = "tls"
    elif any(arg.startswith("--filter-tcp=") for arg in args):
        l7 = "tls"
    elif any(arg.startswith("--filter-udp=") for arg in args):
        l7 = "quic"
    else:
        return args
    return (f"--filter-l7={l7}", *args)


def compose_auto_best(
    profiles: dict[str, VerifiedCandidate],
) -> str:
    """Собирает composite-конфиг из выбранных профилей по доменам.

    Домены с одинаковыми ``args`` объединяются в один профиль с общим
    ``--hostlist-domains``.  Первый профиль пишется без ведущего
    ``--new``, остальные — с ``--new``.  Hostlist обязателен всегда:
    стратегия для discord.com не должна применяться ко всему TCP/443.
    Профиль также получает ``--filter-l7``: без него hostlist не
    фильтрует домены.
    """
    if not profiles:
        return ""

    grouped: dict[tuple[str, ...], list[str]] = {}
    for domain, candidate in profiles.items():
        args = tuple(
            arg
            for arg in candidate.args
            if arg != "--new" and not arg.startswith("--new=")
        )
        if not args:
            continue

        normalized = _with_firewall_filters(shlex.join(args))
        try:
            args = tuple(
                shlex.split(normalized, comments=True, posix=True)
            )
        except ValueError:
            continue
        if not args:
            continue

        args = _ensure_l7_filter(args)
        grouped.setdefault(args, []).append(domain)

    if not grouped:
        return ""

    blocks: list[str] = []
    for index, (args, domains) in enumerate(grouped.items()):
        # nfqws2 ломает hostlist, если первый профиль начинается с --new:
        # ведущий --new создаёт пустой профиль, и фильтры фактически не
        # применяются.  Первый профиль пишем без --new, остальные — с ним.
        prefix = "" if index == 0 else "--new "
        blocks.append(
            f"{prefix}--hostlist-domains={','.join(domains)} "
            f"{shlex.join(args)}"
        )
    # Одна строка сохраняет совместимость с текущим apply_auto_best():
    # он нормализует config через shlex и не должен менять уже собранный
    # composite-конфиг.
    return " ".join(blocks)


def _save_auto_best_meta(
    profiles: dict[str, VerifiedCandidate],
    config_text: str,
    path: Path,
) -> Path:
    """Атомарно сохраняет auto_best.meta.json рядом с конфигом.

    ``path`` — путь к ``auto_best.conf``; имя meta-файла выводится из
    него (``auto_best.meta.json``).  Хэш считается от точного текста,
    который записан в конфиг, включая завершающий перевод строки.
    """
    meta_path = path.with_name(f"{path.stem}.meta.json")
    payload = {
        "version": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "hash": hashlib.sha256(config_text.encode("utf-8")).hexdigest(),
        "profiles": {
            domain: {
                "args": list(candidate.args),
                "strategy": shlex.join(candidate.args),
                "protocol": candidate.protocol,
                "complexity": candidate.complexity,
            }
            for domain, candidate in profiles.items()
        },
        # Совместимость с текущим apply_auto_best().
        "verified": True,
        "strategy": config_text.strip(),
        "saved_at": time.time(),
    }

    try:
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{meta_path.name}.",
            suffix=".tmp",
            dir=meta_path.parent,
        )
    except OSError as exc:
        raise OSError(
            f"Не удалось подготовить {meta_path}: {exc}"
        ) from exc

    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, meta_path)
    except OSError:
        temp_path.unlink(missing_ok=True)
        raise

    return meta_path


def _log_per_domain_profiles(
    profiles: dict[str, VerifiedCandidate],
) -> None:
    """Пишет в лог выбранные профили по доменам."""
    if not profiles:
        logger.info("Профили по доменам: подтверждённых стратегий нет")
        return

    for domain, candidate in profiles.items():
        result = candidate.domains.get(domain)
        latency = (
            result.median_latency_ms if result is not None else None
        )
        logger.info(
            "Профиль для %s: стратегия %s (%sms)",
            domain,
            " ".join(candidate.args),
            latency if latency is not None else "—",
        )


def _select_best_strategy(
    strategies: list[str],
    domains: list[str],
    on_progress: ProgressCallback | None = None,
    *,
    deadline: float | None = None,
    report_out: dict[str, object] | None = None,
) -> tuple[
    str | None,
    float | None,
    dict[str, VerifiedCandidate],
]:
    """Проверяет кандидатов и возвращает лучшую универсальную стратегию.

    Дополнительно возвращает профили по доменам для composite-сборки.
    Кандидаты проверяются динамическими пакетами до общего ``deadline``.
    Ранняя остановка — когда для каждого домена уже есть подтверждённый
    профиль; одна универсальная стратегия больше не требуется.
    """
    candidates = list(dict.fromkeys(strategies))
    if not candidates:
        return None, None, {}
    if deadline is None:
        deadline = time.monotonic() + VERIFY_TIMEOUT

    expected_domains = list(dict.fromkeys(domains))
    profiles: dict[str, VerifiedCandidate] = {}

    _emit_progress(
        on_progress,
        event="status",
        message=(
            f"Найдено стратегий: {len(candidates)}. "
            f"Проверяю через blockcheckw на {len(domains)} доменах..."
        ),
    )

    measured: list[tuple[int, list[int], str]] = []
    combined_matrix: CheckMatrix = {}
    index = 0
    batch_number = 0
    while index < len(candidates):
        remaining = deadline - time.monotonic()
        if remaining < MIN_CHECK_SECONDS:
            logger.info(
                "Проверка кандидатов остановлена по общему дедлайну: "
                "проверено пакетов: %d",
                batch_number,
            )
            break

        estimated = max(
            1,
            int(remaining // CHECK_BATCH_ESTIMATE_SECONDS),
        )
        batch_size = min(
            MAX_LATENCY_TESTS,
            len(candidates) - index,
            estimated,
        )
        batch = candidates[index : index + batch_size]
        index += len(batch)
        batch_number += 1
        _emit_progress(
            on_progress,
            event="status",
            message=(
                f"Пакет проверки {batch_number}: {len(batch)} кандидатов, "
                f"осталось ~{int(remaining)} с..."
            ),
        )
        if report_out is not None:
            checked = report_out.setdefault("checked_strategies", [])
            if isinstance(checked, list):
                checked.extend(batch)

        matrix = measure_latency(
            batch,
            domains,
            on_progress,
            deadline=deadline,
        )
        for strategy, by_domain in matrix.items():
            combined_matrix.setdefault(strategy, {}).update(by_domain)
        measured.extend(_aggregate_measurements(matrix, domains))

        profiles = _select_best_per_domain(combined_matrix, domains)
        if expected_domains and set(profiles) >= set(expected_domains):
            logger.info(
                "Ранняя остановка: профили найдены для всех доменов (%s)",
                ", ".join(expected_domains),
            )
            break

    # Этап B: показываем лучшую подтверждённую стратегию для каждого
    # домена.  Сохранение auto_best.conf по-прежнему делает старая
    # агрегированная логика ниже (Этап C заменит её composite-сборкой).
    profiles = _select_best_per_domain(combined_matrix, domains)
    _log_per_domain_profiles(profiles)

    if not measured:
        logger.warning(
            "blockcheckw check не подтвердил ни одной из %d стратегий; "
            "auto_best.conf не изменён.",
            len(candidates),
        )
        return None, None, profiles

    # 1) максимум рабочих доменов -> минимум failed;
    # 2) минимум медианы median_latency_ms по доменам;
    # 3) минимум худшей (max) задержки.
    failed, latencies, best = min(
        measured,
        key=lambda item: (
            item[0],
            statistics.median(item[1]),
            max(item[1]),
        ),
    )
    if failed:
        logger.warning(
            "Ни одна стратегия не прошла проверку на всех доменах; "
            "лучшая — %d/%d. Универсальная стратегия не сохранена; "
            "использую per-domain профили.",
            len(latencies),
            len(domains),
        )
        return None, None, profiles

    median = statistics.median(latencies)
    worst = max(latencies)
    logger.info(
        "Найдено стратегий: %d. Лучшая: %.1f ms (медиана), "
        "худшая: %d ms, доменов: %d/%d",
        len(candidates),
        median,
        worst,
        len(latencies),
        len(domains),
    )
    return best, median, profiles


def _save_best_strategy(
    strategies: list[str],
    domains: list[str],
    on_progress: ProgressCallback | None = None,
    *,
    deadline: float | None = None,
    report_out: dict[str, object] | None = None,
) -> tuple[bool, str]:
    best, latency, profiles = _select_best_strategy(
        strategies,
        domains,
        on_progress,
        deadline=deadline,
        report_out=report_out,
    )
    if not profiles:
        return (
            False,
            "Не найдено стратегий, подтверждённых check ни для одного "
            "домена. Все кандидаты оказались Mirage/не доставили "
            "страницу, либо закончился общий дедлайн. "
            "auto_best.conf не изменён.",
        )

    if report_out is not None:
        profile_payload: dict[str, dict[str, object]] = {}
        for domain, candidate in profiles.items():
            result = candidate.domains.get(domain)
            profile_payload[domain] = {
                "args": list(candidate.args),
                "strategy": shlex.join(candidate.args),
                "protocol": candidate.protocol,
                "complexity": candidate.complexity,
                "median_latency_ms": (
                    result.median_latency_ms
                    if result is not None
                    else None
                ),
            }
        report_out["profiles"] = profile_payload
        report_out.setdefault("domains", list(profiles))

    config_text = compose_auto_best(profiles)
    if not config_text.strip():
        return (
            False,
            "compose_auto_best вернул пустой конфиг; auto_best.conf "
            "не изменён.",
        )

    ok, message = _save_strategy(config_text, profiles=profiles)
    if ok:
        covered = ", ".join(profiles)
        prefix = (
            f"Найдено стратегий: {len(strategies)}. "
            f"Подтверждено доменов: {len(profiles)} ({covered}). "
        )
        if best is not None and latency is not None:
            prefix += f"Лучшая универсальная медиана: {latency:g} ms. "
        message = prefix + message
    return ok, message


def _run_blockcheck_locked(
    domains: str = DEFAULT_DOMAINS,
    on_progress: ProgressCallback | None = None,
    *,
    scan_domains: str | None = None,
    report_out: dict[str, object] | None = None,
) -> tuple[bool, str]:
    """Один адаптивный поиск по четырём целям.

    Первый этап сканирует YouTube и Discord. Если check не подтвердил
    стратегию на всех целях, второй этап сканирует Twitch и Steam.
    """
    logger.info(
        "Автопоиск: deadline=%s с, scan=%s с/домен, stage_budget=%s с, "
        "verify=%s с, stage_check=%s с, workers=%s, protocols=%s, "
        "check_passes=%s",
        SEARCH_DEADLINE,
        SCAN_TIMEOUT,
        STAGE_SCAN_BUDGET,
        VERIFY_TIMEOUT,
        STAGE_CHECK_BUDGET,
        BLOCKCHECK_WORKERS,
        SCAN_PROTOCOLS,
        CHECK_PASSES,
    )
    if shutil.which("blockcheckw") is None:
        return False, "blockcheckw не установлен. Установите через AUR."
    if os.geteuid() != 0 and shutil.which("sudo") is None:
        return False, (
            "sudo не найден. blockcheckw требует root-права; "
            "установите sudo и настройте NOPASSWD. "
            + SUDO_HINT
        )

    scan_source = scan_domains or (
        DEFAULT_SCAN_DOMAINS if domains == DEFAULT_DOMAINS else domains
    )
    # Сканируем все цели безусловно.  Предварительный blockcheckw status /
    # SNI-фильтр не используется: доступный домен всё равно может отдавать
    # трафик через проблемный CDN, поэтому status не должен отсеивать цель.
    targets = [
        part.strip()
        for part in scan_source.split(",")
        if part.strip()
    ]
    targets = list(dict.fromkeys(targets))[:MAX_VERIFY_DOMAINS]
    if not targets:
        return False, "Не задан ни один домен для сканирования."

    if report_out is not None:
        # Все цели, а не только покрытые: UI должен показать «Нет профиля».
        report_out["domains"] = list(targets)

    deadline = time.monotonic() + SEARCH_DEADLINE
    service = None
    service_stopped = False
    try:
        from src.service import ServiceManager

        service = ServiceManager()
        status = service.status()
        if status.active:
            if not status.ours:
                logger.warning(
                    "zapret-easy.service активна, но unit не принадлежит проекту; "
                    "не останавливаю её"
                )
            else:
                _emit_progress(
                    on_progress,
                    event="status",
                    message="Останавливаю zapret-easy.service на время скана...",
                )
                stop_result = service.stop()
                if not stop_result.ok:
                    return False, (
                        "Не удалось остановить zapret-easy.service: "
                        f"{stop_result.message}"
                    )
                service_stopped = True
                _emit_progress(
                    on_progress,
                    event="status",
                    message="Служба остановлена, начинаю скан...",
                )
    except Exception as exc:
        logger.warning("Не удалось проверить/остановить службу: %s", exc)

    try:
        stages = [
            targets[index : index + 2]
            for index in range(0, len(targets), 2)
        ]
        last_message = "Не найдено подтверждённых стратегий."
        # (домены этапа, сообщение, этап сказал «не заблокировано»)
        stage_results: list[tuple[tuple[str, ...], str, bool]] = []
        for stage_number, stage_domains in enumerate(stages, start=1):
            remaining = deadline - time.monotonic()
            if remaining < MIN_SEARCH_SECONDS:
                last_message = (
                    "Общий дедлайн поиска исчерпан до начала этапа "
                    f"{stage_number}."
                )
                logger.info(last_message)
                break
            stage_budget = max(
                1.0,
                min(STAGE_SCAN_BUDGET, remaining - MIN_CHECK_SECONDS),
            )
            _emit_progress(
                on_progress,
                event="status",
                message=(
                    f"Этап {stage_number}/{len(stages)}: сканирую "
                    f"{', '.join(stage_domains)} "
                    f"(до {int(stage_budget)} с, всего осталось "
                    f"~{int(remaining)} с)..."
                ),
            )
            with tempfile.TemporaryDirectory(
                prefix="zapret-easy-scan-"
            ) as temp_dir:
                directory = Path(temp_dir)
                try:
                    strategies, completed, payload = _scan_for_strategies(
                        stage_domains,
                        directory,
                        on_progress,
                        budget_secs=stage_budget,
                    )
                except subprocess.TimeoutExpired:
                    last_message = (
                        f"blockcheckw scan на этапе {stage_number} не "
                        f"завершился за {stage_budget:g} с."
                    )
                    logger.warning(last_message)
                    stage_results.append(
                        (tuple(stage_domains), last_message, False)
                    )
                    continue
                except OSError as exc:
                    last_message = (
                        f"Не удалось запустить blockcheckw на этапе "
                        f"{stage_number}: {exc}"
                    )
                    logger.warning(last_message)
                    stage_results.append(
                        (tuple(stage_domains), last_message, False)
                    )
                    continue
                except (ScanCancelled, KeyboardInterrupt):
                    logger.info("Поиск blockcheckw отменён пользователем")
                    return False, "Сканирование отменено пользователем"

            if not strategies:
                if completed is not None:
                    last_message = _no_strategy_message(
                        completed,
                        payload=payload,
                    )
                else:
                    last_message = (
                        "blockcheckw не успел просканировать ни один домен "
                        f"на этапе {stage_number}."
                    )
                logger.warning(
                    "blockcheckw scan: этап %d не дал стратегий",
                    stage_number,
                )
                stage_results.append(
                    (
                        tuple(stage_domains),
                        last_message,
                        _payload_is_not_blocked(payload),
                    )
                )
                continue

            logger.info(
                "blockcheckw scan: этап %d, найдено стратегий: %d",
                stage_number,
                len(strategies),
            )
            stage_check_deadline = min(
                deadline,
                time.monotonic() + STAGE_CHECK_BUDGET,
            )
            ok, message = _save_best_strategy(
                strategies,
                targets,
                on_progress,
                deadline=stage_check_deadline,
                report_out=report_out,
            )
            if ok:
                return True, message
            last_message = message
            stage_results.append(
                (tuple(stage_domains), last_message, False)
            )
            logger.info(
                "Этап %d не дал стратегии, подтверждённой на всех целях",
                stage_number,
            )

        return False, _final_stage_message(stage_results, last_message)
    finally:
        if service_stopped and service is not None:
            _emit_progress(
                on_progress,
                event="status",
                message="Запускаю zapret-easy.service обратно...",
            )
            try:
                restart = service.start()
            except Exception as exc:
                logger.exception(
                    "Не удалось запустить zapret-easy.service после скана"
                )
                _emit_progress(
                    on_progress,
                    event="status",
                    message=f"Не удалось запустить службу: {exc}",
                )
            else:
                if restart.ok:
                    logger.info("zapret-easy.service запущена после скана")
                else:
                    logger.error(
                        "Не удалось запустить zapret-easy.service после скана: %s",
                        restart.message,
                    )
                    _emit_progress(
                        on_progress,
                        event="status",
                        message=(
                            "Не удалось запустить службу: "
                            f"{restart.message}"
                        ),
                    )


def _save_auto_best_report(
    report_data: dict[str, object],
    *,
    started_at: str,
    duration_seconds: float,
) -> None:
    """Сохраняет auto_best.report.json; ошибки записи не ломают поиск."""
    raw_checked = report_data.get("checked_strategies", [])
    checked: list[str] = []
    if isinstance(raw_checked, list):
        checked = list(
            dict.fromkeys(
                str(item) for item in raw_checked if isinstance(item, str)
            )
        )

    raw_profiles = report_data.get("profiles", {})
    profiles = raw_profiles if isinstance(raw_profiles, dict) else {}
    raw_domains = report_data.get("domains", [])
    domains = (
        [str(item) for item in raw_domains]
        if isinstance(raw_domains, list)
        else []
    )

    payload = {
        "timestamp": started_at,
        "duration_seconds": round(duration_seconds, 3),
        "checked_strategies": checked,
        "profiles": profiles,
        "domains": domains,
        "result": str(report_data.get("result", "")),
    }

    try:
        AUTO_BEST_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{AUTO_BEST_REPORT_FILE.name}.",
            suffix=".tmp",
            dir=AUTO_BEST_REPORT_FILE.parent,
        )
    except OSError as exc:
        logger.warning("Не удалось подготовить %s: %s", AUTO_BEST_REPORT_FILE, exc)
        return

    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, AUTO_BEST_REPORT_FILE)
    except (OSError, TypeError, ValueError) as exc:
        temp_path.unlink(missing_ok=True)
        logger.warning("Не удалось записать %s: %s", AUTO_BEST_REPORT_FILE, exc)


def run_blockcheck(
    domains: str = DEFAULT_DOMAINS,
    on_progress: ProgressCallback | None = None,
    *,
    scan_domains: str | None = None,
) -> tuple[bool, str]:
    """Публичная точка входа автопоиска с защитой от параллельных запусков."""
    started_monotonic = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )
    report_data: dict[str, object] = {}
    try:
        with _blockcheck_lock():
            running = _other_blockcheck_process()
            if running is not None:
                pid, command = running
                return False, (
                    "Автопоиск уже выполняется другим процессом "
                    f"blockcheckw (PID {pid}: {command}). "
                    "Дождитесь завершения или остановите его."
                )
            ok, message = _run_blockcheck_locked(
                domains,
                on_progress,
                scan_domains=scan_domains,
                report_out=report_data,
            )
            if ok:
                report_data["result"] = message
                _save_auto_best_report(
                    report_data,
                    started_at=started_at,
                    duration_seconds=time.monotonic() - started_monotonic,
                )
            return ok, message
    except BlockcheckBusy as exc:
        return False, str(exc)


def _with_firewall_filters(raw: str) -> str:
    """Добавляет --filter-tcp/udp, если blockcheckw их не вывел.

    `blockcheckw scan` проверяет стратегии через свои профили и в JSON
    отдаёт только payload/desync-аргументы.  Сервису zapret-easy нужен
    ещё фильтр портов, иначе ``derive_firewall_ports`` не сможет собрать
    firewall-правила и установка будет отклонена.
    """
    line = raw.strip()
    if not re.search(r"(?:^|\s)--filter-(?:tcp|udp)=", line):
        if "--payload=http_req" in line:
            line = f"--filter-tcp=80 {line}"
        elif re.search(r"--payload=(?:quic|udp)", line):
            line = f"--filter-udp=443 {line}"
        else:
            # YouTube/Discord и подавляющее большинство стратегий — TLS/TCP 443.
            line = f"--filter-tcp=443 {line}"
    # blockcheckw печатает аргументы простым join(" "), а StrategyManager
    # разбирает .conf через shlex.  Экранируем токены, чтобы inline-Lua
    # (например tls_mod(fake,'rnd')) не потерял кавычки при разборе.
    # Если строка уже экранирована прошлым применением, сначала разбираем
    # её как shell-строку, иначе повторное применение удвоит кавычки.
    if re.search(r"(?:^|\s)['\"]", line):
        try:
            tokens = shlex.split(line, comments=True)
        except ValueError:
            tokens = line.split()
    else:
        tokens = line.split()
    return shlex.join(tokens)


def _ensure_auto_best_lua(strategies_dir: Path) -> Path:
    """Создаёт Lua-заглушку, чтобы StrategyManager увидел auto_best.lua.

    Сами аргументы находятся в auto_best.conf.  Пустой Lua-файл служба
    не примет, поэтому пишем безопасный комментарий.
    """
    lua_path = strategies_dir / AUTO_BEST_LUA_NAME
    if lua_path.is_file():
        try:
            if lua_path.stat().st_size > 0:
                return lua_path
        except OSError as exc:
            raise RuntimeError(f"Не удалось прочитать {lua_path}: {exc}") from exc
    try:
        lua_path.write_text(
            "-- Generated by blockcheckw integration. "
            "Arguments are stored in auto_best.conf.\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise RuntimeError(f"Не удалось создать {lua_path}: {exc}") from exc
    return lua_path


def _rollback_auto_best_apply(
    manager: "StrategyManager",
    service: "ServiceManager | None",
    *,
    previous: str | None,
    lua_name: str,
    was_active: bool,
    attempted_install: bool,
    cause: str,
) -> tuple[bool, str]:
    """Восстанавливает последний auto_best и перезапускает службу."""
    from src.strategies import StrategyError

    try:
        restored = _restore_auto_best_backup(manager.strategies_dir)
    except OSError as exc:
        message = (
            f"{cause}\n"
            f"Не удалось восстановить auto_best.conf из бэкапа: {exc}"
        )
        logger.error(message)
        return False, message

    if not restored:
        suffix = (
            "Служба могла остаться в промежуточном состоянии."
            if attempted_install
            else "Служба не изменялась."
        )
        message = (
            f"{cause}\n"
            f"Бэкап {AUTO_BEST_BACKUP_NAME} не найден; откат невозможен. "
            f"{suffix}"
        )
        logger.error(message)
        return False, message

    target = previous or lua_name
    try:
        manager.set_active(target)
    except StrategyError as exc:
        logger.error(
            "Не удалось восстановить активную стратегию %s: %s",
            target,
            exc,
        )

    restart_required = service is not None and (
        was_active or attempted_install
    )
    if restart_required:
        assert service is not None
        try:
            result = service.install()
        except Exception as exc:  # noqa: BLE001 - откат обязан вернуть текст
            message = (
                f"{cause}\n"
                "Бэкап auto_best.conf восстановлен, но служба не "
                f"перезапущена: {type(exc).__name__}: {exc}"
            )
            logger.exception(message)
            return False, message

        if not result.ok:
            message = (
                f"{cause}\n"
                "Бэкап auto_best.conf восстановлен, но служба не "
                f"поднялась со старым конфигом: {result.message}"
            )
            logger.error(message)
            return False, message

        service_stopped = True
        if was_active:
            try:
                status = service.status()
            except Exception as exc:  # noqa: BLE001 - сообщаем, не молчим
                message = (
                    f"{cause}\n"
                    "Бэкап auto_best.conf восстановлен, но не удалось "
                    f"проверить состояние службы: {type(exc).__name__}: {exc}"
                )
                logger.exception(message)
                return False, message
            if not status.active:
                message = (
                    f"{cause}\n"
                    "Бэкап auto_best.conf восстановлен, но служба "
                    "не активна после отката."
                )
                logger.error(message)
                return False, message
        else:
            try:
                stop_result = service.stop()
            except Exception as exc:  # noqa: BLE001 - сообщаем, не молчим
                message = (
                    f"{cause}\n"
                    "Бэкап auto_best.conf восстановлен, но служба "
                    f"осталась запущенной: {type(exc).__name__}: {exc}"
                )
                logger.exception(message)
                return False, message
            if not stop_result.ok:
                service_stopped = False
                logger.warning(
                    "Не удалось остановить службу после отката: %s",
                    stop_result.message,
                )
    else:
        service_stopped = True

    message = (
        f"{cause}\n"
        "Выполнен откат: auto_best.conf/meta восстановлены из "
        f"{AUTO_BEST_BACKUP_NAME}."
    )
    if restart_required:
        if was_active:
            message += " Служба перезапущена со старым конфигом."
        elif service_stopped:
            message += " Служба остановлена, как была до применения."
        else:
            message += (
                " Служба осталась запущенной со старым конфигом, "
                "остановить её не удалось."
            )
    logger.info("Откат auto_best выполнен: %s", cause)
    return False, message


def apply_auto_best() -> tuple[bool, str]:
    """Применяет auto_best.conf через существующий ServiceManager.

    Перед применением проверяются meta.json, ``verified`` и sha256.
    Перед заменой auto_best.conf на диске сохраняется .bak; если новый
    конфиг не прошёл dry-run, служба не запустилась или проверка
    hash/meta провалилась, бэкап восстанавливается, а служба
    перезапускается со старым конфигом.
    """
    try:
        from src.service import ServiceManager
        from src.strategies import StrategyError, StrategyManager
    except ImportError as exc:  # pragma: no cover - защита от битой установки
        return False, f"Не удалось загрузить модули применения: {exc}"

    manager = StrategyManager()
    conf_path = manager.strategies_dir / AUTO_BEST_NAME
    if not conf_path.is_file():
        return False, "Файл auto_best.conf не найден. Сначала выполните автопоиск."

    try:
        raw_bytes = conf_path.read_bytes()
        raw = raw_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return False, f"Не удалось прочитать auto_best.conf: {exc}"
    if not raw.strip():
        return False, "auto_best.conf пуст. Сначала выполните автопоиск."

    meta_path = manager.strategies_dir / AUTO_BEST_META_NAME
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        meta = None

    service = ServiceManager(manager)
    status = service.status()
    was_active = status.active
    previous = manager.active_name()

    cause: str | None = None
    if not isinstance(meta, dict):
        cause = (
            "auto_best.meta.json отсутствует или повреждён; "
            "проверка hash невозможна."
        )
    elif meta.get("verified") is not True:
        cause = (
            "auto_best.meta.json не подтверждён: verified != true."
        )
    else:
        expected_hash = meta.get("hash")
        actual_hash = hashlib.sha256(raw_bytes).hexdigest()
        if not isinstance(expected_hash, str) or not expected_hash:
            cause = (
                "В auto_best.meta.json нет hash; конфиг нельзя "
                "считать подтверждённым."
            )
        elif actual_hash != expected_hash:
            cause = (
                "sha256(auto_best.conf) не совпадает с hash из "
                "auto_best.meta.json: конфиг подменён. "
                f"Ожидалось {expected_hash}, получено {actual_hash}."
            )
        elif meta.get("strategy") != raw.strip():
            cause = (
                "Содержимое auto_best.conf не совпадает со strategy "
                "из auto_best.meta.json: конфиг изменён вручную."
            )

    if cause is not None:
        logger.error("Применение auto_best отклонено: %s", cause)
        return _rollback_auto_best_apply(
            manager,
            service,
            previous=previous,
            lua_name=AUTO_BEST_LUA_NAME,
            was_active=was_active,
            attempted_install=False,
            cause=cause,
        )

    try:
        lua_path = _ensure_auto_best_lua(manager.strategies_dir)
    except RuntimeError as exc:
        return False, str(exc)

    if not status.installed:
        return (
            False,
            "Служба zapret-easy не установлена. Сначала установите её в пункте «Служба и настройки».",
        )
    if not status.ours:
        return (
            False,
            "Служба zapret-easy установлена сторонним unit-файлом; применение через zapret-easy запрещено.",
        )

    try:
        from src.game_mode import GameModeManager

        game_active = GameModeManager().status().active
    except Exception as exc:  # noqa: BLE001 - Game Mode не должен блокировать применение
        logger.warning("Не удалось проверить состояние Game Mode: %s", exc)
        game_active = False
    if game_active:
        return (
            False,
            "Game Mode активен. Сначала выключите его, чтобы новая стратегия не потеряла игровые UDP-правила.",
        )

    # В нормальном flow .bak уже создан _save_strategy() перед записью
    # нового конфига. Если файла нет (старая установка), фиксируем
    # текущее состояние, чтобы откат был возможен.
    backup_path = (
        manager.strategies_dir / AUTO_BEST_BACKUP_NAME
    )
    if not backup_path.is_file():
        try:
            _backup_auto_best(manager.strategies_dir)
        except OSError as exc:
            return (
                False,
                f"Не удалось создать бэкап auto_best.conf: {exc}",
            )

    try:
        manager.set_active(lua_path.name)
    except StrategyError as exc:
        return False, f"Стратегия auto_best не прошла проверку: {exc}"

    logger.info("Применение auto_best через ServiceManager")
    try:
        result = service.install()
    except Exception as exc:  # noqa: BLE001 - откат обязан вернуть текст
        cause = (
            "Служба не запустилась с новым конфигом: "
            f"{type(exc).__name__}: {exc}"
        )
        logger.exception(cause)
        return _rollback_auto_best_apply(
            manager,
            service,
            previous=previous,
            lua_name=lua_path.name,
            was_active=was_active,
            attempted_install=True,
            cause=cause,
        )

    if not result.ok:
        cause = f"Новый конфиг не применён: {result.message}"
        logger.error(cause)
        return _rollback_auto_best_apply(
            manager,
            service,
            previous=previous,
            lua_name=lua_path.name,
            was_active=was_active,
            attempted_install=True,
            cause=cause,
        )

    # После успешного применения .bak должен указывать на последний
    # рабочий конфиг: это цель следующего отката.
    try:
        _backup_auto_best(manager.strategies_dir)
    except OSError as exc:
        logger.warning(
            "Не удалось обновить бэкап auto_best после применения: %s",
            exc,
        )

    return True, result.message


if __name__ == "__main__":
    ok, message = run_blockcheck()
    print(message)
    raise SystemExit(0 if ok else 1)
