"""Проверка платформы и доступных инструментов zapret-easy."""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal


logger = logging.getLogger("zapret-easy")

OS_RELEASE_FILE: Final = Path("/etc/os-release")
ZAPRET2_SERVICE: Final = "zapret2.service"
ZAPRET_EASY_SERVICE: Final = "zapret-easy.service"
AUR_HELPERS: Final = ("yay", "paru")
REQUIRED_TOOLS: Final = (
    ("pacman", "pacman", "управление пакетами"),
    ("pkexec", "pkexec / Polkit", "запрос прав root"),
    ("nft", "nftables / nft", "правила NFQUEUE"),
    ("systemctl", "systemd / systemctl", "управление службой"),
)

KernelState = Literal["missing", "running", "stopped", "error"]


@dataclass(frozen=True, slots=True)
class ToolStatus:
    """Наличие одного внешнего инструмента."""

    key: str
    label: str
    path: str | None
    required: bool
    purpose: str = ""

    @property
    def found(self) -> bool:
        return self.path is not None


@dataclass(frozen=True, slots=True)
class KernelInfo:
    """Быстрый снимок состояния nfqws2 для шапки TUI."""

    state: KernelState
    detail: str
    path: str | None = None


@dataclass(frozen=True, slots=True)
class SystemReport:
    """Результат проверки системы перед установкой."""

    distro_name: str
    distro_id: str
    is_arch_based: bool
    is_cachyos: bool
    is_root: bool
    tools: tuple[ToolStatus, ...]
    aur_helper: str | None
    aur_helper_path: str | None
    issues: tuple[str, ...]
    warnings: tuple[str, ...]

    def tool(self, key: str) -> ToolStatus | None:
        return next((tool for tool in self.tools if tool.key == key), None)

    @property
    def nfqws2_path(self) -> str | None:
        tool = self.tool("nfqws2")
        return tool.path if tool else None

    @property
    def install_required(self) -> bool:
        return self.nfqws2_path is None

    @property
    def can_install(self) -> bool:
        if not self.install_required or self.issues or self.aur_helper_path is None:
            return False
        git = self.tool("git")
        return git is not None and git.path is not None


def _parse_os_release(path: Path = OS_RELEASE_FILE) -> dict[str, str]:
    """Читает /etc/os-release без падения на нестандартных строках."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("Не удалось прочитать %s: %s", path, exc)
        return {}

    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def _distro_details(os_release: dict[str, str]) -> tuple[str, str, bool, bool]:
    name = (
        os_release.get("PRETTY_NAME")
        or os_release.get("NAME")
        or platform.platform()
    )
    distro_id = os_release.get("ID", "").lower()
    id_like = set(os_release.get("ID_LIKE", "").lower().split())
    arch_ids = {"arch", "cachyos", "endeavouros", "garuda", "manjaro"}
    is_arch_based = distro_id in arch_ids or "arch" in id_like
    is_cachyos = distro_id == "cachyos" or "cachyos" in name.lower()
    return name, distro_id, is_arch_based, is_cachyos


def detect_system() -> SystemReport:
    """Собирает сведения о дистрибутиве и обязательных инструментах."""
    os_release = _parse_os_release()
    name, distro_id, is_arch_based, is_cachyos = _distro_details(os_release)

    tools: list[ToolStatus] = []
    for key, label, purpose in REQUIRED_TOOLS:
        tools.append(
            ToolStatus(
                key=key,
                label=label,
                path=shutil.which(key),
                required=True,
                purpose=purpose,
            )
        )

    tools.append(
        ToolStatus(
            key="nfqws2",
            label="nfqws2 / zapret2",
            path=shutil.which("nfqws2"),
            required=False,
            purpose="ядро обхода DPI",
        )
    )
    tools.append(
        ToolStatus(
            key="git",
            label="git / AUR",
            path=shutil.which("git"),
            required=False,
            purpose="получение AUR-пакета",
        )
    )

    helpers = [(helper, shutil.which(helper)) for helper in AUR_HELPERS]
    helper_name, helper_path = next(
        ((helper, path) for helper, path in helpers if path is not None),
        (None, None),
    )

    issues: list[str] = []
    warnings: list[str] = []

    if not is_arch_based:
        issues.append(
            f"Система «{name}» не основана на Arch Linux. Нужны CachyOS или Arch."
        )
    if os.geteuid() == 0:
        issues.append(
            "zapret-easy нельзя запускать от root. Запустите TUI от обычного пользователя."
        )

    for tool in tools:
        if tool.required and not tool.found:
            issues.append(
                f"Не найден обязательный компонент: {tool.label} ({tool.purpose})."
            )

    if helper_path is None:
        warnings.append(
            "AUR-хелпер не найден. Для автоустановки нужен yay или paru."
        )
    elif shutil.which("git") is None:
        warnings.append(
            "git не найден. AUR-хелпер не сможет получить пакет zapret2."
        )

    return SystemReport(
        distro_name=name,
        distro_id=distro_id,
        is_arch_based=is_arch_based,
        is_cachyos=is_cachyos,
        is_root=os.geteuid() == 0,
        tools=tuple(tools),
        aur_helper=helper_name,
        aur_helper_path=helper_path,
        issues=tuple(issues),
        warnings=tuple(warnings),
    )


def check_kernel() -> KernelInfo:
    """Проверяет nfqws2 и службу zapret2 без длинных ожиданий."""
    nfqws2 = shutil.which("nfqws2")
    if nfqws2 is None:
        return KernelInfo(
            state="missing",
            detail="nfqws2 не найден — начните с пункта 1",
        )

    systemctl = shutil.which("systemctl")
    if systemctl is None:
        return KernelInfo(
            state="error",
            detail="systemctl не найден",
            path=nfqws2,
        )

    try:
        result = subprocess.run(
            [
                systemctl,
                "is-active",
                ZAPRET_EASY_SERVICE,
                ZAPRET2_SERVICE,
            ],
            capture_output=True,
            text=True,
            timeout=0.75,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning(
            "Не удалось проверить службы zapret: %s",
            exc,
        )
        return KernelInfo(
            state="error",
            detail="служба не отвечает",
            path=nfqws2,
        )

    states = result.stdout.splitlines()
    easy_state = states[0].strip() if len(states) > 0 else "unknown"
    package_state = states[1].strip() if len(states) > 1 else "unknown"

    if easy_state == "active":
        return KernelInfo(
            state="running",
            detail=f"{ZAPRET_EASY_SERVICE} активен",
            path=nfqws2,
        )
    if package_state == "active":
        return KernelInfo(
            state="running",
            detail=f"{ZAPRET2_SERVICE} активен",
            path=nfqws2,
        )
    if easy_state in {"inactive", "failed", "unknown"}:
        return KernelInfo(
            state="stopped",
            detail=f"{ZAPRET_EASY_SERVICE}: {easy_state}",
            path=nfqws2,
        )
    return KernelInfo(
        state="stopped",
        detail=f"{ZAPRET_EASY_SERVICE}: {easy_state or 'нет данных'}",
        path=nfqws2,
    )
