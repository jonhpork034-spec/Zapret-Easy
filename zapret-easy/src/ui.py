"""Быстрый терминальный интерфейс zapret-easy."""

from __future__ import annotations

import json
import logging
import re
import select
import sys
import time
from typing import Final

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text

from src.blockcheck_integration import (
    AUTO_BEST_REPORT_FILE,
    apply_auto_best,
    run_blockcheck,
)
from src.detect import SystemReport, check_kernel, detect_system
from src.game_mode import GameModeManager, GameModeResult, GameModeStatus
from src.installer import PACKAGE_NAME, build_install_plan, install_zapret2
from src.service import (
    ZAPRET_UNITS,
    ServiceManager,
    ServicePreflight,
    ServiceResult,
    ServiceStatus,
)
from src.strategies import (
    COMMUNITY_SOURCES,
    CommunityImportResult,
    Strategy,
    StrategyError,
    StrategyManager,
    fetch_community_strategies,
)
from src.tweaks import (
    SYSCTL_FILE,
    TweakManager,
    TweakOptions,
    TweakResult,
    TweakStatus,
)

console = Console()
logger = logging.getLogger("zapret-easy")

BASE_ACCENT: Final = "#c084fc"
BASE_MINT: Final = "#34d399"
BASE_AMBER: Final = "#fbbf24"
BASE_RED: Final = "#f87171"
BASE_MUTED: Final = "grey62"

ACCENT: str = BASE_ACCENT
MINT: str = BASE_MINT
AMBER: str = BASE_AMBER
RED: str = BASE_RED
MUTED: str = BASE_MUTED

# Неоново-зелёная схема активного игрового режима.
GAME_ACCENT: Final = "#39ff14"
GAME_MINT: Final = "#00ff9f"
GAME_AMBER: Final = "#b6ff00"
GAME_RED: Final = "#ff4d6d"
GAME_MUTED: Final = "#6fcf97"

_KERNEL_BADGES: Final = {
    "missing": ("НЕ УСТАНОВЛЕН", RED),
    "running": ("РАБОТАЕТ", MINT),
    "stopped": ("НЕ ЗАПУЩЕН", AMBER),
    "error": ("ОШИБКА", RED),
}

MENU_ACTIONS: Final = (
    (
        "quickstart",
        "1. Установить и запустить всё",
        "автонастройка под ключ",
    ),
    (
        "strategies",
        "2. Управление стратегиями",
        "Lua-стратегии и активный профиль",
    ),
    (
        "test",
        "3. Тест стратегий",
        "автопоиск рабочей конфигурации",
    ),
    (
        "blockcheck",
        "4. [F] ⚡ Автопоиск идеальной стратегии (blockcheckw)",
        "сканирование портов и стратегий через Rust-бинарник",
    ),
    (
        "settings",
        "5. Служба и настройки",
        "status, установка, откат",
    ),
    (
        "game",
        "6. [G] 🎮 Включить Игровой Режим",
        "UDP для игр/Discord + системный буст",
    ),
    (
        "disable_all",
        "7. ⛔ Полностью выключить zapret и все службы",
        "stop и disable всех zapret-служб",
    ),
    (
        "exit",
        "8. Выход",
        "закрыть zapret-easy",
    ),
)

SETTINGS_ACTIONS: Final = (
    (
        "status",
        "Статус службы",
        "systemd, стратегия и конфликты",
    ),
    (
        "install",
        "Установить и запустить",
        "unit, active.conf и правила nftables",
    ),
    (
        "start",
        "Запустить",
        "systemctl start zapret-easy.service",
    ),
    (
        "stop",
        "Остановить",
        "systemctl stop zapret-easy.service",
    ),
    (
        "rollback",
        "Откат",
        "удалить unit и восстановить inet zapret2",
    ),
    (
        "tweaks",
        "Сетевые твики",
        "sysctl: fq/cake, BBR, backlog",
    ),
    (
        "back",
        "Назад",
        "вернуться в главное меню",
    ),
)

TWEAK_ACTIONS: Final = (
    (
        "apply",
        "Применить / обновить",
        "безопасные sysctl-параметры",
    ),
    (
        "revert",
        "Удалить твики",
        "вернуть старые значения и файл",
    ),
    (
        "back",
        "Назад",
        "вернуться к службе",
    ),
)

_TWEAK_LABELS: Final = {
    "net.core.default_qdisc": "Очередь qdisc",
    "net.ipv4.tcp_congestion_control": "Congestion control",
    "net.core.netdev_max_backlog": "netdev_max_backlog",
    "net.ipv4.tcp_fastopen": "TCP Fast Open",
    "net.ipv4.tcp_mtu_probing": "TCP MTU probing",
    "net.ipv4.ip_forward": "IP forwarding",
}

DOWNLOAD_STRATEGY_CHOICE: Final = "__download_community_strategies__"


def _set_game_theme(active: bool) -> None:
    """Переключает акцентные цвета TUI на неоново-зелёные."""
    global ACCENT, MINT, AMBER, RED, MUTED

    if active:
        ACCENT = GAME_ACCENT
        MINT = GAME_MINT
        AMBER = GAME_AMBER
        RED = GAME_RED
        MUTED = GAME_MUTED
    else:
        ACCENT = BASE_ACCENT
        MINT = BASE_MINT
        AMBER = BASE_AMBER
        RED = BASE_RED
        MUTED = BASE_MUTED

    _KERNEL_BADGES["missing"] = ("НЕ УСТАНОВЛЕН", RED)
    _KERNEL_BADGES["running"] = ("РАБОТАЕТ", MINT)
    _KERNEL_BADGES["stopped"] = ("НЕ ЗАПУЩЕН", AMBER)
    _KERNEL_BADGES["error"] = ("ОШИБКА", RED)


def _game_status() -> GameModeStatus:
    return GameModeManager().status()


def _menu_actions() -> tuple[tuple[str, str, str], ...]:
    """Главное меню с динамическим пунктом Game Mode."""
    status = _game_status()
    result: list[tuple[str, str, str]] = []
    for value, label, hint in MENU_ACTIONS:
        if value == "game":
            if status.active:
                label = "6. [G] 🎮 Выключить Игровой Режим"
                hint = "вернуть governor, qdisc, watchdog и active.conf"
            else:
                label = "6. [G] 🎮 Включить Игровой Режим"
                hint = "UDP для игр/Discord + системный буст"
        result.append((value, label, hint))
    return tuple(result)


def _status_cell(label: str, value: str, color: str) -> Text:
    """Одна пара «подпись — значение» для шапки."""
    cell = Text()
    cell.append(f"{label:<12}", style=MUTED)
    cell.append(value, style=f"bold {color}")
    return cell


def _print_header() -> None:
    """Рисует статичный Dashboard без анимаций."""
    game = _game_status()
    _set_game_theme(game.active)

    service: ServiceManager | None = None
    service_active = False
    service_unknown = False
    try:
        service = ServiceManager()
        service_active = service.status().active
    except Exception:
        service_unknown = True
        logger.exception("Не удалось получить статус службы")

    strategy_name = "—"
    if service is not None:
        try:
            strategy_name = service.manager.active_name() or "не выбрана"
        except Exception:
            logger.exception("Не удалось получить активную стратегию")

    kernel = check_kernel()
    kernel_label, kernel_color = _KERNEL_BADGES[kernel.state]

    if service_unknown:
        service_value, service_color = "● НЕИЗВЕСТНО", MUTED
    elif service_active:
        service_value, service_color = "● АКТИВНА", MINT
    else:
        service_value, service_color = "○ ОСТАНОВЛЕНА", RED

    if game.active:
        game_value, game_color = "● ВКЛЮЧЕН", MINT
    else:
        game_value, game_color = "○ ВЫКЛЮЧЕН", MUTED

    service_cell = _status_cell("Служба", service_value, service_color)
    strategy_cell = _status_cell("Стратегия", strategy_name, ACCENT)
    game_cell = _status_cell("Game Mode", game_value, game_color)
    kernel_cell = _status_cell("Ядро", f"● {kernel_label}", kernel_color)

    info = Table.grid(padding=(0, 4), expand=True)
    if console.width >= 76:
        info.add_column(ratio=1)
        info.add_column(ratio=1)
        info.add_row(service_cell, strategy_cell)
        info.add_row(game_cell, kernel_cell)
    else:
        info.add_column()
        for cell in (service_cell, strategy_cell, game_cell, kernel_cell):
            info.add_row(cell)

    footer: list[str] = []
    if game.active:
        details: list[str] = []
        if game.interface:
            details.append(f"интерфейс {game.interface}")
        if game.qdisc:
            details.append(f"qdisc {game.qdisc}")
        if game.governor:
            details.append(f"governor {game.governor}")
        if game.watchdog_stopped:
            details.append("watchdog остановлен")
        if details:
            footer.append("Game Mode: " + " · ".join(details))
    if kernel.state in {"error", "stopped"}:
        footer.append(kernel.detail)

    body: list[Text | Table] = [info]
    if footer:
        body.append(Text("\n" + "\n".join(footer), style=MUTED))

    console.print()
    console.print(
        Panel(
            Group(*body),
            title=f"[bold {ACCENT}]⚡ ZAPRET EASY[/]",
            subtitle=f"[{MUTED}]обход DPI · zapret2 / nfqws2[/]",
            border_style=ACCENT,
            padding=(1, 2),
        )
    )


def _render_action_menu(
    actions: tuple[tuple[str, str, str], ...] | list[tuple[str, str, str]],
    title: str,
) -> None:
    """Единый стиль для всех нумерованных меню."""
    table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
    table.add_column(justify="right", width=3, style=f"bold {ACCENT}")
    table.add_column(ratio=1)

    for index, (_value, label, hint) in enumerate(actions, start=1):
        caption = re.sub(r"^\d+\.\s*", "", label)
        item = Text()
        item.append(caption, style="bold")
        item.append("\n")
        item.append(hint, style=MUTED)
        table.add_row(str(index), item)

    console.print()
    console.print(
        Panel(
            table,
            title=f"[bold {ACCENT}]{title}[/]",
            border_style=ACCENT,
            padding=(0, 1),
        )
    )


def _select_action() -> str | None:
    """Нативное меню на rich.Prompt с повторным вводом при ошибке."""
    actions = _menu_actions()
    _render_action_menu(actions, "Главное меню")
    console.print(
        f"[{MUTED}]Подсказка: Enter — пункт 1 · G — игра · "
        "F — автопоиск · Ctrl+C — обновить[/]"
    )
    console.print()
    while True:
        raw = Prompt.ask(
            "[bold]Выберите пункт[/]",
            default="1",
            show_default=False,
        ).strip()
        if raw.lower() == "g":
            return "game"
        if raw.lower() == "f":
            return "blockcheck"
        if raw.isdigit():
            index = int(raw)
            if 1 <= index <= len(actions):
                return actions[index - 1][0]
        console.print(
            f"[{RED}]Нужен номер от 1 до {len(actions)}, G или F. "
            "Попробуйте снова.[/]"
        )


def _ask_number(prompt: str, choices: list[int], default: int) -> int:
    """Спрашивает число из choices, повторяя ввод при ошибке."""
    while True:
        try:
            value = IntPrompt.ask(prompt, default=default)
        except (TypeError, ValueError):
            value = None
        if value in choices:
            return value
        console.print(
            f"[{RED}]Нужен номер из списка: "
            f"{', '.join(str(choice) for choice in choices)}.[/]"
        )


def _pause() -> None:
    console.print()
    Prompt.ask(f"[{MUTED}]Enter — вернуться в меню[/]", default="", show_default=False)


def _show_system_report(report: SystemReport) -> None:
    """Показывает состояние платформы и обязательных инструментов."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style=MUTED, no_wrap=True)
    table.add_column()

    arch = "Arch-based" if report.is_arch_based else "не Arch"
    table.add_row("Система", f"{report.distro_name}  [dim]({arch})[/]")

    if report.aur_helper_path:
        helper = f"[{MINT}]✓[/] {report.aur_helper}  [dim]{report.aur_helper_path}[/]"
    else:
        helper = f"[{AMBER}]—[/] не найден"
    table.add_row("AUR-хелпер", helper)

    for tool in report.tools:
        if tool.found:
            value = f"[{MINT}]✓[/] {tool.path}"
        elif tool.required:
            value = f"[{RED}]✗[/] не найден"
        else:
            value = f"[{AMBER}]—[/] не найден"
        table.add_row(tool.label, value)

    console.print()
    console.print(
        Panel(
            table,
            title="[bold]Проверка системы[/]",
            border_style=ACCENT,
            padding=(0, 1),
        )
    )

    if report.issues:
        console.print(
            Panel(
                Text("\n".join(report.issues)),
                title=f"[{RED}]Блокеры[/]",
                border_style=RED,
                padding=(0, 1),
            )
        )
    if report.warnings:
        console.print(
            Panel(
                Text("\n".join(report.warnings)),
                title=f"[{AMBER}]Предупреждения[/]",
                border_style=AMBER,
                padding=(0, 1),
            )
        )


def _quickstart() -> None:
    """Проверяет систему и устанавливает zapret2 после подтверждения."""
    report = detect_system()
    _show_system_report(report)
    plan = build_install_plan(report)

    if plan.already_installed:
        logger.info("Установка не нужна: %s", plan.reason)
        console.print()
        console.print(
            Panel(
                f"[bold {MINT}]zapret2 уже установлен[/]\n"
                f"[{MUTED}]Следующие шаги: выбор стратегии и запуск службы.[/]",
                border_style=MINT,
                padding=(1, 2),
            )
        )
        _pause()
        return

    if not plan.can_install:
        logger.warning("Установка невозможна: %s", plan.reason)
        console.print()
        console.print(
            Panel(
                Text(plan.reason),
                title=f"[{RED}]Установка невозможна[/]",
                border_style=RED,
                padding=(1, 2),
            )
        )
        _pause()
        return

    description = "\n\n".join(
        f"{step.description}\n[dim]$ {step.command}[/]" for step in plan.steps
    )
    console.print()
    console.print(
        Panel(
            Text.from_markup(description),
            title="[bold]План установки[/]",
            border_style=MINT,
            padding=(1, 2),
        )
    )
    console.print(
        f"[{MUTED}]Сборка AUR идёт от обычного пользователя. "
        "Установка пакета внутри хелпера выполняется через pkexec.[/]"
    )

    if not Confirm.ask(
        f"[bold]Установить {PACKAGE_NAME} из AUR сейчас?[/]",
        default=False,
    ):
        logger.info("Пользователь отменил установку zapret2")
        console.print(f"[{AMBER}]Установка отменена.[/]")
        _pause()
        return

    logger.info("Пользователь подтвердил установку zapret2")
    console.print(
        f"[{MUTED}]Собираю и устанавливаю zapret2... "
        "Это может занять несколько минут.[/]"
    )
    result = install_zapret2(plan, dry_run=False)

    if result.ok:
        console.print()
        console.print(
            Panel(
                f"[bold {MINT}]{result.message}[/]\n"
                f"[{MUTED}]Дальше: выбор стратегии (2), тест (3), "
                "служба (5).[/]",
                title="[bold]Готово[/]",
                border_style=MINT,
                padding=(1, 2),
            )
        )
    else:
        console.print()
        console.print(
            Panel(
                Text(result.message),
                title=f"[{RED}]Ошибка установки[/]",
                border_style=RED,
                padding=(1, 2),
            )
        )
        if result.output:
            console.print(
                Panel(
                    Text(result.output, style=MUTED),
                    title="Последние строки вывода",
                    border_style=AMBER,
                    padding=(0, 1),
                )
            )
    _pause()


def _strategy_state_plain(strategy: Strategy, valid_syntax: bool) -> str:
    if strategy.error or strategy.profile.error or not valid_syntax:
        return "ошибка"
    if not strategy.profile.args:
        return "нет профиля"
    return "готова"


def _strategy_status(strategy: Strategy, valid_syntax: bool) -> str:
    state = _strategy_state_plain(strategy, valid_syntax)
    if state == "ошибка":
        return f"[{RED}]✗ ошибка[/]"
    if state == "нет профиля":
        return f"[{AMBER}]○ нет .conf[/]"
    return f"[{MINT}]✓ готова[/]"


def _strategy_profile_status(strategy: Strategy) -> str:
    if strategy.profile.error:
        return f"[{RED}]✗[/]"
    if strategy.profile.args:
        return f"[{MINT}]✓[/]"
    return f"[{AMBER}]—[/]"


def _draw_strategy_screen(
    manager: StrategyManager,
) -> tuple[list[Strategy], str | None]:
    """Рисует каталог стратегий и возвращает список и активный профиль."""
    console.clear()
    _print_header()

    strategies = manager.list_strategies()
    active_name = manager.active_name()
    console.print()
    console.print(
        f"  Папка стратегий: [{MUTED}]{escape(str(manager.strategies_dir))}[/]"
    )

    if not strategies:
        console.print()
        console.print(
            Panel(
                Text(
                    "В каталоге нет файлов *.lua. "
                    "Добавьте проверенную стратегию и повторите."
                ),
                title=f"[{AMBER}]Стратегии не найдены[/]",
                border_style=AMBER,
                padding=(1, 2),
            )
        )
        _pause()
        return strategies, active_name

    table = Table(
        box=None,
        show_header=True,
        header_style=MUTED,
        padding=(0, 2),
    )
    table.add_column("", width=1)
    table.add_column("Стратегия", min_width=18)
    table.add_column("Размер", justify="right")
    table.add_column("Профиль", justify="center")
    table.add_column("Состояние")

    broken: list[tuple[str, str]] = []
    for strategy in strategies:
        is_active = strategy.name == active_name
        marker = f"[{MINT}]●[/]" if is_active else " "
        name = escape(strategy.name)
        if is_active:
            name = f"[bold]{name}[/]"

        validation = manager.validate(strategy)
        if strategy.error:
            broken.append((strategy.name, strategy.error))
        elif strategy.profile.error:
            broken.append((strategy.name, strategy.profile.error))
        elif not validation.valid:
            broken.append((strategy.name, "\n".join(validation.errors)))

        table.add_row(
            marker,
            name,
            strategy.size_label,
            _strategy_profile_status(strategy),
            _strategy_status(strategy, validation.valid),
        )

    console.print()
    console.print(
        Panel(
            table,
            title="[bold]Lua-стратегии[/]",
            border_style=ACCENT,
            padding=(0, 1),
        )
    )

    if active_name:
        console.print(
            f"  Активная: [bold {MINT}]{escape(active_name)}[/]"
        )
        if not any(strategy.name == active_name for strategy in strategies):
            console.print(
                Panel(
                    Text(
                        f"Активная стратегия «{active_name}» отсутствует в каталоге."
                    ),
                    border_style=AMBER,
                    padding=(0, 1),
                )
            )
    else:
        console.print(f"  Активная: [{MUTED}]не выбрана[/]")

    if broken:
        lines = [f"{name}: {reason}" for name, reason in broken]
        console.print(
            Panel(
                Text("\n\n".join(lines)),
                title=f"[{RED}]Файлы с ошибками[/]",
                border_style=RED,
                padding=(0, 1),
            )
        )

    if any(not strategy.profile.args for strategy in strategies):
        console.print(
            f"[{MUTED}]Стратегия готова, когда в <name>.conf есть аргументы "
            "nfqws2. Сейчас такие профили — заглушки.[/]"
        )

    return strategies, active_name


def _select_strategy(
    manager: StrategyManager,
    strategies: list[Strategy],
    active_name: str | None,
) -> str | None:
    """Нативный выбор стратегии с повторным вводом."""
    console.print()
    table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
    table.add_column(width=1)
    table.add_column(justify="right", width=3, style=f"bold {ACCENT}")
    table.add_column(ratio=1)
    table.add_column(justify="right")

    for index, strategy in enumerate(strategies, start=1):
        is_active = strategy.name == active_name
        marker = (
            Text("●", style=f"bold {MINT}")
            if is_active
            else Text(" ")
        )
        validation = manager.validate(strategy)
        table.add_row(
            marker,
            str(index),
            Text(strategy.name, style="bold" if is_active else None),
            _strategy_status(strategy, validation.valid),
        )

    table.add_row(
        "",
        "D",
        Text("Скачать популярные стратегии"),
        Text("из интернета", style=MUTED),
    )
    table.add_row(
        "",
        "0",
        Text("Назад"),
        Text("в главное меню", style=MUTED),
    )
    console.print(
        Panel(
            table,
            title="[bold]Выбор стратегии[/]",
            border_style=ACCENT,
            padding=(0, 1),
        )
    )

    available_names = [strategy.name for strategy in strategies]
    default_index = (
        available_names.index(active_name) + 1
        if active_name in available_names
        else 1
    )
    while True:
        raw = Prompt.ask(
            "\n[bold]Номер стратегии или D[/]",
            default=str(default_index),
            show_default=False,
        ).strip()
        if raw.lower() == "d":
            return DOWNLOAD_STRATEGY_CHOICE
        if raw.isdigit():
            selected = int(raw)
            if selected == 0:
                return None
            if 1 <= selected <= len(strategies):
                return strategies[selected - 1].name
        console.print(
            f"[{RED}]Введите номер от 0 до {len(strategies)} или D.[/]"
        )


def _show_community_result(result: CommunityImportResult) -> None:
    sections: list[tuple[str, str, str]] = []
    if result.imported:
        sections.append(
            (
                "Импортировано",
                "\n".join(f"✓ {name}" for name in result.imported),
                MINT,
            )
        )
    if result.skipped:
        sections.append(
            (
                "Пропущено",
                "\n".join(f"• {item}" for item in result.skipped),
                AMBER,
            )
        )
    if result.errors:
        sections.append(
            (
                "Ошибки",
                "\n".join(f"✗ {item}" for item in result.errors),
                RED,
            )
        )
    if result.notes:
        sections.append(
            (
                "Примечания",
                "\n".join(f"· {item}" for item in result.notes),
                MUTED,
            )
        )

    body = Text()
    for index, (title, content, color) in enumerate(sections):
        if index:
            body.append("\n\n")
        body.append(title + "\n", style=f"bold {color}")
        body.append(content, style=color)
    if not sections:
        body.append("Источники ничего не вернули.", style=AMBER)

    console.print()
    console.print(
        Panel(
            body,
            title="[bold]Community-стратегии[/]",
            border_style=MINT if result.imported else AMBER,
            padding=(1, 2),
        )
    )
    if result.imported:
        console.print(
            f"  [{MUTED}]Активная стратегия не изменена. "
            "Выберите новую в списке.[/]"
        )


def _download_community_strategies(manager: StrategyManager) -> None:
    supported = [source for source in COMMUNITY_SOURCES if source.supported]
    source_lines = "\n".join(
        f"• {source.name} — {source.description}" for source in supported
    )
    console.print()
    console.print(
        Panel(
            Text(
                "Будут скачаны только текстовые .conf/.lua и hostlists "
                "из фиксированных HTTPS-источников. Скачанные скрипты и "
                ".bat не выполняются. Активная стратегия не меняется.\n\n"
                + source_lines
            ),
            title="[bold]Скачать популярные стратегии[/]",
            border_style=ACCENT,
            padding=(0, 1),
        )
    )
    if not Confirm.ask(
        "Скачать стратегии из этих источников?",
        default=True,
    ):
        return

    try:
        console.print(
            f"[{MUTED}]Скачиваю и проверяю стратегии...[/]"
        )
        result = fetch_community_strategies(manager.strategies_dir)
    except StrategyError as exc:
        logger.warning("Импорт community-стратегий не удался: %s", exc)
        console.print()
        console.print(
            Panel(
                Text(str(exc)),
                title=f"[{RED}]Импорт не удался[/]",
                border_style=RED,
                padding=(1, 2),
            )
        )
        _pause()
        return

    _show_community_result(result)
    _pause()


def _manage_strategies() -> None:
    """Экран выбора и сохранения активной Lua-стратегии."""
    manager = StrategyManager()
    while True:
        strategies, active_name = _draw_strategy_screen(manager)
        if not strategies:
            if Confirm.ask(
                "В каталоге нет стратегий. Скачать популярные?",
                default=True,
            ):
                _download_community_strategies(manager)
                continue
            return

        choice = _select_strategy(manager, strategies, active_name)
        if choice is None:
            return
        if choice == DOWNLOAD_STRATEGY_CHOICE:
            _download_community_strategies(manager)
            continue

        try:
            selected = manager.set_active(choice)
        except StrategyError as exc:
            logger.warning("Стратегия отклонена: %s", exc)
            console.print()
            console.print(
                Panel(
                    Text(str(exc)),
                    title=f"[{RED}]Стратегия отклонена[/]",
                    border_style=RED,
                    padding=(1, 2),
                )
            )
            _pause()
            continue

        message = Text()
        message.append("Активная стратегия: ", style=MUTED)
        message.append(selected.name, style=f"bold {MINT}")
        message.append("\nКонфиг: ", style=MUTED)
        message.append(str(manager.config_file), style=MUTED)

        console.print()
        console.print(
            Panel(
                message,
                title="[bold]Сохранено[/]",
                border_style=MINT,
                padding=(1, 2),
            )
        )
        if not selected.profile.args:
            console.print(
                Panel(
                    Text(
                        "В .conf нет аргументов nfqws2. Перед запуском "
                        "добавьте проверенный профиль стратегии."
                    ),
                    title=f"[{AMBER}]Внимание[/]",
                    border_style=AMBER,
                    padding=(0, 1),
                )
            )
        _pause()


def _test_strategies() -> None:
    """Старый тестер удалён из UI; проверка идёт через blockcheckw."""
    console.clear()
    _print_header()
    console.print()
    console.print(
        Panel(
            Text(
                "Старый тестер стратегий больше не используется.\n\n"
                "Для проверки и автопоиска стратегий используйте "
                "пункт 4: [F] ⚡ Автопоиск идеальной стратегии (blockcheckw)."
            ),
            title=f"[{AMBER}]Тест стратегий отключён[/]",
            border_style=AMBER,
            padding=(1, 2),
        )
    )
    _pause()


def _show_autosearch_results(status_msg: str) -> None:
    """Показывает per-domain картину из auto_best.report.json."""
    del status_msg
    try:
        payload = json.loads(
            AUTO_BEST_REPORT_FILE.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, ValueError):
        return
    if not isinstance(payload, dict):
        return

    raw_profiles = payload.get("profiles")
    profiles = raw_profiles if isinstance(raw_profiles, dict) else {}
    raw_domains = payload.get("domains")
    if isinstance(raw_domains, list):
        domains = [str(item) for item in raw_domains]
    else:
        domains = list(profiles)
    if not domains:
        return

    table = Table(
        title="Результаты автопоиска по доменам",
        box=None,
        header_style=MUTED,
        padding=(0, 2),
        expand=True,
    )
    table.add_column("Домен", no_wrap=True)
    table.add_column("Стратегия", ratio=1, overflow="fold")
    table.add_column("Медиана (ms)", justify="right")
    table.add_column("Статус")

    for domain in domains:
        raw_profile = profiles.get(domain)
        if isinstance(raw_profile, dict):
            strategy = raw_profile.get("strategy")
            if not isinstance(strategy, str) or not strategy:
                raw_args = raw_profile.get("args")
                strategy = (
                    " ".join(str(item) for item in raw_args)
                    if isinstance(raw_args, list)
                    else "—"
                )
            median = raw_profile.get("median_latency_ms")
            median_text = (
                str(median)
                if isinstance(median, (int, float))
                else "—"
            )
            status = f"[{MINT}]✓ подтверждено[/]"
        else:
            strategy = "—"
            median_text = "—"
            status = f"[{AMBER}]Нет профиля[/]"

        table.add_row(
            escape(domain),
            escape(str(strategy)),
            median_text,
            status,
        )

    console.print()
    console.print(table)


def _blockcheck_autosearch() -> None:
    """Запускает blockcheckw без анимаций и применяет результат."""
    console.clear()
    _print_header()
    console.print()
    console.print(
        Panel(
            Text(
                "Поиск выполняется современным Rust-бинарником blockcheckw.\n"
                "Старые blockcheck.sh и blockcheck2.sh не используются.\n\n"
                "Поиск адаптивный: сначала YouTube и Discord, затем при "
                "необходимости Twitch и Steam. Стратегия сохраняется только "
                "после проверки на всех целях.\n\n"
                "Для сканирования нужны root-права: пароль запросит Polkit "
                "через pkexec.\n"
                "Поиск может занять до 30 минут. Не закрывайте терминал.\n"
                "Нажмите Ctrl+C для отмены."
            ),
            title="[bold]⚡ Автопоиск идеальной стратегии[/]",
            border_style=ACCENT,
            padding=(1, 2),
        )
    )

    last_message = ""

    def on_progress(event: dict[str, object]) -> None:
        nonlocal last_message
        if event.get("event") not in {"status", "latency"}:
            return
        message = str(event.get("message") or "").strip()
        if message and message != last_message:
            console.print(f"[{MUTED}]{escape(message)}[/]")
            last_message = message

    ok = False
    status_msg = "Автопоиск завершился без результата."
    try:
        ok, status_msg = run_blockcheck(on_progress=on_progress)
    except KeyboardInterrupt:
        logger.info("Автопоиск blockcheckw отменён пользователем")
        console.clear()
        return
    except Exception as exc:  # защита TUI
        logger.exception("Ошибка автопоиска blockcheckw")
        ok, status_msg = False, f"Ошибка автопоиска: {exc}"

    if ok:
        _show_autosearch_results(status_msg)

    console.print()
    console.print(
        Panel(
            Text(status_msg),
            title="[bold]Результат автопоиска[/]",
            border_style=MINT if ok else RED,
            padding=(1, 2),
        )
    )

    if not ok:
        if "отменено" in status_msg.lower():
            console.clear()
            return
        _pause()
        return

    if not Confirm.ask(
        "Применить новую стратегию и перезапустить сервис?",
        default=False,
    ):
        _pause()
        return

    console.print(
        f"[{MUTED}]Запускаю pkexec. Пароль запрашивает Polkit.[/]"
    )
    try:
        apply_ok, apply_msg = apply_auto_best()
    except KeyboardInterrupt:
        console.clear()
        logger.info("Применение auto_best отменено пользователем")
        return
    except Exception as exc:  # защита TUI
        logger.exception("Ошибка применения auto_best")
        apply_ok, apply_msg = False, f"Ошибка применения стратегии: {exc}"

    console.print()
    console.print(
        Panel(
            Text(apply_msg),
            title="[bold]Применение auto_best[/]",
            border_style=MINT if apply_ok else RED,
            padding=(1, 2),
        )
    )
    _pause()


def _service_state_label(active: bool, enabled: bool) -> str:
    if active:
        label = f"[{MINT}]● активна[/]"
    else:
        label = f"[{AMBER}]○ не запущена[/]"
    if enabled:
        label += f" [{MUTED}]· автозапуск[/]"
    else:
        label += f" [{MUTED}]· без автозапуска[/]"
    return label


def _show_service_status(
    manager: StrategyManager,
    status: ServiceStatus,
) -> None:
    """Показывает состояние службы и пакетного zapret2."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style=MUTED, no_wrap=True)
    table.add_column()

    unit = (
        escape(str(status.unit_path))
        if status.installed
        else "не установлен"
    )
    table.add_row("Unit", unit)
    table.add_row("Служба", _service_state_label(status.active, status.enabled))
    table.add_row("Состояние", escape(status.detail))
    table.add_row(
        "Стратегия",
        escape(manager.active_name() or "не выбрана"),
    )

    if status.package_active:
        package = f"[{RED}]● активна[/]"
    elif status.package_enabled:
        package = f"[{AMBER}]○ включена[/]"
    else:
        package = f"[{MUTED}]— не активна[/]"
    table.add_row("zapret2.service", package)

    if status.installed and not status.ours:
        table.add_row(
            "Внимание",
            f"[{RED}]файл unit создан не zapret-easy[/]",
        )

    console.print()
    console.print(
        Panel(
            table,
            title="[bold]Служба zapret-easy[/]",
            border_style=ACCENT,
            padding=(0, 1),
        )
    )

    if status.package_conflict:
        console.print(
            Panel(
                Text(
                    "Пакетная служба zapret2.service уже активна или включена. "
                    "Второй nfqws2 запускать нельзя. Остановите и отключите её:\n"
                    "sudo systemctl disable --now zapret2.service"
                ),
                title=f"[{RED}]Конфликт служб[/]",
                border_style=RED,
                padding=(0, 1),
            )
        )


def _show_service_preflight(preflight: ServicePreflight) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=MUTED, no_wrap=True)
    table.add_column()
    table.add_row("Пользователь", escape(preflight.user or "не определён"))
    table.add_row(
        "Стратегия",
        escape(preflight.strategy_name or "не выбрана"),
    )
    table.add_row(
        "Порты",
        f"TCP: {escape(preflight.ports_tcp or '—')}   "
        f"UDP: {escape(preflight.ports_udp or '—')}",
    )
    table.add_row(
        "nfqws2",
        escape(str(preflight.nfqws2)) if preflight.nfqws2 else "не найден",
    )

    console.print()
    console.print(
        Panel(
            table,
            title="[bold]Параметры установки[/]",
            border_style=ACCENT,
            padding=(0, 1),
        )
    )

    if preflight.errors:
        console.print()
        console.print(
            Panel(
                Text("\n".join(preflight.errors)),
                title=f"[{RED}]Установка невозможна[/]",
                border_style=RED,
                padding=(1, 2),
            )
        )
    if preflight.warnings:
        console.print()
        console.print(
            Panel(
                Text("\n".join(preflight.warnings)),
                title=f"[{AMBER}]Перед установкой[/]",
                border_style=AMBER,
                padding=(0, 1),
            )
        )


def _show_service_result(result: ServiceResult) -> None:
    title = "Готово" if result.ok else "Ошибка службы"
    border = MINT if result.ok else RED
    console.print()
    console.print(
        Panel(
            Text(result.message),
            title=f"[{border}]{title}[/]",
            border_style=border,
            padding=(1, 2),
        )
    )
    if result.output:
        console.print(
            Panel(
                Text(result.output, style=MUTED),
                title="Вывод команды",
                border_style=AMBER,
                padding=(0, 1),
            )
        )


def _service_install(service: ServiceManager) -> None:
    console.clear()
    _print_header()
    _show_service_status(service.manager, service.status())
    console.print(f"[{MUTED}]Проверяю готовность службы...[/]")
    preflight = service.preflight()
    _show_service_preflight(preflight)
    if not preflight.ok:
        _pause()
        return

    if not Confirm.ask(
        f"[bold]Установить и запустить {escape('zapret-easy.service')}?[/]",
        default=False,
    ):
        logger.info("Пользователь отменил установку службы")
        _pause()
        return

    logger.info(
        "Пользователь подтвердил установку службы: %s",
        preflight.strategy_name,
    )
    console.print(
        f"[{MUTED}]Запускаю pkexec. Пароль запрашивает Polkit; "
        "не закрывайте терминал.[/]"
    )
    result = service.install(preflight)
    _show_service_result(result)
    _pause()


def _service_start(service: ServiceManager) -> None:
    console.clear()
    _print_header()
    status = service.status()
    _show_service_status(service.manager, status)
    if status.active:
        console.print(f"[{MINT}]Служба уже активна.[/]")
        _pause()
        return
    if not status.installed:
        console.print(
            Panel(
                Text(
                    "Служба не установлена. Сначала выполните "
                    "«Установить и запустить»."
                ),
                title=f"[{AMBER}]Нечего запускать[/]",
                border_style=AMBER,
                padding=(1, 2),
            )
        )
        _pause()
        return
    if status.package_active or status.package_enabled:
        console.print(
            Panel(
                Text(
                    "Обнаружена zapret2.service. Остановите и отключите её, "
                    "иначе два nfqws2 будут конфликтовать за очередь и "
                    "правила nftables."
                ),
                title=f"[{RED}]Конфликт со службой пакета[/]",
                border_style=RED,
                padding=(1, 2),
            )
        )
        _pause()
        return
    if not Confirm.ask(
        f"[bold]Запустить {escape('zapret-easy.service')} сейчас?[/]",
        default=True,
    ):
        _pause()
        return

    console.print(
        f"[{MUTED}]Запускаю pkexec. Пароль запрашивает Polkit.[/]"
    )
    result = service.start()
    _show_service_result(result)
    _pause()


def _service_stop(service: ServiceManager) -> None:
    console.clear()
    _print_header()
    status = service.status()
    _show_service_status(service.manager, status)
    if not status.installed and not status.active:
        console.print(f"[{MUTED}]Служба не установлена.[/]")
        _pause()
        return
    if not Confirm.ask(
        f"[bold]Остановить {escape('zapret-easy.service')}?[/]",
        default=True,
    ):
        _pause()
        return

    console.print(
        f"[{MUTED}]Запускаю pkexec. Пароль запрашивает Polkit.[/]"
    )
    result = service.stop()
    _show_service_result(result)
    _pause()


def _service_rollback(service: ServiceManager) -> None:
    console.clear()
    _print_header()
    status = service.status()
    _show_service_status(service.manager, status)
    if status.package_active:
        console.print(
            Panel(
                Text(
                    "Сначала остановите zapret2.service. Пока она активна, "
                    "откат может перезаписать таблицу inet zapret2, "
                    "которой пользуется пакет."
                ),
                title=f"[{RED}]Конфликт со службой пакета[/]",
                border_style=RED,
                padding=(1, 2),
            )
        )
        _pause()
        return
    console.print(
        Panel(
            Text(
                "Будут выполнены: systemctl stop/disable, удаление "
                "/etc/systemd/system/zapret-easy.service и wants-ссылки, "
                "daemon-reload, reset-failed, stop_fw и восстановление "
                "только таблицы inet zapret2 из снимка. Полный backup "
                "nftables остаётся как аварийная страховка."
            ),
            title=f"[{AMBER}]Что делает откат[/]",
            border_style=AMBER,
            padding=(0, 1),
        )
    )
    if not Confirm.ask(
        f"[bold {RED}]Полностью удалить службу zapret-easy?[/]",
        default=False,
    ):
        logger.info("Пользователь отменил откат службы")
        _pause()
        return

    logger.info("Пользователь подтвердил откат службы")
    console.print(
        f"[{MUTED}]Запускаю pkexec. Пароль запрашивает Polkit.[/]"
    )
    result = service.rollback()
    _show_service_result(result)
    _pause()


def _disable_all_services() -> None:
    """Останавливает и отключает все известные zapret-службы."""
    console.clear()
    _print_header()
    service = ServiceManager()
    _show_service_status(service.manager, service.status())

    console.print(
        Panel(
            Text(
                "Будет выполнено systemctl stop + disable для:\n"
                + "\n".join(f"  • {unit}" for unit in ZAPRET_UNITS)
                + "\n\nUnit-файлы, стратегии и настройки не удаляются. "
                "Обход DPI будет выключен до ручного включения."
            ),
            title=f"[bold {AMBER}]Полное выключение zapret[/]",
            border_style=AMBER,
            padding=(1, 2),
        )
    )
    if not Confirm.ask(
        f"[bold {RED}]Остановить и отключить все службы zapret?[/]",
        default=False,
    ):
        logger.info("Пользователь отменил полное выключение служб")
        _pause()
        return

    logger.info("Пользователь подтвердил полное выключение служб zapret")
    console.print(
        f"[{MUTED}]Запускаю pkexec. Пароль запрашивает Polkit.[/]"
    )
    result = service.disable_all()
    _show_service_result(result)
    _pause()


def _show_tweak_status(status: TweakStatus) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column("Параметр", style=MUTED, no_wrap=True)
    table.add_column("Сейчас")
    for key, label in _TWEAK_LABELS.items():
        value = status.current.get(key, "—")
        table.add_row(label, escape(value))

    console.print()
    console.print(
        Panel(
            table,
            title="[bold]Сетевой стек сейчас[/]",
            border_style=ACCENT,
            padding=(0, 1),
        )
    )

    file_state = (
        "создан zapret-easy"
        if status.file_ours
        else ("чужой файл" if status.file_exists else "нет")
    )
    console.print(
        f"  Файл: [bold]{escape(str(SYSCTL_FILE))}[/] "
        f"[{MUTED}]({file_state})[/]"
    )
    console.print(
        f"  Доступно qdisc: [{MUTED}]{', '.join(status.qdiscs)}[/]"
        f"   BBR: {'да' if status.bbr_available else 'нет'}"
    )
    if status.backup_file:
        console.print(
            f"  Backup: [{MUTED}]{escape(str(status.backup_file))}[/]"
        )
    if status.before_file:
        console.print(
            f"  Точка возврата: [{MINT}]есть[/]"
        )

    if status.file_exists and not status.file_ours:
        console.print()
        console.print(
            Panel(
                Text(
                    "Файл 99-zapret-easy.conf уже существует и создан не "
                    "zapret-easy. Перед изменением он будет сохранён в "
                    "/var/lib/zapret-easy/tweaks/."
                ),
                title=f"[{AMBER}]Внимание[/]",
                border_style=AMBER,
                padding=(0, 1),
            )
        )
    if not status.bbr_available:
        console.print(
            f"[{MUTED}]BBR отсутствует в tcp_available_congestion_control: "
            "пункт BBR будет пропущен.[/]"
        )


def _show_tweak_result(result: TweakResult) -> None:
    text = Text(result.message)
    if result.output:
        output = result.output.strip()
        if len(output) > 2000:
            output = output[-2000:]
        text.append("\n\n", style=MUTED)
        text.append(output)
    console.print()
    console.print(
        Panel(
            text,
            title="[bold]Твики[/]" if result.ok else f"[{RED}]Ошибка[/]",
            border_style=MINT if result.ok else RED,
            padding=(1, 2),
        )
    )


def _select_tweak_action(status: TweakStatus) -> str | None:
    actions = [
        action
        for action in TWEAK_ACTIONS
        if action[0] != "revert"
        or status.file_ours
        or status.before_file
    ]
    _render_action_menu(actions, "Сетевые твики")
    index = _ask_number(
        "\n[bold]Пункт[/]",
        [number for number in range(1, len(actions) + 1)],
        1,
    )
    return actions[index - 1][0]


def _choose_tweak_options(status: TweakStatus) -> TweakOptions | None:
    qdisc_name = "cake" if "cake" in status.qdiscs else "fq"
    console.print()
    qdisc = Confirm.ask(
        f"Очередь {qdisc_name} (fq/cake)?",
        default=True,
    )
    bbr = (
        Confirm.ask("Включить BBR?", default=True)
        if status.bbr_available
        else False
    )
    if not status.bbr_available:
        console.print(f"[{MUTED}]BBR недоступен и будет пропущен.[/]")
    backlog = Confirm.ask(
        "Поднять netdev_max_backlog до 4096?", default=True
    )
    fastopen = Confirm.ask("Включить TCP Fast Open (3)?", default=True)
    mtu_probing = Confirm.ask(
        "Включить TCP MTU probing?", default=True
    )
    ip_forward = Confirm.ask(
        "Включить ip_forward=1 (VPN/контейнеры)?",
        default=False,
    )
    return TweakOptions(
        qdisc="auto" if qdisc else None,
        bbr=bbr,
        netdev_backlog=backlog,
        tcp_fastopen=fastopen,
        tcp_mtu_probing=mtu_probing,
        ip_forward=ip_forward,
    )


def _network_tweaks() -> None:
    manager = TweakManager()
    while True:
        console.clear()
        _print_header()
        status = manager.status()
        _show_tweak_status(status)
        action = _select_tweak_action(status)
        if action is None or action == "back":
            return

        if action == "revert":
            if not status.file_ours and not status.before_file:
                console.print(
                    Panel(
                        Text("Нет файла твиков zapret-easy и точки возврата."),
                        border_style=AMBER,
                        padding=(0, 1),
                    )
                )
                _pause()
                continue
            console.print(
                Panel(
                    Text(
                        "Будут удалены только твики zapret-easy, а "
                        "значения из before.json будут применены обратно. "
                        "Остальные sysctl-настройки не затрагиваются."
                    ),
                    title=f"[{AMBER}]Удаление твиков[/]",
                    border_style=AMBER,
                    padding=(0, 1),
                )
            )
            if not Confirm.ask(
                f"[bold {RED}]Удалить твики и вернуть старые значения?[/]",
                default=False,
            ):
                _pause()
                continue
            console.print(
                f"[{MUTED}]Запускаю pkexec. Пароль запрашивает Polkit.[/]"
            )
            _show_tweak_result(manager.revert())
            _pause()
            continue

        if action != "apply":
            continue

        options = _choose_tweak_options(status)
        if options is None:
            continue
        if not any(
            (
                options.qdisc is not None,
                options.bbr,
                options.netdev_backlog,
                options.tcp_fastopen,
                options.tcp_mtu_probing,
                options.ip_forward,
            )
        ):
            console.print(
                f"[{AMBER}]Ничего не выбрано.[/]"
            )
            _pause()
            continue

        selected = []
        if options.qdisc is not None:
            selected.append("qdisc=fq/cake (авто)")
        if options.bbr:
            selected.append("BBR")
        if options.netdev_backlog:
            selected.append("netdev_max_backlog=4096")
        if options.tcp_fastopen:
            selected.append("tcp_fastopen=3")
        if options.tcp_mtu_probing:
            selected.append("tcp_mtu_probing=1")
        if options.ip_forward:
            selected.append("ip_forward=1")

        console.print()
        console.print(
            Panel(
                Text(
                    "Будет записан /etc/sysctl.d/99-zapret-easy.conf:\n"
                    + "\n".join(f"• {item}" for item in selected)
                    + "\n\nПеред записью — backup; затем sysctl -p и "
                    "проверка фактических значений."
                ),
                title="[bold]План[/]",
                border_style=ACCENT,
                padding=(0, 1),
            )
        )
        if options.ip_forward:
            console.print(
                Panel(
                    Text(
                        "ip_forward=1 нужен только для VPN, контейнеров "
                        "или маршрутизации. Если не уверены — снимите "
                        "галочку."
                    ),
                    title=f"[{AMBER}]VPN/контейнеры[/]",
                    border_style=AMBER,
                    padding=(0, 1),
                )
            )
        if status.file_exists and not status.file_ours:
            console.print(
                f"[{AMBER}]Существующий файл будет сохранён в backup.[/]"
            )
        if not Confirm.ask(
            "[bold]Применить выбранные твики?[/]",
            default=False,
        ):
            _pause()
            continue

        console.print(
            f"[{MUTED}]Запускаю pkexec. Пароль запрашивает Polkit.[/]"
        )
        _show_tweak_result(manager.apply(options))
        _pause()


def _select_settings_action() -> str | None:
    _render_action_menu(SETTINGS_ACTIONS, "Служба и настройки")
    index = _ask_number(
        "\n[bold]Пункт[/]",
        list(range(1, len(SETTINGS_ACTIONS) + 1)),
        len(SETTINGS_ACTIONS),
    )
    return SETTINGS_ACTIONS[index - 1][0]


def _settings() -> None:
    """Экран управления systemd-службой и откатом."""
    service = ServiceManager()
    while True:
        console.clear()
        _print_header()
        status = service.status()
        _show_service_status(service.manager, status)

        action = _select_settings_action()
        if action is None or action == "back":
            return
        if action == "status":
            _pause()
            continue
        if action == "install":
            _service_install(service)
            continue
        if action == "start":
            _service_start(service)
            continue
        if action == "stop":
            _service_stop(service)
            continue
        if action == "rollback":
            _service_rollback(service)
            continue
        if action == "tweaks":
            _network_tweaks()
            continue

        logger.warning("Неизвестное действие экрана службы: %s", action)


def _game_mode() -> None:
    """Экран включения/выключения игрового режима."""
    manager = GameModeManager()
    status = manager.status()

    console.print()
    if status.active:
        console.print(
            Panel(
                Text(
                    "Игровой режим сейчас активен.\n"
                    "Будут возвращены CPU governor, sysctl-буферы, qdisc, "
                    "watchdog и исходный active.conf.",
                    style=f"bold {ACCENT}",
                ),
                title="🎮 Game Mode",
                border_style=ACCENT,
            )
        )
        if not Confirm.ask(
            "Выключить игровой режим?",
            default=False,
        ):
            return
        console.print(
            f"[{MUTED}]Запускаю pkexec. Пароль запрашивает Polkit.[/]"
        )
        result = manager.disable()
    else:
        body = Text()
        body.append(
            "Игровой режим добавит UDP-профили поверх текущей стратегии "
            "nfqws2. YouTube-профиль не будет заменён или остановлен.\n\n",
            style=f"bold {ACCENT}",
        )
        body.append("Будет применено:\n", style="bold white")
        body.append("  • CPU governor performance (cpupower)\n")
        body.append("  • net.core.rmem_max / wmem_max = 26214400\n")
        body.append("  • fq_codel на интерфейсе маршрута по умолчанию\n")
        body.append("  • остановка watchdog-таймера, если он есть\n")
        body.append(
            "  • UDP-правила DBD 19294-19344, STUN, стандартные "
            "игровые порты и Discord 50000-65535\n"
        )
        console.print(
            Panel(
                body,
                title="🎮 Включить Game Mode",
                border_style=ACCENT,
            )
        )
        if status.stale:
            console.print(
                f"[{AMBER}]  Найдено состояние прошлой загрузки; "
                "оно будет заменено новым.[/]"
            )
        if not Confirm.ask(
            "Применить игровой режим через pkexec?",
            default=False,
        ):
            return
        console.print(
            f"[{MUTED}]Запускаю pkexec. Пароль запрашивает Polkit.[/]"
        )
        result = manager.enable()

    _show_game_result(result)
    _set_game_theme(result.active)


def _show_game_result(result: GameModeResult) -> None:
    """Показывает итог root-операции и список применённых бустов."""
    _set_game_theme(result.active)
    console.print()
    color = ACCENT if result.ok else RED
    body = Text()
    body.append(result.message, style=f"bold {color}")
    if result.details:
        body.append("\n")
        for detail in result.details:
            body.append("\n  • ", style=f"bold {color}")
            body.append(detail)
    console.print(
        Panel(
            body,
            title="🎮 Game Mode",
            border_style=color,
            padding=(0, 1),
        )
    )
    _pause()


def _goodbye() -> None:
    console.print()
    console.print(
        Align.center(
            Text("До встречи. Пусть DPI не мешает.", style=f"bold {ACCENT}")
        )
    )
    console.print()


def _enter_pressed() -> bool:
    """Проверяет, нажал ли пользователь Enter, не блокируя анимацию."""
    if not sys.stdin.isatty():
        return False
    try:
        ready, _, _ = select.select([sys.stdin], [], [], 0)
    except (OSError, ValueError):
        return False
    if not ready:
        return False
    try:
        line = sys.stdin.readline()
    except (OSError, ValueError):
        return False
    return line.strip() == ""


def _banner_color(ratio: float) -> str:
    """Плавный перелив cyan -> violet."""
    start = (0x22, 0xD3, 0xEE)
    end = (0xA8, 0x55, 0xF7)
    mixed = tuple(
        int(left + (right - left) * ratio)
        for left, right in zip(start, end, strict=True)
    )
    return "#{:02x}{:02x}{:02x}".format(*mixed)


def _banner_frame(word: str, subtitle: str, color: str) -> Align:
    text = Text()
    text.append(word, style=f"bold {color}")
    if subtitle:
        text.append("\n")
        text.append(subtitle, style=f"italic {MUTED}")
    return Align.center(text)


def show_animated_banner() -> None:
    """Показывает короткий баннер; Enter прерывает его сразу."""
    console.clear()
    if not console.is_terminal or not sys.stdin.isatty():
        console.print(_banner_frame("ZAPRET", "by Kyza", "#22d3ee"))
        return

    try:
        with Live(
            _banner_frame("", "", "#22d3ee"),
            console=console,
            refresh_per_second=20,
            transient=True,
        ) as live:
            shown = ""
            for char in "ZAPRET":
                if _enter_pressed():
                    return
                shown += char
                live.update(_banner_frame(shown, "", "#22d3ee"))
                time.sleep(0.055)

            subtitle = ""
            for char in "by Kyza":
                if _enter_pressed():
                    return
                subtitle += char
                live.update(_banner_frame("ZAPRET", subtitle, "#22d3ee"))
                time.sleep(0.035)

            for step in range(26):
                if _enter_pressed():
                    return
                color = _banner_color(step / 25)
                live.update(_banner_frame("ZAPRET", "by Kyza", color))
                time.sleep(0.05)
    except KeyboardInterrupt:
        logger.info("Анимация баннера прервана пользователем")
    except Exception:
        logger.exception("Не удалось показать анимированный баннер")
    finally:
        console.clear()


def run_ui() -> int:
    """Запускает цикл TUI; Ctrl+C возвращает в меню, EOF завершает."""
    try:
        show_animated_banner()
    except KeyboardInterrupt:
        logger.info("Анимация баннера прервана пользователем")
    except Exception:
        logger.exception("Не удалось показать баннер")

    try:
        while True:
            try:
                console.clear()
                _print_header()
                action = _select_action()
            except KeyboardInterrupt:
                console.clear()
                logger.info("Выбор в меню прерван пользователем")
                continue

            if action is None or action == "exit":
                _goodbye()
                logger.info("Корректный выход из TUI")
                return 0

            try:
                if action == "quickstart":
                    _quickstart()
                elif action == "strategies":
                    _manage_strategies()
                elif action == "test":
                    _test_strategies()
                elif action == "blockcheck":
                    _blockcheck_autosearch()
                elif action == "settings":
                    _settings()
                elif action == "game":
                    _game_mode()
                elif action == "disable_all":
                    _disable_all_services()
                else:
                    logger.warning("Неизвестное действие меню: %s", action)
            except KeyboardInterrupt:
                console.clear()
                logger.info("Действие меню прервано пользователем")
                continue
    except EOFError:
        _goodbye()
        logger.info("TUI завершён по EOF")
        return 0
