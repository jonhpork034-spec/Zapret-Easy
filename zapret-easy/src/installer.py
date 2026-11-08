"""Безопасная установка пакета zapret2 из AUR."""

from __future__ import annotations

import argparse
import logging
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Literal


from src.detect import SystemReport, detect_system
from src.logger import setup_logging


logger = logging.getLogger("zapret-easy")

PACKAGE_NAME = "zapret2"
INSTALL_TIMEOUT = 1800


@dataclass(frozen=True, slots=True)
class InstallStep:
    """Одна команда плана установки."""

    description: str
    argv: tuple[str, ...]
    root_via_pkexec: bool = False

    @property
    def command(self) -> str:
        return shlex.join(self.argv)


@dataclass(frozen=True, slots=True)
class InstallPlan:
    """Проверенный план установки. По умолчанию ничего не выполняет."""

    can_install: bool
    reason: str
    steps: tuple[InstallStep, ...] = ()
    already_installed: bool = False


@dataclass(frozen=True, slots=True)
class InstallResult:
    ok: bool
    status: Literal[
        "success", "dry-run", "already-installed", "blocked", "error"
    ]
    message: str
    output: str = ""
    returncode: int | None = None


def build_install_plan(report: SystemReport | None = None) -> InstallPlan:
    """Строит команду установки, не запуская её.

    AUR-хелпер запускается от обычного пользователя: makepkg не работает
    от root. Его root-вызовы идут через pkexec, переданный в --sudo.
    """
    report = report or detect_system()

    if report.nfqws2_path is not None:
        return InstallPlan(
            can_install=False,
            reason="zapret2 уже установлен: nfqws2 найден.",
            already_installed=True,
        )

    if report.issues:
        return InstallPlan(
            can_install=False,
            reason=" ".join(report.issues),
        )

    if report.aur_helper_path is None:
        return InstallPlan(
            can_install=False,
            reason=(
                "Не найден AUR-хелпер. Установите yay или paru, "
                "затем повторите попытку."
            ),
        )

    git = report.tool("git")
    if git is None or git.path is None:
        return InstallPlan(
            can_install=False,
            reason="Не найден git — он нужен для получения AUR-пакета.",
        )

    pkexec = report.tool("pkexec")
    if pkexec is None or pkexec.path is None:
        return InstallPlan(
            can_install=False,
            reason="Не найден pkexec — установка без root через Polkit невозможна.",
        )

    helper_name = report.aur_helper or os.path.basename(report.aur_helper_path)
    argv = (
        report.aur_helper_path,
        "--sudo",
        pkexec.path,
        "--noconfirm",
        "--needed",
        "-S",
        PACKAGE_NAME,
    )
    step = InstallStep(
        description=(
            f"Установка {PACKAGE_NAME} из AUR через {helper_name}: "
            "сборка от пользователя, pacman через pkexec"
        ),
        argv=argv,
        root_via_pkexec=True,
    )
    return InstallPlan(
        can_install=True,
        reason="Система готова к установке zapret2.",
        steps=(step,),
    )


def _output_tail(output: str, limit: int = 6000) -> str:
    output = output.strip()
    if len(output) <= limit:
        return output
    return "…\n" + output[-limit:]


def install_zapret2(
    plan: InstallPlan | None = None,
    *,
    dry_run: bool = True,
) -> InstallResult:
    """Выполняет план установки.

    dry_run=True — только логирует и возвращает команды, ничего не меняя.
    """
    plan = plan or build_install_plan()

    if plan.already_installed:
        return InstallResult(
            ok=True,
            status="already-installed",
            message=plan.reason,
        )
    if not plan.can_install or not plan.steps:
        logger.warning("Установка заблокирована: %s", plan.reason)
        return InstallResult(ok=False, status="blocked", message=plan.reason)

    if dry_run:
        lines = [step.command for step in plan.steps]
        for line in lines:
            logger.info("DRY-RUN: %s", line)
        return InstallResult(
            ok=True,
            status="dry-run",
            message="Тестовый режим: команды не выполнялись.",
            output="\n".join(lines),
        )

    step = plan.steps[0]
    logger.info("Запуск установки: %s", step.command)
    env = os.environ.copy()
    env.setdefault("NO_COLOR", "1")

    try:
        completed = subprocess.run(
            list(step.argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=INSTALL_TIMEOUT,
            check=False,
            env=env,
        )
    except FileNotFoundError:
        message = f"Команда установки не найдена: {step.argv[0]}"
        logger.error(message)
        return InstallResult(ok=False, status="error", message=message)
    except subprocess.TimeoutExpired:
        message = (
            f"Установка не завершилась за {INSTALL_TIMEOUT // 60} минут. "
            "Проверьте вывод AUR-хелпера."
        )
        logger.error(message)
        return InstallResult(ok=False, status="error", message=message)
    except OSError as exc:
        message = f"Не удалось запустить установку: {exc}"
        logger.error(message)
        return InstallResult(ok=False, status="error", message=message)

    output = _output_tail(completed.stdout or "")
    if completed.returncode != 0:
        logger.error(
            "Установка завершилась с кодом %s\n%s",
            completed.returncode,
            output,
        )
        return InstallResult(
            ok=False,
            status="error",
            message=(
                f"AUR-хелпер завершился с кодом {completed.returncode}. "
                "Проверьте вывод ниже."
            ),
            output=output,
            returncode=completed.returncode,
        )

    nfqws2 = shutil.which("nfqws2")
    if nfqws2 is None:
        message = (
            "Пакет установлен, но nfqws2 не появился в PATH. "
            "Проверьте состав пакета zapret2."
        )
        logger.error(message)
        return InstallResult(
            ok=False,
            status="error",
            message=message,
            output=output,
        )

    logger.info("zapret2 установлен, nfqws2: %s", nfqws2)
    return InstallResult(
        ok=True,
        status="success",
        message=f"zapret2 установлен. nfqws2: {nfqws2}",
        output=output,
    )


def _print_report(report: SystemReport) -> None:
    arch = "Arch-based" if report.is_arch_based else "не Arch"
    print(f"ОС:          {report.distro_name} ({arch})")
    print(f"AUR-хелпер:  {report.aur_helper or 'не найден'}")
    for tool in report.tools:
        state = tool.path if tool.path else "не найден"
        print(f"{tool.label:<20} {state}")
    for issue in report.issues:
        print(f"ОШИБКА: {issue}")
    for warning in report.warnings:
        print(f"ВНИМАНИЕ: {warning}")


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Показать или выполнить установку zapret2 из AUR."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="показать команды и ничего не устанавливать (режим по умолчанию)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="действительно запустить установку через AUR-хелпер и pkexec",
    )
    args = parser.parse_args(argv)

    if args.yes and args.dry_run:
        parser.error("--yes и --dry-run нельзя использовать вместе")

    setup_logging()
    report = detect_system()
    _print_report(report)

    plan = build_install_plan(report)
    if plan.already_installed:
        print(f"\n{plan.reason}")
        return 0
    if not plan.can_install:
        print(f"\nУстановка невозможна: {plan.reason}")
        return 1

    print("\nПлан установки:")
    for step in plan.steps:
        print(f"  {step.description}")
        print(f"  $ {step.command}")
        if step.root_via_pkexec:
            print("  root-вызовы pacman внутри хелпера идут через pkexec")

    if not args.yes:
        result = install_zapret2(plan, dry_run=True)
        print(f"\n{result.message}")
        print("Для реальной установки: python -m src.installer --yes")
        return 0

    result = install_zapret2(plan, dry_run=False)
    print(f"\n{result.message}")
    if result.output:
        print(result.output)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(_cli())
