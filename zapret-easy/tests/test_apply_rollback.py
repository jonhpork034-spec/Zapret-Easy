"""Этап D: проверка hash/meta и откат auto_best."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.blockcheck_integration import (
    AUTO_BEST_BACKUP_NAME,
    AUTO_BEST_META_BACKUP_NAME,
    _backup_auto_best,
    _restore_auto_best_backup,
    _rollback_auto_best_apply,
    apply_auto_best,
)


class FakeManager:
    def __init__(self, strategies_dir: Path) -> None:
        self.strategies_dir = strategies_dir
        self.active = "auto_best.lua"

    def active_name(self) -> str:
        return self.active

    def set_active(self, name: str) -> None:
        self.active = name


class FakeService:
    def __init__(
        self,
        *,
        install_ok: bool = True,
        install_message: str = "ok",
    ) -> None:
        self.install_ok = install_ok
        self.install_message = install_message
        self.install_calls = 0
        self.stop_calls = 0

    def status(self) -> SimpleNamespace:
        return SimpleNamespace(installed=True, ours=True, active=True)

    def install(self) -> SimpleNamespace:
        self.install_calls += 1
        return SimpleNamespace(
            ok=self.install_ok,
            message=self.install_message,
        )

    def stop(self) -> SimpleNamespace:
        self.stop_calls += 1
        return SimpleNamespace(ok=True, message="stopped")


def _write_pair(
    directory: Path,
    conf: str,
    meta: dict[str, object],
) -> None:
    (directory / "auto_best.conf").write_text(conf, encoding="utf-8")
    (directory / "auto_best.meta.json").write_text(
        json.dumps(meta, ensure_ascii=False),
        encoding="utf-8",
    )


class AutoBestBackupTests(unittest.TestCase):
    def test_backup_and_restore_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            _write_pair(
                directory,
                "old-conf\n",
                {"verified": True, "strategy": "old-conf"},
            )

            _backup_auto_best(directory)

            _write_pair(
                directory,
                "new-conf\n",
                {"verified": True, "strategy": "new-conf"},
            )

            self.assertTrue(
                (directory / AUTO_BEST_BACKUP_NAME).is_file()
            )
            self.assertTrue(
                (directory / AUTO_BEST_META_BACKUP_NAME).is_file()
            )

            self.assertTrue(_restore_auto_best_backup(directory))
            self.assertEqual(
                (directory / "auto_best.conf").read_text(
                    encoding="utf-8"
                ),
                "old-conf\n",
            )
            self.assertEqual(
                json.loads(
                    (directory / "auto_best.meta.json").read_text(
                        encoding="utf-8"
                    )
                )["strategy"],
                "old-conf",
            )


class ApplyAutoBestRollbackTests(unittest.TestCase):
    def test_hash_mismatch_restores_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            _write_pair(
                directory,
                "old-conf\n",
                {"verified": True, "strategy": "old-conf"},
            )
            _backup_auto_best(directory)

            _write_pair(
                directory,
                "tampered-conf\n",
                {
                    "verified": True,
                    "hash": "0" * 64,
                    "strategy": "tampered-conf",
                },
            )

            manager = FakeManager(directory)
            service = FakeService()

            with (
                patch(
                    "src.strategies.StrategyManager",
                    return_value=manager,
                ),
                patch(
                    "src.service.ServiceManager",
                    return_value=service,
                ),
            ):
                ok, message = apply_auto_best()

            self.assertFalse(ok)
            self.assertIn("sha256", message)
            self.assertIn("Выполнен откат", message)
            self.assertEqual(service.install_calls, 1)
            self.assertEqual(
                (directory / "auto_best.conf").read_text(
                    encoding="utf-8"
                ),
                "old-conf\n",
            )
            self.assertEqual(manager.active, "auto_best.lua")

    def test_rollback_reports_service_start_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            _write_pair(
                directory,
                "old-conf\n",
                {"verified": True, "strategy": "old-conf"},
            )
            _backup_auto_best(directory)

            _write_pair(
                directory,
                "new-conf\n",
                {"verified": True, "strategy": "new-conf"},
            )

            manager = FakeManager(directory)
            service = FakeService(
                install_ok=False,
                install_message="nfqws2 --dry-run failed",
            )

            ok, message = _rollback_auto_best_apply(
                manager,
                service,
                previous="auto_best.lua",
                lua_name="auto_best.lua",
                was_active=True,
                attempted_install=True,
                cause="Новый конфиг не применён.",
            )

            self.assertFalse(ok)
            self.assertIn("не поднялась", message)
            self.assertIn("nfqws2 --dry-run failed", message)
            self.assertEqual(
                (directory / "auto_best.conf").read_text(
                    encoding="utf-8"
                ),
                "old-conf\n",
            )


if __name__ == "__main__":
    unittest.main()
