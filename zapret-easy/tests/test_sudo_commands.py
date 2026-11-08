"""Проверки неинтерактивного sudo -n."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from src.blockcheck_integration import (
    SUDO_HINT,
    _check_command,
    _common_command,
    _no_strategy_message,
    _scan_command,
    _sudo_auth_failed,
)


def _which(name: str) -> str | None:
    return {
        "blockcheckw": "/usr/bin/blockcheckw",
        "sudo": "/usr/bin/sudo",
    }.get(name)


class SudoCommandTests(unittest.TestCase):
    def test_blockcheck_commands_start_with_sudo_n(self) -> None:
        with (
            patch("src.blockcheck_integration.os.geteuid", return_value=1000),
            patch(
                "src.blockcheck_integration.shutil.which",
                side_effect=_which,
            ),
        ):
            common = _common_command()
            scan = _scan_command("youtube.com", 30)
            check = _check_command(Path("/tmp/report.json"), "youtube.com")

        for command in (common, scan, check):
            self.assertEqual(command[:2], ["sudo", "-n"])
            self.assertEqual(command[2], "/usr/bin/blockcheckw")

    def test_missing_sudo_raises_clear_error(self) -> None:
        with (
            patch("src.blockcheck_integration.os.geteuid", return_value=1000),
            patch(
                "src.blockcheck_integration.shutil.which",
                return_value=None,
            ),
        ):
            with self.assertRaises(OSError) as context:
                _common_command()

        self.assertIn("sudo не найден", str(context.exception))
        self.assertIn("/etc/sudoers.d/zapret-easy", str(context.exception))

    def test_sudo_password_messages_are_recognized(self) -> None:
        self.assertTrue(
            _sudo_auth_failed("sudo: a password is required")
        )
        self.assertTrue(
            _sudo_auth_failed("sudo: a terminal is required")
        )
        self.assertTrue(
            _sudo_auth_failed("no tty present and no askpass program specified")
        )
        self.assertFalse(_sudo_auth_failed("network is unreachable"))

    def test_no_strategy_message_explains_sudoers(self) -> None:
        completed = subprocess.CompletedProcess(
            ["blockcheckw"],
            1,
            "",
            "sudo: a password is required",
        )
        message = _no_strategy_message(completed)
        self.assertEqual(message, SUDO_HINT)


if __name__ == "__main__":
    unittest.main()
