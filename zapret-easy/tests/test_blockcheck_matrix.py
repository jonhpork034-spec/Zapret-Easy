"""Этап A: матрица результатов blockcheckw check."""

from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from src.blockcheck_integration import (
    DomainCheckResult,
    VerifiedCandidate,
    _aggregate_measurements,
    _final_stage_message,
    _load_check_cache,
    _save_auto_best_meta,
    _select_best_per_domain,
    _with_firewall_filters,
    compose_auto_best,
    measure_latency,
)


def _result(
    domain: str = "youtube.com",
    **overrides: object,
) -> DomainCheckResult:
    values: dict[str, object] = {
        "domain": domain,
        "working": True,
        "passes_ok": 3,
        "passes_total": 3,
        "median_latency_ms": 180,
        "observed": "Bytes",
        "admits": ("Good",),
        "error": None,
    }
    values.update(overrides)
    return DomainCheckResult(**values)  # type: ignore[arg-type]


def _entry(args: str, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "protocol": "HTTPS/TLS1.2",
        "args": args,
        "working": True,
        "passes_ok": 3,
        "passes_total": 3,
        "median_latency_ms": 180,
        "observed": "Bytes",
        "admits": ["Good"],
    }
    values.update(overrides)
    return values


def _candidate(args: tuple[str, ...]) -> VerifiedCandidate:
    return VerifiedCandidate(
        args=args,
        protocol="HTTPS/TLS1.2",
        complexity=len(args),
        domains={},
    )


def _payload(entries: list[dict[str, object]]) -> str:
    return json.dumps(
        {
            "schema": 1,
            "outcome": "found",
            "working": len(entries),
            "strategies": entries,
        },
        ensure_ascii=False,
    )


class DomainCheckResultTests(unittest.TestCase):
    def test_confirmed_requires_full_delivery(self) -> None:
        self.assertTrue(_result().confirmed)

        self.assertFalse(_result(working=False).confirmed)
        self.assertFalse(_result(passes_ok=2).confirmed)
        self.assertFalse(_result(passes_total=0).confirmed)
        self.assertFalse(_result(median_latency_ms=None).confirmed)
        self.assertFalse(_result(median_latency_ms=0).confirmed)
        self.assertFalse(_result(error="timeout").confirmed)

    def test_only_narrow_mirage_is_rejected(self) -> None:
        # Широкий круг [Mirage, Grinding, Good] — это «не установили»,
        # а не доказанный Mirage.
        self.assertTrue(_result(admits=("Good", "Mirage")).confirmed)
        self.assertFalse(_result(admits=("Mirage",)).confirmed)
        self.assertFalse(_result(observed="Mirage").confirmed)


class MeasureLatencyMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self._cache_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._cache_dir.cleanup)
        cache_path = Path(self._cache_dir.name) / "check_cache.json"
        patcher = patch(
            "src.blockcheck_integration.CHECK_CACHE_FILE",
            cache_path,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_builds_strategy_by_domain_matrix(self) -> None:
        entries = [
            _entry("A", median_latency_ms=180),
            _entry("B", passes_ok=2),
            _entry("C", admits=["Mirage"]),
        ]

        def fake_check(
            command: list[str],
            on_progress: object = None,
            *,
            timeout: float = 0,
        ) -> subprocess.CompletedProcess[str]:
            del on_progress, timeout
            return subprocess.CompletedProcess(
                command,
                0,
                _payload(entries),
                "",
            )

        with patch(
            "src.blockcheck_integration._run_blockcheck_command",
            side_effect=fake_check,
        ):
            matrix = measure_latency(
                ["A", "B", "C", "D"],
                ["youtube.com", "discord.com"],
                deadline=time.monotonic() + 120,
            )

        self.assertEqual(
            set(matrix),
            {"A", "B", "C", "D"},
        )
        for strategy in matrix:
            self.assertEqual(
                set(matrix[strategy]),
                {"youtube.com", "discord.com"},
            )

        self.assertTrue(matrix["A"]["youtube.com"].confirmed)
        self.assertTrue(matrix["A"]["discord.com"].confirmed)

        self.assertFalse(matrix["B"]["youtube.com"].confirmed)
        self.assertEqual(matrix["B"]["youtube.com"].passes_ok, 2)

        self.assertFalse(matrix["C"]["youtube.com"].confirmed)
        self.assertIn("Mirage", matrix["C"]["youtube.com"].admits)

        # D отсутствует в отчёте: запись должна остаться с диагностикой.
        self.assertFalse(matrix["D"]["youtube.com"].confirmed)
        self.assertIsNotNone(matrix["D"]["youtube.com"].error)

    def test_keeps_confirmed_domains_on_partial_check(self) -> None:
        def fake_check(
            command: list[str],
            on_progress: object = None,
            *,
            timeout: float = 0,
        ) -> subprocess.CompletedProcess[str]:
            del on_progress
            domain = command[command.index("-d") + 1]
            if domain == "discord.com":
                raise subprocess.TimeoutExpired(command, timeout)
            return subprocess.CompletedProcess(
                command,
                0,
                _payload([_entry("A")]),
                "",
            )

        with patch(
            "src.blockcheck_integration._run_blockcheck_command",
            side_effect=fake_check,
        ):
            matrix = measure_latency(
                ["A"],
                ["youtube.com", "discord.com"],
                deadline=time.monotonic() + 120,
            )

        self.assertTrue(matrix["A"]["youtube.com"].confirmed)
        self.assertIn(
            "таймаут",
            matrix["A"]["discord.com"].error or "",
        )

    def test_not_blocked_check_is_ignored(self) -> None:
        payload = json.dumps(
            {
                "schema": 1,
                "outcome": "not_blocked",
                "strategies": [_entry("A")],
            }
        )

        def fake_check(
            command: list[str],
            on_progress: object = None,
            *,
            timeout: float = 0,
        ) -> subprocess.CompletedProcess[str]:
            del on_progress, timeout
            return subprocess.CompletedProcess(
                command,
                0,
                payload,
                "",
            )

        with patch(
            "src.blockcheck_integration._run_blockcheck_command",
            side_effect=fake_check,
        ):
            matrix = measure_latency(
                ["A"],
                ["youtube.com"],
                deadline=time.monotonic() + 120,
            )
            cache = _load_check_cache()

        self.assertFalse(matrix["A"]["youtube.com"].confirmed)
        self.assertIn(
            "не обнаружил",
            matrix["A"]["youtube.com"].error or "",
        )
        self.assertEqual(cache, {})


class FinalStageMessageTests(unittest.TestCase):
    def test_accessible_stage_does_not_hide_blocked_failure(self) -> None:
        message = _final_stage_message(
            [
                (
                    ("youtube.com", "discord.com"),
                    "blockcheckw check не подтвердил стратегии.",
                    False,
                ),
                (
                    ("twitch.tv", "steamcommunity.com"),
                    "blockcheckw не обнаружил блокировку.",
                    True,
                ),
            ],
            "default",
        )

        self.assertIn("не подтвердил", message)
        self.assertIn("twitch.tv", message)
        self.assertIn("не обнаружил", message)

    def test_blocked_failure_after_accessible_stage_is_kept(self) -> None:
        message = _final_stage_message(
            [
                (
                    ("youtube.com",),
                    "blockcheckw не обнаружил блокировку.",
                    True,
                ),
                (
                    ("twitch.tv",),
                    "blockcheckw scan не завершился.",
                    False,
                ),
            ],
            "default",
        )

        self.assertIn("twitch.tv", message)
        self.assertIn("youtube.com", message)
        self.assertIn("не обнаружил", message)


class AggregateMeasurementsTests(unittest.TestCase):
    def test_keeps_legacy_winner_shape(self) -> None:
        matrix = {
            "A": {
                "youtube.com": _result("youtube.com", median_latency_ms=180),
                "discord.com": _result("discord.com", median_latency_ms=250),
            },
            "B": {
                "youtube.com": _result("youtube.com", working=False),
                "discord.com": _result("discord.com", median_latency_ms=300),
            },
            "C": {
                "youtube.com": _result("youtube.com", median_latency_ms=100),
                "discord.com": _result("discord.com", passes_ok=2),
            },
        }

        measured = _aggregate_measurements(
            matrix,
            ["youtube.com", "discord.com"],
        )

        self.assertIn((0, [180, 250], "A"), measured)
        self.assertIn((1, [300], "B"), measured)
        self.assertIn((1, [100], "C"), measured)


class SelectBestPerDomainTests(unittest.TestCase):
    def test_chooses_different_strategies_for_domains(self) -> None:
        matrix = {
            "stable-180": {
                "youtube.com": _result(
                    "youtube.com",
                    median_latency_ms=180,
                ),
                "discord.com": _result(
                    "discord.com",
                    median_latency_ms=250,
                ),
            },
            "stable-200": {
                "youtube.com": _result(
                    "youtube.com",
                    median_latency_ms=200,
                ),
                "discord.com": _result(
                    "discord.com",
                    median_latency_ms=200,
                ),
            },
            "partial-fast": {
                "youtube.com": _result(
                    "youtube.com",
                    passes_ok=2,
                    median_latency_ms=100,
                ),
                "discord.com": _result(
                    "discord.com",
                    passes_ok=2,
                    median_latency_ms=100,
                ),
            },
            "discord-only": {
                "youtube.com": _result("youtube.com", working=False),
                "discord.com": _result(
                    "discord.com",
                    median_latency_ms=150,
                ),
            },
            "twitch-only": {
                "twitch.tv": _result(
                    "twitch.tv",
                    median_latency_ms=90,
                ),
            },
        }

        profiles = _select_best_per_domain(
            matrix,
            ["youtube.com", "discord.com", "twitch.tv"],
        )

        self.assertEqual(
            profiles["youtube.com"].args,
            ("stable-180",),
        )
        self.assertEqual(
            profiles["discord.com"].args,
            ("discord-only",),
        )
        self.assertEqual(
            profiles["twitch.tv"].args,
            ("twitch-only",),
        )
        self.assertEqual(
            profiles["youtube.com"].protocol,
            "HTTPS/TLS1.2",
        )
        self.assertEqual(
            profiles["youtube.com"].complexity,
            1,
        )
        self.assertIn("discord.com", profiles["youtube.com"].domains)

    def test_stability_beats_latency(self) -> None:
        matrix = {
            "partial-fast": {
                "youtube.com": _result(
                    "youtube.com",
                    passes_ok=2,
                    median_latency_ms=100,
                ),
            },
            "stable-slow": {
                "youtube.com": _result(
                    "youtube.com",
                    median_latency_ms=300,
                ),
            },
        }

        profiles = _select_best_per_domain(matrix, ["youtube.com"])

        self.assertEqual(
            profiles["youtube.com"].args,
            ("stable-slow",),
        )

    def test_complexity_is_len_args_tiebreaker(self) -> None:
        long_strategy = "--filter-tcp=443 --lua-desync=fake:blob=x"
        short_strategy = "--filter-tcp=443"
        matrix = {
            long_strategy: {
                "youtube.com": _result(
                    "youtube.com",
                    median_latency_ms=150,
                ),
            },
            short_strategy: {
                "youtube.com": _result(
                    "youtube.com",
                    median_latency_ms=150,
                ),
            },
        }

        profiles = _select_best_per_domain(matrix, ["youtube.com"])

        self.assertEqual(
            profiles["youtube.com"].args,
            ("--filter-tcp=443",),
        )
        self.assertEqual(
            profiles["youtube.com"].complexity,
            1,
        )

    def test_domain_without_confirmed_strategy_is_skipped(self) -> None:
        matrix = {
            "A": {
                "youtube.com": _result("youtube.com"),
                "discord.com": _result("discord.com", working=False),
            },
        }

        profiles = _select_best_per_domain(
            matrix,
            ["youtube.com", "discord.com", "twitch.tv"],
        )

        self.assertEqual(set(profiles), {"youtube.com"})


class ComposeAutoBestTests(unittest.TestCase):
    def test_groups_same_args_and_splits_different(self) -> None:
        shared = (
            "--filter-tcp=443",
            "--lua-desync=fake:blob=fake_default_tls",
        )
        other = (
            "--filter-tcp=443",
            "--lua-desync=multisplit:pos=1",
        )
        profiles = {
            "youtube.com": _candidate(shared),
            "googlevideo.com": _candidate(shared),
            "discord.com": _candidate(other),
        }

        text = compose_auto_best(profiles)

        self.assertEqual(text.count("--new"), 1)
        self.assertIn(
            "--hostlist-domains=youtube.com,googlevideo.com",
            text,
        )
        self.assertIn("--hostlist-domains=discord.com", text)
        self.assertIn("--lua-desync=fake:blob=fake_default_tls", text)
        self.assertIn("--lua-desync=multisplit:pos=1", text)
        # apply_auto_best() не должен переписывать уже собранный конфиг.
        self.assertEqual(_with_firewall_filters(text), text)

    def test_single_profile_always_has_hostlist(self) -> None:
        profiles = {
            "youtube.com": _candidate(
                (
                    "--filter-tcp=443",
                    "--lua-desync=fake:blob=fake_default_tls",
                )
            ),
        }

        text = compose_auto_best(profiles)

        self.assertEqual(text.count("--new"), 0)
        self.assertIn("--hostlist-domains=youtube.com", text)
        self.assertIn("--filter-l7=tls", text)
        self.assertEqual(text.count("--filter-tcp=443"), 1)
        self.assertTrue(text.startswith("--hostlist-domains=youtube.com "))

    def test_single_profile_adds_missing_filter_once(self) -> None:
        profiles = {
            "youtube.com": _candidate(
                ("--lua-desync=fake:blob=fake_default_tls",)
            ),
        }

        text = compose_auto_best(profiles)

        self.assertEqual(text.count("--filter-tcp=443"), 1)
        self.assertIn("--filter-l7=tls", text)
        self.assertTrue(
            text.startswith(
                "--hostlist-domains=youtube.com "
                "--filter-l7=tls --filter-tcp=443 "
            )
        )

    def test_inline_lua_quotes_survive_compose(self) -> None:
        strategy = (
            "--lua-init=fake_default_tls="
            "tls_mod(fake_default_tls,'rnd') "
            "--payload=tls_client_hello "
            "--lua-desync=multisplit:pos=10,midsld"
        )
        profiles = _select_best_per_domain(
            {strategy: {"youtube.com": _result("youtube.com")}},
            ["youtube.com"],
        )

        self.assertIn("'rnd'", profiles["youtube.com"].args[0])

        text = compose_auto_best(profiles)
        parsed = shlex.split(text, comments=True)

        self.assertTrue(
            any(
                "tls_mod(fake_default_tls,'rnd')" in token
                for token in parsed
            )
        )

    def test_meta_contains_hash_and_domain_profiles(self) -> None:
        profiles = {
            "youtube.com": _candidate(("--filter-tcp=443",)),
        }
        config_text = "--filter-tcp=443\n"

        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "auto_best.conf"
            meta_path = _save_auto_best_meta(
                profiles,
                config_text,
                config_path,
            )
            payload = json.loads(meta_path.read_text(encoding="utf-8"))

        self.assertEqual(meta_path.name, "auto_best.meta.json")
        self.assertEqual(
            payload["hash"],
            hashlib.sha256(config_text.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(
            payload["profiles"]["youtube.com"]["args"],
            ["--filter-tcp=443"],
        )
        self.assertEqual(payload["strategy"], "--filter-tcp=443")
        self.assertTrue(payload["verified"])
        self.assertIn("timestamp", payload)


if __name__ == "__main__":
    unittest.main()
