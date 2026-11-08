"""Этап E: ранняя остановка, кэш check и отчёт автопоиска."""

from __future__ import annotations

import contextlib
import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from src.blockcheck_integration import (
    DEFAULT_DOMAINS,
    DEFAULT_SCAN_DOMAINS,
    DomainCheckResult,
    _load_check_cache,
    _save_check_cache,
    _select_best_strategy,
    measure_latency,
    run_blockcheck,
)


def _result(
    domain: str,
    *,
    working: bool = True,
    passes_ok: int = 3,
    passes_total: int = 3,
    latency: int = 150,
) -> DomainCheckResult:
    return DomainCheckResult(
        domain=domain,
        working=working,
        passes_ok=passes_ok,
        passes_total=passes_total,
        median_latency_ms=latency,
        observed="Bytes",
        admits=("Good",),
        error=None,
    )


def _payload(args: str = "A") -> str:
    return json.dumps(
        {
            "schema": 1,
            "outcome": "found",
            "strategies": [
                {
                    "protocol": "HTTPS/TLS1.2",
                    "args": args,
                    "working": True,
                    "passes_ok": 3,
                    "passes_total": 3,
                    "median_latency_ms": 150,
                    "observed": "Bytes",
                    "admits": ["Good"],
                }
            ],
        },
        ensure_ascii=False,
    )


class ForcedTargetsTests(unittest.TestCase):
    def test_default_targets_include_cdn_infrastructure(self) -> None:
        expected = {
            "youtube.com",
            "discord.com",
            "cloudflare.com",
            "amazon.com",
        }
        self.assertEqual(
            set(DEFAULT_SCAN_DOMAINS.split(",")),
            expected,
        )
        self.assertEqual(DEFAULT_DOMAINS, DEFAULT_SCAN_DOMAINS)


class EarlyStopTests(unittest.TestCase):
    def test_stops_when_every_domain_has_a_profile(self) -> None:
        calls: list[list[str]] = []

        def fake_measure(
            batch: list[str],
            domains: list[str],
            on_progress: object = None,
            *,
            deadline: float | None = None,
        ) -> dict[str, dict[str, DomainCheckResult]]:
            del domains, on_progress, deadline
            calls.append(list(batch))
            if len(calls) > 1:
                raise AssertionError("второй батч не должен вызываться")
            return {
                "A": {
                    "youtube.com": _result("youtube.com"),
                    "discord.com": _result("discord.com", working=False),
                },
                "B": {
                    "youtube.com": _result("youtube.com", working=False),
                    "discord.com": _result("discord.com"),
                },
            }

        with patch(
            "src.blockcheck_integration.measure_latency",
            side_effect=fake_measure,
        ):
            best, latency, profiles = _select_best_strategy(
                ["A", "B", "C", "D", "E", "F", "G", "H"],
                ["youtube.com", "discord.com"],
                deadline=time.monotonic() + 120,
            )

        self.assertEqual(len(calls), 1)
        self.assertEqual(
            set(profiles),
            {"youtube.com", "discord.com"},
        )
        self.assertIsNone(best)
        self.assertIsNone(latency)


class CheckCacheTests(unittest.TestCase):
    def test_uses_fresh_cached_result_without_blockcheckw(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "check_cache.json"
            with patch(
                "src.blockcheck_integration.CHECK_CACHE_FILE",
                cache_path,
            ):
                _save_check_cache(
                    {
                        "A||youtube.com": {
                            "working": True,
                            "passes_ok": 3,
                            "passes_total": 3,
                            "median_latency_ms": 150,
                            "observed": "Bytes",
                            "admits": ["Good"],
                            "timestamp": time.time(),
                        }
                    }
                )
                with patch(
                    "src.blockcheck_integration._run_blockcheck_command",
                    side_effect=AssertionError(
                        "blockcheckw не должен вызываться при cache hit"
                    ),
                ):
                    matrix = measure_latency(
                        ["A"],
                        ["youtube.com"],
                        deadline=time.monotonic() + 120,
                    )

        self.assertTrue(matrix["A"]["youtube.com"].confirmed)

    def test_saves_confirmed_result_to_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "check_cache.json"

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
                    _payload("A"),
                    "",
                )

            with patch(
                "src.blockcheck_integration.CHECK_CACHE_FILE",
                cache_path,
            ):
                with patch(
                    "src.blockcheck_integration._run_blockcheck_command",
                    side_effect=fake_check,
                ):
                    measure_latency(
                        ["A"],
                        ["youtube.com"],
                        deadline=time.monotonic() + 120,
                    )
                cache = _load_check_cache()

        entry = cache["A||youtube.com"]
        self.assertIs(entry["working"], True)
        self.assertEqual(entry["passes_ok"], 3)
        self.assertEqual(entry["median_latency_ms"], 150)


class ReportTests(unittest.TestCase):
    def test_report_is_saved_after_successful_search(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "auto_best.report.json"

            def fake_search(
                domains: str,
                on_progress: object = None,
                *,
                scan_domains: str | None = None,
                report_out: dict[str, object] | None = None,
            ) -> tuple[bool, str]:
                del domains, on_progress, scan_domains
                assert report_out is not None
                report_out["checked_strategies"] = ["A", "B", "A"]
                report_out["profiles"] = {
                    "youtube.com": {"strategy": "A"}
                }
                report_out["domains"] = ["youtube.com"]
                return True, "ok"

            with (
                patch(
                    "src.blockcheck_integration.AUTO_BEST_REPORT_FILE",
                    report_path,
                ),
                patch(
                    "src.blockcheck_integration._blockcheck_lock",
                    new=lambda: contextlib.nullcontext(),
                ),
                patch(
                    "src.blockcheck_integration._other_blockcheck_process",
                    return_value=None,
                ),
                patch(
                    "src.blockcheck_integration._run_blockcheck_locked",
                    side_effect=fake_search,
                ),
            ):
                ok, message = run_blockcheck()

            self.assertTrue(ok)
            self.assertEqual(message, "ok")
            payload = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertIn("timestamp", payload)
        self.assertGreaterEqual(payload["duration_seconds"], 0)
        self.assertEqual(payload["checked_strategies"], ["A", "B"])
        self.assertEqual(
            payload["profiles"]["youtube.com"]["strategy"],
            "A",
        )


if __name__ == "__main__":
    unittest.main()
