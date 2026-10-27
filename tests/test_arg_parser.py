# -*- coding: utf-8 -*-
"""Tests for opensquat.arg_parser — mode resolution and auth dispatch."""
import sys
from unittest import TestCase
from unittest.mock import patch

from opensquat import arg_parser, auth


class TestModeResolution(TestCase):
    """The mode flag derivation branches of get_args()."""

    def _run(self, argv):
        """Run get_args with a fake sys.argv and return the Namespace."""
        with patch.object(sys, "argv", ["opensquat"] + argv):
            return arg_parser.get_args()

    def test_no_flags_is_community(self):
        args = self._run([])
        self.assertEqual("community", args.mode)
        self.assertIsNone(args.resolved_api_key)
        self.assertFalse(args.premium)
        self.assertFalse(args.api)

    def test_premium_flag_selects_premium_feed(self):
        with patch.object(auth, "load_api_key", return_value="os_test_key"):
            args = self._run(["--premium"])
        self.assertEqual("premium_feed", args.mode)
        self.assertEqual("os_test_key", args.resolved_api_key)

    def test_api_flag_selects_premium_api(self):
        with patch.object(auth, "load_api_key", return_value="os_test_key"):
            args = self._run(["--api"])
        self.assertEqual("premium_api", args.mode)
        self.assertEqual("os_test_key", args.resolved_api_key)

    def test_premium_and_api_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            self._run(["--premium", "--api"])

    def test_api_key_flag_is_passed_through_to_auth_loader(self):
        with patch.object(auth, "load_api_key", return_value="os_resolved") as mock_load:
            args = self._run(["--api", "--api-key", "os_from_cli"])
        mock_load.assert_called_once_with("os_from_cli")
        self.assertEqual("os_resolved", args.resolved_api_key)

    def test_community_mode_does_not_call_auth_loader(self):
        with patch.object(auth, "load_api_key") as mock_load:
            args = self._run([])
        mock_load.assert_not_called()
        self.assertIsNone(args.resolved_api_key)

    def test_community_mode_ignores_stray_api_key_arg(self):
        """--api-key without a mode is still parsed but not resolved."""
        with patch.object(auth, "load_api_key") as mock_load:
            args = self._run(["--api-key", "os_ignored"])
        # parsed onto the namespace (cli.py uses it for a hint) ...
        self.assertEqual("os_ignored", args.api_key)
        # ... but never fed to the loader
        mock_load.assert_not_called()
        self.assertIsNone(args.resolved_api_key)


class TestAuthErrorExit(TestCase):
    """Non-community mode with no usable key must exit -1."""

    def _run(self, argv):
        with patch.object(sys, "argv", ["opensquat"] + argv):
            return arg_parser.get_args()

    def test_premium_without_any_key_exits(self):
        with patch.object(
            auth, "load_api_key",
            side_effect=auth.AuthError("No openSquat API key found"),
        ):
            with self.assertRaises(SystemExit) as ctx:
                self._run(["--premium"])
        # exit(-1) → SystemExit(-1)
        self.assertEqual(-1, ctx.exception.code)

    def test_api_without_any_key_exits(self):
        with patch.object(
            auth, "load_api_key",
            side_effect=auth.AuthError("No openSquat API key found"),
        ):
            with self.assertRaises(SystemExit) as ctx:
                self._run(["--api"])
        self.assertEqual(-1, ctx.exception.code)


class TestFuzzinessChoices(TestCase):
    """--api-fuzziness has a closed set of valid values."""

    def _run(self, argv):
        with patch.object(sys, "argv", ["opensquat"] + argv):
            return arg_parser.get_args()

    def test_valid_fuzziness_accepted(self):
        for choice in ("exact", "low", "high", "auto"):
            with self.subTest(choice=choice):
                with patch.object(auth, "load_api_key", return_value="k"):
                    args = self._run(["--api", "--api-fuzziness", choice])
                self.assertEqual(choice, args.api_fuzziness)

    def test_invalid_fuzziness_rejected(self):
        with patch.object(auth, "load_api_key", return_value="k"):
            with self.assertRaises(SystemExit):
                self._run(["--api", "--api-fuzziness", "bogus"])


class TestRateLimitFlag(TestCase):
    """--api-rate-limit parses to an int and defaults to None (unlimited)."""

    def _run(self, argv):
        with patch.object(sys, "argv", ["opensquat"] + argv):
            return arg_parser.get_args()

    def test_api_rate_limit_flag_parses(self):
        with patch.object(auth, "load_api_key", return_value="k"):
            args = self._run(["--api", "--api-rate-limit", "5"])
        self.assertEqual(5, args.api_rate_limit)

    def test_api_rate_limit_defaults_to_none(self):
        with patch.object(auth, "load_api_key", return_value="k"):
            args = self._run(["--api"])
        self.assertIsNone(args.api_rate_limit)

    def test_api_rate_limit_not_required_in_community_mode(self):
        args = self._run([])
        self.assertIsNone(args.api_rate_limit)


class TestDeprecatedPeriodFlag(TestCase):
    """-p/--period is deprecated and should exit with a clear message."""

    def _run(self, argv):
        with patch.object(sys, "argv", ["opensquat"] + argv):
            return arg_parser.get_args()

    def test_period_flag_exits(self):
        with self.assertRaises(SystemExit):
            self._run(["-p", "daily"])


class TestPhishingFallbackFlag(TestCase):
    """--phishing-fallback is opt-in and must be an https URL."""

    def _run(self, argv):
        with patch.object(sys, "argv", ["opensquat"] + argv):
            return arg_parser.get_args()

    def test_no_fallback_by_default(self):
        self.assertIsNone(self._run([]).phishing_fallback)

    def test_https_url_is_accepted(self):
        args = self._run(
            ["--phishing", "out.txt",
             "--phishing-fallback", "https://lists.example.org/p.txt"]
        )
        self.assertEqual("https://lists.example.org/p.txt",
                         args.phishing_fallback)

    def test_plain_http_url_is_rejected(self):
        with self.assertRaises(SystemExit):
            self._run(["--phishing-fallback", "http://lists.example.org/p"])

    def test_non_url_is_rejected(self):
        with self.assertRaises(SystemExit):
            self._run(["--phishing-fallback", "not-a-url"])
