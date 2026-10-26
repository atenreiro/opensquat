# -*- coding: utf-8 -*-
"""Tests for opensquat.phishing."""
import os
import tempfile
from unittest import TestCase
from unittest.mock import MagicMock, patch

import requests

from opensquat.phishing import Phishing


def _response(content, status=200):
    response = MagicMock()
    response.status_code = status
    response.content = content
    return response


ERROR_PAGE = (
    b"<html><body><h1>503 Service Unavailable</h1>\n"
    b"No server is available to handle this request.\n</body></html>\n"
)


class _InTempDir(TestCase):

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _saved_db(self):
        with open("phishing.db", "rb") as f:
            return f.read()


class TestUpdateDb(_InTempDir):

    @patch("opensquat.phishing.requests.get")
    def test_primary_list_is_used_when_it_answers(self, mock_get):
        mock_get.return_value = _response(b"paypal-login.example\n")

        Phishing().update_db()

        self.assertEqual(b"paypal-login.example\n", self._saved_db())
        self.assertEqual(1, mock_get.call_count)

    @patch("opensquat.phishing.requests.get")
    def test_error_page_is_not_saved_as_the_database(self, mock_get):
        phishing = Phishing()
        mock_get.side_effect = [
            _response(ERROR_PAGE, status=503),
            _response(b"# header\nbank-verify.example\n"),
        ]

        phishing.update_db()

        self.assertEqual(b"# header\nbank-verify.example\n", self._saved_db())
        self.assertEqual(
            phishing.fallback_db, mock_get.call_args_list[1][0][0]
        )

    @patch("opensquat.phishing.requests.get")
    def test_unreachable_primary_falls_back(self, mock_get):
        mock_get.side_effect = [
            requests.exceptions.ConnectionError("refused"),
            _response(b"bank-verify.example\n"),
        ]

        Phishing().update_db()

        self.assertEqual(b"bank-verify.example\n", self._saved_db())

    @patch("opensquat.phishing.requests.get")
    def test_empty_primary_falls_back(self, mock_get):
        mock_get.side_effect = [
            _response(b""),
            _response(b"bank-verify.example\n"),
        ]

        Phishing().update_db()

        self.assertEqual(b"bank-verify.example\n", self._saved_db())

    @patch("opensquat.phishing.requests.get")
    def test_exits_when_no_list_can_be_downloaded(self, mock_get):
        mock_get.side_effect = [
            _response(ERROR_PAGE, status=503),
            _response(b"", status=403),
        ]

        with self.assertRaises(SystemExit):
            Phishing().update_db()
        self.assertFalse(os.path.exists("phishing.db"))


class TestCheckPhishing(_InTempDir):

    def test_comment_lines_do_not_match_keywords(self):
        with open("keywords.txt", "w", encoding="utf-8") as f:
            f.write("netapi\n")
        with open("phishing.db", "w", encoding="utf-8") as f:
            f.write(
                "# NetAPI.com - currently compromised URLs (2026-10-26).\n"
                "netapi-login.example\n"
                "unrelated.example\n"
            )

        phishing = Phishing()
        phishing.set_keywords("keywords.txt")
        phishing.count_keywords()

        self.assertEqual(["netapi-login.example"], phishing.check_phishing())
