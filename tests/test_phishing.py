# -*- coding: utf-8 -*-
"""Tests for opensquat.phishing."""
import os
import tempfile
from unittest import TestCase
from unittest.mock import MagicMock, patch

import requests

from opensquat import phishing
from opensquat.phishing import Phishing

PRIMARY = "https://phish.co.za/latest/phishing-domains-ACTIVE.txt"
FALLBACK = "https://lists.example.org/phishing.txt"


def _response(content, status=200, content_type="text/plain",
              url=PRIMARY, content_length=None):
    response = MagicMock()
    response.status_code = status
    response.url = url
    response.history = []
    response.headers = {"content-type": content_type}
    if content_length is not None:
        response.headers["content-length"] = str(content_length)
    response.iter_content.side_effect = lambda chunk_size=None: iter(
        [content[i:i + 4] for i in range(0, len(content), 4)]
    )
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


class TestRedactUrl(TestCase):

    def test_userinfo_query_and_fragment_are_removed(self):
        self.assertEqual(
            "https://lists.example.org:8443/p.txt",
            phishing.redact_url(
                "https://user:secret@lists.example.org:8443/p.txt"
                "?key=abc123#frag"
            ),
        )

    def test_plain_url_is_unchanged(self):
        self.assertEqual(PRIMARY, phishing.redact_url(PRIMARY))


class TestSecretsNotPrinted(_InTempDir):

    SECRET_URL = "https://u:pw123@lists.example.org/p.txt?key=tok456"

    @patch("opensquat.phishing.requests.get")
    def test_fallback_credentials_never_reach_the_output(self, mock_get):
        mock_get.side_effect = [
            _response(ERROR_PAGE, status=503),
            requests.exceptions.ConnectionError("failed: " + self.SECRET_URL),
        ]
        phish = Phishing(fallback_db=self.SECRET_URL)

        with patch("builtins.print") as mock_print:
            with self.assertRaises(SystemExit):
                phish.update_db()

        printed = " ".join(
            " ".join(str(a) for a in c.args) for c in mock_print.call_args_list
        )
        for secret in ("pw123", "tok456", "u:pw"):
            self.assertNotIn(secret, printed)
        self.assertIn("lists.example.org", printed)

    @patch("opensquat.phishing.requests.get")
    def test_source_is_stored_redacted(self, mock_get):
        mock_get.return_value = _response(
            b"bank.example\n", url=self.SECRET_URL
        )
        phish = Phishing(fallback_db=self.SECRET_URL)
        phish.phishing_db = self.SECRET_URL

        phish.update_db()

        self.assertEqual("https://lists.example.org/p.txt", phish.source)


class TestSanitizeDb(TestCase):

    def test_keeps_hosts_and_urls_lowercased(self):
        lines, rejected = Phishing.sanitize_db(
            b"PayPal-Login.Example\r\n"
            b"https://bank-verify.example/login?id=1\n"
            b"1.2.3.4:8080\n"
        )
        self.assertEqual(
            ["paypal-login.example",
             "https://bank-verify.example/login?id=1",
             "1.2.3.4:8080"],
            lines,
        )
        self.assertEqual(0, rejected)

    def test_comments_and_blank_lines_are_ignored_not_rejected(self):
        lines, rejected = Phishing.sanitize_db(
            b"# header\n\n   \nbank-verify.example\n"
        )
        self.assertEqual(["bank-verify.example"], lines)
        self.assertEqual(0, rejected)

    def test_escape_sequences_and_control_characters_are_dropped(self):
        lines, rejected = Phishing.sanitize_db(
            b"paypal.example\n"
            b"\x1b[2Jpaypal.evil\n"
            b"\x1b]0;owned\x07paypal.evil2\n"
            b"paypal\x00.evil3\n"
            b"paypal.example\x1b[31m\n"
        )
        self.assertEqual(["paypal.example"], lines)
        self.assertEqual(4, rejected)

    def test_unsafe_characters_are_dropped(self):
        lines, rejected = Phishing.sanitize_db(
            b"ok.example\n"
            b"two words.example\n"
            b"=cmd|calc.example\n"
            b"quote'.example\n"
            b"back\\slash.example\n"
            b"-leading.example\n"
            b"<script>.example\n"
        )
        self.assertEqual(["ok.example"], lines)
        self.assertEqual(6, rejected)

    def test_invalid_utf8_does_not_crash(self):
        lines, rejected = Phishing.sanitize_db(
            b"ok.example\n\xff\xfe\xfa.example\n"
        )
        self.assertEqual(["ok.example"], lines)
        self.assertEqual(1, rejected)

    def test_overlong_lines_are_dropped(self):
        lines, rejected = Phishing.sanitize_db(
            b"ok.example\n" + b"a" * (phishing.MAX_LINE_LENGTH + 1) + b"\n"
        )
        self.assertEqual(["ok.example"], lines)
        self.assertEqual(1, rejected)


class TestDownloadDb(TestCase):

    @patch("opensquat.phishing.requests.get")
    def test_valid_list_is_returned(self, mock_get):
        mock_get.return_value = _response(b"paypal-login.example\n")
        self.assertEqual(
            b"paypal-login.example\n", Phishing().download_db(PRIMARY)
        )

    @patch("opensquat.phishing.requests.get")
    def test_non_https_url_is_refused_without_a_request(self, mock_get):
        self.assertIsNone(
            Phishing().download_db("http://phish.co.za/list.txt")
        )
        mock_get.assert_not_called()

    @patch("opensquat.phishing.requests.get")
    def test_error_status_is_refused(self, mock_get):
        mock_get.return_value = _response(ERROR_PAGE, status=503)
        self.assertIsNone(Phishing().download_db(PRIMARY))

    @patch("opensquat.phishing.requests.get")
    def test_html_page_with_status_200_is_refused(self, mock_get):
        mock_get.return_value = _response(
            ERROR_PAGE, content_type="text/html; charset=utf-8"
        )
        self.assertIsNone(Phishing().download_db(PRIMARY))

    @patch("opensquat.phishing.requests.get")
    def test_json_body_is_refused(self, mock_get):
        mock_get.return_value = _response(
            b'{"error": "rate limited"}', content_type="application/json"
        )
        self.assertIsNone(Phishing().download_db(PRIMARY))

    @patch("opensquat.phishing.requests.get")
    def test_redirect_to_plain_http_is_refused(self, mock_get):
        mock_get.return_value = _response(
            b"paypal.example\n", url="http://phish.co.za/list.txt"
        )
        self.assertIsNone(Phishing().download_db(PRIMARY))

    @patch("opensquat.phishing.requests.get")
    def test_redirect_chain_through_plain_http_is_refused(self, mock_get):
        response = _response(b"paypal.example\n")
        hop = MagicMock()
        hop.url = "http://phish.co.za/list.txt"
        response.history = [hop]
        mock_get.return_value = response
        self.assertIsNone(Phishing().download_db(PRIMARY))

    @patch("opensquat.phishing.requests.get")
    def test_content_type_header_is_not_echoed(self, mock_get):
        mock_get.return_value = _response(
            ERROR_PAGE, content_type="text/html\x1b[2J\x1b]0;owned\x07"
        )
        with patch("builtins.print") as mock_print:
            self.assertIsNone(Phishing().download_db(PRIMARY))
        printed = " ".join(
            " ".join(str(a) for a in c.args) for c in mock_print.call_args_list
        )
        self.assertNotIn("\x1b", printed)
        self.assertNotIn("owned", printed)

    @patch("opensquat.phishing.requests.get")
    def test_empty_body_is_refused(self, mock_get):
        mock_get.return_value = _response(b"")
        self.assertIsNone(Phishing().download_db(PRIMARY))

    @patch("opensquat.phishing.requests.get")
    def test_declared_size_over_the_cap_is_refused(self, mock_get):
        response = _response(
            b"x.example\n", content_length=phishing.MAX_DB_BYTES + 1
        )
        mock_get.return_value = response
        self.assertIsNone(Phishing().download_db(PRIMARY))
        response.iter_content.assert_not_called()

    @patch("opensquat.phishing.MAX_DB_BYTES", 16)
    @patch("opensquat.phishing.requests.get")
    def test_streamed_body_over_the_cap_is_refused(self, mock_get):
        mock_get.return_value = _response(b"paypal.example\n" * 4)
        self.assertIsNone(Phishing().download_db(PRIMARY))

    @patch("opensquat.phishing.requests.get")
    def test_connection_error_is_refused(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError("refused")
        self.assertIsNone(Phishing().download_db(PRIMARY))

    @patch("opensquat.phishing.requests.get")
    def test_response_is_always_closed(self, mock_get):
        response = _response(ERROR_PAGE, status=503)
        mock_get.return_value = response
        Phishing().download_db(PRIMARY)
        response.close.assert_called_once_with()


class TestUpdateDb(_InTempDir):

    @patch("opensquat.phishing.requests.get")
    def test_primary_list_is_used_when_it_answers(self, mock_get):
        mock_get.return_value = _response(b"paypal-login.example\n")

        phish = Phishing()
        phish.update_db()

        self.assertEqual(b"paypal-login.example\n", self._saved_db())
        self.assertEqual(1, mock_get.call_count)
        self.assertEqual(PRIMARY, phish.source)

    @patch("opensquat.phishing.requests.get")
    def test_saved_database_contains_only_sanitized_lines(self, mock_get):
        mock_get.return_value = _response(
            b"# header\nPaypal-Login.example\n\x1b[2Jevil\nbank.example\n"
        )

        Phishing().update_db()

        self.assertEqual(
            b"paypal-login.example\nbank.example\n", self._saved_db()
        )

    @patch("opensquat.phishing.requests.get")
    def test_no_fallback_is_tried_unless_configured(self, mock_get):
        mock_get.return_value = _response(ERROR_PAGE, status=503)

        with self.assertRaises(SystemExit):
            Phishing().update_db()

        self.assertEqual(1, mock_get.call_count)
        self.assertFalse(os.path.exists("phishing.db"))

    @patch("opensquat.phishing.requests.get")
    def test_error_page_falls_back_to_the_configured_list(self, mock_get):
        phish = Phishing(fallback_db=FALLBACK)
        mock_get.side_effect = [
            _response(ERROR_PAGE, status=503),
            _response(b"# header\nbank-verify.example\n", url=FALLBACK),
        ]

        phish.update_db()

        self.assertEqual(b"bank-verify.example\n", self._saved_db())
        self.assertEqual(FALLBACK, mock_get.call_args_list[1][0][0])
        self.assertEqual(FALLBACK, phish.source)

    @patch("opensquat.phishing.requests.get")
    def test_unreachable_primary_falls_back(self, mock_get):
        mock_get.side_effect = [
            requests.exceptions.ConnectionError("refused"),
            _response(b"bank-verify.example\n", url=FALLBACK),
        ]

        Phishing(fallback_db=FALLBACK).update_db()

        self.assertEqual(b"bank-verify.example\n", self._saved_db())

    @patch("opensquat.phishing.requests.get")
    def test_empty_primary_falls_back(self, mock_get):
        mock_get.side_effect = [
            _response(b""),
            _response(b"bank-verify.example\n", url=FALLBACK),
        ]

        Phishing(fallback_db=FALLBACK).update_db()

        self.assertEqual(b"bank-verify.example\n", self._saved_db())

    @patch("opensquat.phishing.requests.get")
    def test_mostly_invalid_primary_falls_back(self, mock_get):
        mock_get.side_effect = [
            _response(b"ok.example\n" + b"bad line one\n" * 5),
            _response(b"bank-verify.example\n", url=FALLBACK),
        ]

        Phishing(fallback_db=FALLBACK).update_db()

        self.assertEqual(b"bank-verify.example\n", self._saved_db())

    @patch("opensquat.phishing.requests.get")
    def test_exits_when_no_list_can_be_downloaded(self, mock_get):
        mock_get.side_effect = [
            _response(ERROR_PAGE, status=503),
            _response(b"", status=403, url=FALLBACK),
        ]

        with self.assertRaises(SystemExit):
            Phishing(fallback_db=FALLBACK).update_db()
        self.assertFalse(os.path.exists("phishing.db"))

    @patch("opensquat.phishing.requests.get")
    def test_failed_update_keeps_the_previous_database(self, mock_get):
        with open("phishing.db", "w", encoding="utf-8") as f:
            f.write("previous.example\n")
        mock_get.return_value = _response(ERROR_PAGE, status=503)

        with self.assertRaises(SystemExit):
            Phishing().update_db()

        self.assertEqual(b"previous.example\n", self._saved_db())

    @patch("opensquat.phishing.os.replace", side_effect=OSError("disk"))
    @patch("opensquat.phishing.requests.get")
    def test_write_failure_leaves_no_temp_file(self, mock_get, _replace):
        mock_get.return_value = _response(b"paypal.example\n")

        with self.assertRaises(OSError):
            Phishing().update_db()

        self.assertEqual([], os.listdir("."))


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

        phish = Phishing()
        phish.set_keywords("keywords.txt")
        phish.count_keywords()

        self.assertEqual(["netapi-login.example"], phish.check_phishing())
