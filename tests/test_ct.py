# -*- coding: utf-8 -*-
"""
Tests for opensquat.ct — Certificate Transparency lookups via crt.sh.

check_certificate() is tri-state:
    True  - CT logs found
    False - crt.sh answered, no CT logs for this domain
    None  - indeterminate (unreachable, non-200, unparseable)

The None state exists because collapsing "no certificates" and "could not
find out" into one boolean made crt.sh outages read as suspicious
certificates, and unreachable hosts read as valid ones.
"""
import os
from unittest import TestCase
from unittest.mock import patch, MagicMock

from opensquat.ct import CRTSH, CTLog


FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "crtsh_results.html"
)


def _page(html, status=200):
    """Mock a requests.get return value with an explicit status code."""
    return MagicMock(text=html, status_code=status)


def _real_page():
    """A real crt.sh results page (domains sanitised, structure intact)."""
    with open(FIXTURE, encoding="utf-8") as handle:
        return handle.read()


class TestCRTSH(TestCase):
    """Tests for Certificate Transparency checking."""

    @patch('opensquat.ct.requests.get')
    def test_certificates_not_found(self, mock_get):
        """A domain with no CT logs returns False (the suspicious signal)."""
        # crt.sh's "None found" page: header table only, no results table.
        mock_get.return_value = _page(
            "<html><body><table><tr><td>crt.sh</td></tr></table>"
            "None found</body></html>"
        )
        self.assertFalse(
            CRTSH.check_certificate("thisisnotarealdomain12345xyz.com")
        )


class TestRealCrtShPage(TestCase):
    """
    Parse an actual crt.sh results page captured from the live service.

    This is the only test that would catch crt.sh changing its table
    layout. The synthetic two-empty-tables fixtures used elsewhere pass
    regardless of column order, which is exactly how the issuer_name /
    matching_ident off-by-one went unnoticed.
    """

    @patch('opensquat.ct.requests.get')
    def test_real_page_reports_certificates_found(self, mock_get):
        mock_get.return_value = _page(_real_page())
        self.assertTrue(CRTSH.check_certificate("example.com"))

    def test_fixture_row_shape_matches_parser_constants(self):
        """
        Pin the column layout the parser depends on. If crt.sh adds or
        reorders a column, this fails with a clear diff instead of the
        parser silently reading the wrong field.
        """
        from bs4 import BeautifulSoup, NavigableString

        soup = BeautifulSoup(_real_page(), "html.parser")
        tables = soup.find_all("table")
        self.assertGreaterEqual(len(tables), 2)

        rows = None
        for container in tables[1]:
            if isinstance(container, NavigableString):
                continue
            rows = container.find_all("tr")
            break
        self.assertIsNotNone(rows)

        tds = rows[1].find_all("td")
        self.assertGreaterEqual(len(tds), CRTSH.MIN_COLUMNS)
        # Issuer column must look like a CA distinguished name, not a domain.
        issuer = tds[CRTSH.COL_ISSUER].text
        self.assertIn("O=", issuer)
        self.assertIn("CN=", issuer)
        # Matching-identities column must look like a hostname.
        self.assertIn(".", tds[CRTSH.COL_MATCHING_IDENT].text)

    @patch('opensquat.ct.requests.get')
    def test_issuer_column_is_a_ca_not_a_domain(self, mock_get):
        """
        Regression for the off-by-one: issuer_name used to read the
        Matching Identities column, so it held a hostname. The
        untrusted-CA comparison was therefore matching a CA name against
        a domain and could never fire.
        """
        from bs4 import BeautifulSoup, NavigableString

        soup = BeautifulSoup(_real_page(), "html.parser")
        rows = None
        for container in soup.find_all("table")[1]:
            if isinstance(container, NavigableString):
                continue
            rows = container.find_all("tr")
            break

        tds = rows[1].find_all("td")
        issuer = tds[CRTSH.COL_ISSUER].text
        identity = tds[CRTSH.COL_MATCHING_IDENT].text.strip()
        self.assertNotEqual(issuer.strip(), identity)
        self.assertNotIn("example.com", issuer)

    @patch('opensquat.ct.requests.get')
    def test_short_rows_are_skipped_not_fatal(self, mock_get):
        """A malformed row must not abort the whole lookup."""
        html = (
            "<html><body><table></table>"
            "<table><tbody>"
            "<tr><th>hdr</th></tr>"
            "<tr><td>only</td><td>two</td></tr>"
            "<tr><td>1</td><td>2</td><td>3</td><td>4</td>"
            "<td>cn.example.com</td><td>id.example.com</td>"
            "<td>C=US, O=Let's Encrypt, CN=YR2</td></tr>"
            "</tbody></table></body></html>"
        )
        mock_get.return_value = _page(html)
        self.assertTrue(CRTSH.check_certificate("id.example.com"))


class TestIndeterminateResults(TestCase):
    """
    None means "we could not find out". Reporting a verdict without data
    is what made crt.sh outages look like suspicious certificates.
    """

    @patch('opensquat.ct.requests.get')
    def test_network_error_returns_none(self, mock_get):
        mock_get.side_effect = Exception("Network error")
        self.assertIsNone(CRTSH.check_certificate("example.com"))

    @patch('opensquat.ct.requests.get')
    def test_502_returns_none_not_false(self, mock_get):
        """
        crt.sh serves 502 error pages as HTML. Parsing one yields no
        results table, which previously read as "no certificates found"
        and flagged every domain as suspicious during an outage.
        """
        mock_get.return_value = _page(
            "<html><head><title>502 Bad Gateway</title></head>"
            "<body><center><h1>502 Bad Gateway</h1></center></body></html>",
            status=502,
        )
        self.assertIsNone(CRTSH.check_certificate("example.com"))

    @patch('opensquat.ct.requests.get')
    def test_other_error_statuses_return_none(self, mock_get):
        for status in (429, 500, 503, 403):
            with self.subTest(status=status):
                mock_get.return_value = _page("<html></html>", status=status)
                self.assertIsNone(CRTSH.check_certificate("example.com"))

    @patch('opensquat.ct.requests.get')
    def test_timeout_is_indeterminate(self, mock_get):
        import requests
        mock_get.side_effect = requests.exceptions.ReadTimeout("timed out")
        self.assertIsNone(CRTSH.check_certificate("example.com"))


class TestTableCountGuard(TestCase):
    """
    Regression: check_certificate used to do soup.find_all("table")[1]
    with no length guard, so any crt.sh response with fewer than two
    tables raised IndexError instead of returning a verdict. The
    try/except above it wraps only requests.get, not the parsing, so the
    error escaped the method entirely.

    These all use HTTP 200 — a 200 with no results table is a genuine
    "no certificates found" answer (False), unlike a non-200 (None).
    """

    @patch('opensquat.ct.requests.get')
    def test_zero_tables_returns_false(self, mock_get):
        mock_get.return_value = _page("<html><body>None found</body></html>")
        self.assertFalse(CRTSH.check_certificate("example.com"))

    @patch('opensquat.ct.requests.get')
    def test_single_table_returns_false(self, mock_get):
        mock_get.return_value = _page(
            "<html><body><table><tr><td>x</td></tr></table></body></html>"
        )
        self.assertFalse(CRTSH.check_certificate("example.com"))

    @patch('opensquat.ct.requests.get')
    def test_empty_html_returns_false(self, mock_get):
        mock_get.return_value = _page("")
        self.assertFalse(CRTSH.check_certificate("example.com"))

    @patch('opensquat.ct.requests.get')
    def test_empty_ct_logs_returns_false(self, mock_get):
        """Test that no CT logs for a domain returns False."""
        mock_get.return_value = _page(
            "<html><body><table></table><table></table></body></html>"
        )
        self.assertFalse(CRTSH.check_certificate("nodomain.test"))


class TestCTLog(TestCase):
    """Tests for CTLog data class."""

    def test_ctlog_creation(self):
        """Test CTLog object creation."""
        log = CTLog(
            _id="12345",
            logget_at="2024-01-01",
            not_before="2024-01-01",
            not_after="2025-01-01",
            matching_ident=["example.com"],
            issuer_name="DigiCert Inc"
        )
        self.assertEqual("12345", log._id)
        self.assertEqual("DigiCert Inc", log.issuer_name)
        self.assertIn("example.com", log.matching_ident)
