# -*- coding: utf-8 -*-
"""
Tests for the output layer: cli.py's serialisers and output.SaveFile.

These pin the cross-mode output contract. Premium API mode carries rich
per-domain metadata (LookalikeDomain objects in keyword_domains_meta) while
community and premium-feed modes carry bare strings in keyword_domains —
but all three must emit the same top-level JSON shape, which the README
documents publicly.
"""
import csv
import json
import os
import tempfile
from unittest import TestCase
from unittest.mock import patch

from opensquat.api_client import LookalikeDomain
from opensquat.cli import (
    CT_FAILURE_LIMIT,
    _build_csv_rows,
    _build_json_content,
    _filter_by_certificate_transparency,
    _serialize_domain,
)
from opensquat.output import SaveFile


IDN_DOMAIN = LookalikeDomain(
    domain="xn--mirosoft-hw7c.com",
    tld="com",
    date="09-04-2026",
    idn=True,
    unicode="miᴄrosoft.com",
)
PLAIN_DOMAIN = LookalikeDomain(
    domain="securite-microsoft.fr", tld="fr", date="09-04-2026", idn=False
)


class FakeScanner:
    """Stands in for app.Domain with just the attributes output reads."""

    def __init__(self, keyword_domains, keyword_domains_meta=None):
        self.keyword_domains = keyword_domains
        self.keyword_domains_meta = keyword_domains_meta or {}


class TestSerializeDomain(TestCase):
    """
    Contract: optional fields are omitted when None to keep output compact,
    but `idn` is ALWAYS emitted — its presence tells consumers the check ran,
    which is different from the information being absent.
    """

    def test_bare_domain_still_emits_idn(self):
        self.assertEqual(
            {"domain": "a.com", "idn": False},
            _serialize_domain(LookalikeDomain("a.com")),
        )

    def test_full_metadata_is_emitted(self):
        self.assertEqual(
            {
                "domain": "xn--mirosoft-hw7c.com",
                "tld": "com",
                "date": "09-04-2026",
                "idn": True,
                "unicode": "miᴄrosoft.com",
            },
            _serialize_domain(IDN_DOMAIN),
        )

    def test_none_fields_are_omitted(self):
        result = _serialize_domain(LookalikeDomain("a.com", tld=None, date=None))
        self.assertNotIn("tld", result)
        self.assertNotIn("date", result)

    def test_unicode_omitted_when_not_idn(self):
        """unicode is only meaningful alongside idn=True."""
        domain = LookalikeDomain("a.com", idn=False, unicode="ignored")
        self.assertNotIn("unicode", _serialize_domain(domain))

    def test_idn_true_without_unicode_omits_unicode(self):
        domain = LookalikeDomain("a.com", idn=True, unicode=None)
        result = _serialize_domain(domain)
        self.assertTrue(result["idn"])
        self.assertNotIn("unicode", result)


class TestBuildJsonContent(TestCase):
    def test_rich_metadata_path(self):
        scanner = FakeScanner(
            {"microsoft": [IDN_DOMAIN.domain, PLAIN_DOMAIN.domain]},
            {"microsoft": [IDN_DOMAIN, PLAIN_DOMAIN]},
        )
        result = _build_json_content(
            scanner, {IDN_DOMAIN.domain, PLAIN_DOMAIN.domain}
        )
        self.assertEqual(1, len(result))
        self.assertEqual("microsoft", result[0]["keyword"])
        self.assertEqual(2, len(result[0]["domains"]))
        self.assertEqual("com", result[0]["domains"][0]["tld"])

    def test_fallback_path_emits_domain_only(self):
        """Community / premium-feed modes have no metadata."""
        scanner = FakeScanner({"microsoft": ["mirosoft.com", "mcrosoft.net"]})
        result = _build_json_content(
            scanner, {"mirosoft.com", "mcrosoft.net"}
        )
        self.assertEqual(
            [{
                "keyword": "microsoft",
                "domains": [
                    {"domain": "mirosoft.com"}, {"domain": "mcrosoft.net"}
                ],
            }],
            result,
        )

    def test_top_level_shape_matches_across_modes(self):
        """The cross-mode consistency the README promises."""
        rich = _build_json_content(
            FakeScanner({"m": [IDN_DOMAIN.domain]}, {"m": [IDN_DOMAIN]}),
            {IDN_DOMAIN.domain},
        )
        bare = _build_json_content(
            FakeScanner({"m": ["mirosoft.com"]}), {"mirosoft.com"}
        )
        self.assertEqual(["keyword", "domains"], list(rich[0]))
        self.assertEqual(["keyword", "domains"], list(bare[0]))

    def test_filtered_out_domains_are_excluded(self):
        """Post-processing (--vt, --portcheck) narrows the surviving set."""
        scanner = FakeScanner(
            {"microsoft": [IDN_DOMAIN.domain, PLAIN_DOMAIN.domain]},
            {"microsoft": [IDN_DOMAIN, PLAIN_DOMAIN]},
        )
        result = _build_json_content(scanner, {IDN_DOMAIN.domain})
        self.assertEqual(1, len(result[0]["domains"]))
        self.assertEqual(IDN_DOMAIN.domain, result[0]["domains"][0]["domain"])

    def test_keyword_with_no_survivors_is_dropped(self):
        scanner = FakeScanner(
            {"microsoft": [IDN_DOMAIN.domain]}, {"microsoft": [IDN_DOMAIN]}
        )
        self.assertEqual([], _build_json_content(scanner, set()))

    def test_empty_scanner_yields_empty_list(self):
        self.assertEqual([], _build_json_content(FakeScanner({}), set()))

    def test_mixed_keywords_use_the_right_path_each(self):
        scanner = FakeScanner(
            {"microsoft": [IDN_DOMAIN.domain], "google": ["gooogle.com"]},
            {"microsoft": [IDN_DOMAIN]},
        )
        result = _build_json_content(
            scanner, {IDN_DOMAIN.domain, "gooogle.com"}
        )
        by_keyword = {entry["keyword"]: entry for entry in result}
        self.assertIn("tld", by_keyword["microsoft"]["domains"][0])
        self.assertEqual(
            {"domain": "gooogle.com"}, by_keyword["google"]["domains"][0]
        )


class TestBuildCsvRows(TestCase):
    EXPECTED_HEADER = [
        "keyword", "domain", "tld", "first_seen", "is_idn", "unicode"
    ]

    def test_header_is_always_first(self):
        rows = _build_csv_rows(FakeScanner({}), set())
        self.assertEqual([self.EXPECTED_HEADER], rows)

    def test_rich_row_is_fully_populated(self):
        scanner = FakeScanner(
            {"microsoft": [IDN_DOMAIN.domain]}, {"microsoft": [IDN_DOMAIN]}
        )
        rows = _build_csv_rows(scanner, {IDN_DOMAIN.domain})
        self.assertEqual(
            [
                "microsoft", "xn--mirosoft-hw7c.com", "com", "09-04-2026",
                "true", "miᴄrosoft.com",
            ],
            rows[1],
        )

    def test_is_idn_uses_lowercase_strings(self):
        scanner = FakeScanner(
            {"m": [PLAIN_DOMAIN.domain]}, {"m": [PLAIN_DOMAIN]}
        )
        rows = _build_csv_rows(scanner, {PLAIN_DOMAIN.domain})
        self.assertEqual("false", rows[1][4])

    def test_fallback_row_leaves_metadata_columns_empty(self):
        scanner = FakeScanner({"microsoft": ["mirosoft.com"]})
        rows = _build_csv_rows(scanner, {"mirosoft.com"})
        self.assertEqual(["microsoft", "mirosoft.com", "", "", "", ""], rows[1])

    def test_every_row_has_the_header_width(self):
        scanner = FakeScanner(
            {"a": [IDN_DOMAIN.domain], "b": ["plain.com"]},
            {"a": [IDN_DOMAIN]},
        )
        rows = _build_csv_rows(
            scanner, {IDN_DOMAIN.domain, "plain.com"}
        )
        for row in rows:
            self.assertEqual(len(self.EXPECTED_HEADER), len(row))


class TestCertificateTransparencyFilter(TestCase):
    """
    The --ct post-processing pass.

    Regression context: --ct was parsed but never consumed for three
    years. It was originally passed positionally into doppelganger_only,
    so it silently toggled doppelganger mode; commit 733772e fixed that
    mis-wiring but left the flag orphaned with no consumer.
    """

    def _run(self, domains, statuses):
        """Run the filter with check_certificate() returning `statuses`."""
        with patch(
            "opensquat.ct.CRTSH.check_certificate", side_effect=statuses
        ) as mock_check:
            kept = _filter_by_certificate_transparency(domains)
        return kept, mock_check

    def test_domains_with_ct_logs_are_cleared(self):
        kept, _ = self._run(["a.com", "b.com"], [True, True])
        self.assertEqual([], kept)

    def test_domains_without_ct_logs_are_kept(self):
        kept, _ = self._run(["a.com", "b.com"], [False, False])
        self.assertEqual(["a.com", "b.com"], kept)

    def test_mixed_results_keep_only_the_suspicious(self):
        kept, _ = self._run(
            ["clean.com", "suspicious.com", "alsoclean.com"],
            [True, False, True],
        )
        self.assertEqual(["suspicious.com"], kept)

    def test_indeterminate_results_are_kept_not_dropped(self):
        """
        Fails open: None means crt.sh could not answer, which is not
        evidence a domain is clean. Dropping it would silently discard
        potentially malicious domains during a crt.sh outage.
        """
        kept, _ = self._run(["a.com", "b.com"], [None, None])
        self.assertEqual(["a.com", "b.com"], kept)

    def test_order_is_preserved(self):
        kept, _ = self._run(
            ["a.com", "b.com", "c.com", "d.com"],
            [False, True, None, False],
        )
        self.assertEqual(["a.com", "c.com", "d.com"], kept)

    def test_empty_input_makes_no_lookups(self):
        kept, mock_check = self._run([], [])
        self.assertEqual([], kept)
        mock_check.assert_not_called()

    def test_circuit_breaker_stops_querying_crtsh(self):
        """
        After CT_FAILURE_LIMIT consecutive failures, stop hammering a
        service that is clearly down — one message beats a timeout per
        domain on a large result set.
        """
        domains = [f"d{i}.com" for i in range(20)]
        kept, mock_check = self._run(domains, [None] * 20)
        self.assertEqual(domains, kept)
        self.assertEqual(CT_FAILURE_LIMIT, mock_check.call_count)

    def test_breaker_keeps_all_remaining_domains(self):
        domains = [f"d{i}.com" for i in range(10)]
        kept, _ = self._run(domains, [None] * 10)
        self.assertEqual(10, len(kept))

    def test_a_success_resets_the_failure_streak(self):
        """
        Intermittent failures must not trip the breaker — only a genuine
        consecutive run does.
        """
        statuses = [None] * (CT_FAILURE_LIMIT - 1) + [False] + [None] * 4
        domains = [f"d{i}.com" for i in range(len(statuses))]
        kept, mock_check = self._run(domains, statuses)
        self.assertEqual(len(statuses), mock_check.call_count)
        self.assertEqual(domains, kept)


class TestSaveFile(TestCase):
    """Round-trip the three output formats through a real file."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def _path(self, name):
        return os.path.join(self.tmpdir.name, name)

    def test_text_round_trip(self):
        path = self._path("out.txt")
        SaveFile().main(path, "txt", ["a.com", "b.com"])
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(["a.com", "b.com"], handle.read().splitlines())

    def test_json_round_trip_preserves_unicode(self):
        path = self._path("out.json")
        content = [{
            "keyword": "microsoft",
            "domains": [_serialize_domain(IDN_DOMAIN)],
        }]
        SaveFile().main(path, "json", content)
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(content, json.load(handle))
        with open(path, encoding="utf-8") as handle:
            # ensure_ascii=False keeps the homograph human-readable on disk
            self.assertIn("miᴄrosoft.com", handle.read())

    def test_csv_is_written_with_a_utf8_bom(self):
        """Excel on Windows needs the BOM to render the unicode column."""
        path = self._path("out.csv")
        SaveFile().main(path, "csv", [["keyword"], ["microsoft"]])
        with open(path, "rb") as handle:
            self.assertTrue(handle.read().startswith(b"\xef\xbb\xbf"))

    def test_csv_round_trip(self):
        path = self._path("out.csv")
        rows = _build_csv_rows(
            FakeScanner(
                {"microsoft": [IDN_DOMAIN.domain]},
                {"microsoft": [IDN_DOMAIN]},
            ),
            {IDN_DOMAIN.domain},
        )
        SaveFile().main(path, "csv", rows)
        with open(path, encoding="utf-8-sig", newline="") as handle:
            self.assertEqual(rows, list(csv.reader(handle)))

    def test_unknown_type_falls_back_to_text(self):
        path = self._path("out.dat")
        SaveFile().main(path, "unknown", ["a.com"])
        with open(path, encoding="utf-8") as handle:
            self.assertEqual("a.com\n", handle.read())
