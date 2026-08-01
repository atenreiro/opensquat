# -*- coding: utf-8 -*-
"""
Live contract test for the openSquat lookalike API.

WHY THIS EXISTS
---------------
Every test in test_api_client.py parses a hand-written fixture, so together
they verify the client against our *assumptions* about the server, never
against the server itself. If the API renamed or dropped a field the client
reads, all 30 of them would still pass while Premium API output silently
degraded — most damagingly `unicode_domain`, which backs the IDN homograph
rendering the README leads with.

This test closes that gap. It asserts SHAPE ONLY — which fields exist and
what types they are — never specific domains, because the NRD feed changes
daily and a test that pins real results would be flaky by construction.

COST AND OPT-IN
---------------
One run makes exactly ONE API call and consumes ONE query from the plan
quota. It therefore requires TWO explicit signals and is skipped otherwise:

    OPENSQUAT_LIVE_TESTS=1          consent to spend quota
    OPENSQUAT_API_KEY=os_...        the credential

The key alone is deliberately not enough. Exporting OPENSQUAT_API_KEY is the
documented way to use the CLI, so keying off it alone would silently bill a
credit every time a developer ran the suite. Note this reads the environment
directly rather than going through auth.load_api_key(), which would also pick
up api_key.txt from the working directory — same reasoning.

RUN IT
------
    OPENSQUAT_LIVE_TESTS=1 OPENSQUAT_API_KEY=os_... pytest tests/test_api_contract.py -v

Keep it out of CI: the release gate must stay hermetic and free.
"""
import os
import warnings
from unittest import TestCase, skipUnless

from opensquat.api_client import APIClient, LookalikeDomain


KEYWORD = "microsoft"
MAX_RESULTS = 100

LIVE_ENABLED = os.environ.get("OPENSQUAT_LIVE_TESTS") == "1"
API_KEY = os.environ.get("OPENSQUAT_API_KEY", "").strip()

SKIP_REASON = (
    "live API contract test — set OPENSQUAT_LIVE_TESTS=1 and "
    "OPENSQUAT_API_KEY to run (consumes 1 query from your plan quota)"
)

# Fields the client reads today. _parse_success maps result-level names onto
# LookalikeDomain; anything removed here is a breaking change for the CLI.
CLIENT_READS_TOP_LEVEL = {"keyword", "results", "balance", "count", "total"}
CLIENT_READS_PER_RESULT = {"domain", "tld", "date", "idn", "unicode_domain"}


@skipUnless(LIVE_ENABLED and API_KEY, SKIP_REASON)
class TestLiveApiContract(TestCase):
    """
    One HTTP call shared by the whole class (setUpClass), so the full
    contract is checked for a single credit.
    """

    @classmethod
    def setUpClass(cls):
        client = APIClient(API_KEY)
        try:
            url = f"{client.base_url}/v1/nrd/lookalike/{KEYWORD}"
            cls.response = client._session.post(
                url,
                params={
                    "format": "json",
                    "fuzziness": "high",
                    "max_results": MAX_RESULTS,
                },
                timeout=client.timeout,
                allow_redirects=False,
            )
        finally:
            client.close()

        cls.body = cls.response.json() if cls.response.status_code == 200 else {}
        cls.results = cls.body.get("results") or []

    def _require_results(self):
        if not self.results:
            self.skipTest(
                f"server returned no results for '{KEYWORD}'; "
                "cannot check per-result shape"
            )

    def test_endpoint_returns_200(self):
        self.assertEqual(
            200,
            self.response.status_code,
            f"POST /v1/nrd/lookalike/{KEYWORD} returned "
            f"{self.response.status_code}: {self.response.text[:300]}",
        )

    def test_top_level_fields_the_client_reads_are_present(self):
        missing = {"keyword", "results"} - set(self.body)
        self.assertEqual(
            set(),
            missing,
            f"server dropped required top-level field(s) {missing}; "
            f"got keys {sorted(self.body)}",
        )

    def test_top_level_field_types(self):
        self.assertIsInstance(self.body.get("keyword"), str)
        self.assertIsInstance(self.body.get("results"), list)
        for name in ("count", "total"):
            if self.body.get(name) is not None:
                with self.subTest(field=name):
                    self.assertIsInstance(self.body[name], int)
        if self.body.get("balance") is not None:
            self.assertIsInstance(self.body["balance"], int)

    def test_every_result_carries_a_domain_string(self):
        """`domain` is the only per-result field the client cannot do without."""
        self._require_results()
        for index, result in enumerate(self.results):
            with self.subTest(index=index):
                self.assertIsInstance(result, dict)
                self.assertIsInstance(result.get("domain"), str)
                self.assertTrue(result["domain"])

    def test_optional_result_fields_have_expected_types(self):
        self._require_results()
        for index, result in enumerate(self.results):
            with self.subTest(index=index, domain=result.get("domain")):
                for name in ("tld", "date", "unicode_domain"):
                    if result.get(name) is not None:
                        self.assertIsInstance(result[name], str)
                if result.get("idn") is not None:
                    self.assertIsInstance(result["idn"], bool)

    def test_idn_results_carry_a_unicode_rendering(self):
        """
        The headline Premium API feature: an IDN homograph must ship the
        unicode form alongside the punycode, otherwise `xn--mirosoft-hw7c.com`
        reaches the user with no indication of what it impersonates.

        Skips when the page happens to contain no IDN domains — they are
        genuinely rare, so this asserts opportunistically rather than
        pinning a result the feed may not produce today.
        """
        self._require_results()
        idn_results = [r for r in self.results if r.get("idn")]
        if not idn_results:
            self.skipTest(
                f"no IDN domains among {len(self.results)} results for "
                f"'{KEYWORD}' today"
            )
        for result in idn_results:
            with self.subTest(domain=result.get("domain")):
                self.assertIsInstance(
                    result.get("unicode_domain"),
                    str,
                    "idn=True result is missing unicode_domain; the CLI "
                    "would emit idn:true with no unicode rendering",
                )

    def test_client_parses_the_live_payload(self):
        """_parse_success must consume the real response without raising."""
        parsed = APIClient._parse_success(KEYWORD, self.response)
        self.assertEqual(KEYWORD, parsed.keyword)
        self.assertEqual(len(self.results), len(parsed.domains))
        for domain in parsed.domains:
            with self.subTest(domain=domain.domain):
                self.assertIsInstance(domain, LookalikeDomain)
                self.assertIsInstance(domain.domain, str)
                self.assertIsInstance(domain.idn, bool)

    def test_client_mapping_matches_the_payload(self):
        """Field-by-field: what the server sent survives into the dataclass."""
        self._require_results()
        parsed = APIClient._parse_success(KEYWORD, self.response)
        by_domain = {d.domain: d for d in parsed.domains}
        for result in self.results:
            domain = by_domain.get(result["domain"])
            with self.subTest(domain=result["domain"]):
                self.assertIsNotNone(domain)
                self.assertEqual(result.get("tld"), domain.tld)
                self.assertEqual(result.get("date"), domain.date)
                self.assertEqual(bool(result.get("idn", False)), domain.idn)
                self.assertEqual(
                    result.get("unicode_domain"), domain.unicode
                )

    def test_report_server_fields_the_client_ignores(self):
        """
        Informational, never fails: additive server changes are backward
        compatible, so they must not break the build. But they are worth
        surfacing — the API already returns threat intelligence (score,
        similarity, risk, threat_score, tags) that the CLI drops on the
        floor while the MCP surface exposes it.

        Emits a warning rather than printing, so it shows in pytest's
        warnings summary even though the test passes.
        """
        self._require_results()
        seen = set()
        for result in self.results:
            seen.update(result)
        ignored = seen - CLIENT_READS_PER_RESULT
        if ignored:
            warnings.warn(
                f"server returns per-result fields the client ignores: "
                f"{sorted(ignored)}",
                UserWarning,
            )
        extra_top = set(self.body) - CLIENT_READS_TOP_LEVEL - {"query_time"}
        if extra_top:
            warnings.warn(
                f"server returns top-level fields the client ignores: "
                f"{sorted(extra_top)}",
                UserWarning,
            )
