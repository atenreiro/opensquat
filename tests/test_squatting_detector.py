# -*- coding: utf-8 -*-
"""
Tests for opensquat.squatting_detector — the matching engine.

SquattingDetector.check() has four outcomes per domain: a Levenshtein
similarity match, a homograph match, a substring ("contains") match, and
no match. In --doppelganger mode it takes a separate path entirely.

Every test here is hermetic: the doppelganger path performs HTTP and CT
lookups, so both are mocked.
"""
import io
from unittest import TestCase
from unittest.mock import MagicMock, patch

from opensquat.squatting_detector import SquattingDetector


CYRILLIC_C = "с"  # U+0441, confusable with Latin 'c'


def run(keyword, domains, confidence=1, **kwargs):
    """Run a check and return (matched_domains, buffer_text)."""
    buffer = io.StringIO()
    detector = SquattingDetector(confidence_level=confidence, **kwargs)
    matched = detector.check(keyword, domains, buffer)
    return matched, buffer.getvalue()


class TestSimilarityBranch(TestCase):
    """Levenshtein matches within the confidence threshold."""

    def test_exact_match_is_detected(self):
        matched, text = run("google", ["google.com"])
        self.assertEqual(["google.com"], matched)
        self.assertIn("Similarity detected", text)

    def test_single_edit_typosquat_is_detected(self):
        matched, _ = run("google", ["gooogle.com"])
        self.assertEqual(["gooogle.com"], matched)

    def test_unrelated_domain_is_not_matched(self):
        matched, _ = run("google", ["totallyunrelated.org"])
        self.assertEqual([], matched)

    def test_confidence_zero_rejects_single_edit(self):
        """-c 0 is exact-only, so a one-character typo must not match."""
        matched, _ = run("google", ["gooogle.xyz"], confidence=0)
        self.assertEqual([], matched)

    def test_higher_confidence_widens_the_net(self):
        strict, _ = run("google", ["gooooogle.xyz"], confidence=1)
        loose, _ = run("google", ["gooooogle.xyz"], confidence=3)
        self.assertEqual([], strict)
        self.assertEqual(["gooooogle.xyz"], loose)

    def test_only_the_first_label_is_compared(self):
        """Matching runs on domain.split('.')[0], not the full domain."""
        matched, _ = run("google", ["google.co.uk"])
        self.assertEqual(["google.co.uk"], matched)

    def test_original_domain_is_returned_not_the_label(self):
        matched, _ = run("google", ["gooogle.com"])
        self.assertEqual(["gooogle.com"], matched)

    def test_feed_order_is_preserved(self):
        matched, _ = run(
            "google", ["gooogle.com", "nope.org", "gogle.net", "no.io"]
        )
        self.assertEqual(["gooogle.com", "gogle.net"], matched)


class TestHomographBranch(TestCase):
    """Confusable characters fold to Latin before comparison."""

    def test_cyrillic_homograph_is_detected(self):
        domain = "mi" + CYRILLIC_C + "rosoft.com"
        matched, text = run("microsoft", [domain])
        self.assertEqual([domain], matched)
        self.assertIn("Homograph detected", text)

    def test_homograph_reports_as_homograph_not_similarity(self):
        domain = "mi" + CYRILLIC_C + "rosoft.com"
        _, text = run("microsoft", [domain])
        self.assertIn("Homograph detected", text)
        self.assertNotIn("Similarity detected", text)

    def test_homograph_of_a_different_brand_does_not_match(self):
        matched, _ = run("microsoft", ["g" + CYRILLIC_C + "ogle.com"])
        self.assertEqual([], matched)


class TestContainsBranch(TestCase):
    """Fallback substring match when the edit distance is too large."""

    def test_brand_embedded_in_longer_domain_is_found(self):
        matched, text = run("facebook", ["facebook-login-secure.net"])
        self.assertEqual(["facebook-login-secure.net"], matched)
        self.assertIn("Found", text)

    def test_brand_in_a_subdomain_is_found(self):
        """
        The label here is 'login', so only the contains branch can catch it.
        """
        matched, _ = run("paypal", ["login.paypal-secure.ru"])
        self.assertEqual(["login.paypal-secure.ru"], matched)

    def test_contains_matches_against_the_full_domain_including_tld(self):
        """
        Documents current behaviour, which is asymmetric with the
        doppelganger path: _process_levenshtein tests `keyword in
        original_domain` (TLD included) while _process_doppelganger tests
        `keyword in domain_part` (label only).

        Consequence: a keyword that collides with a TLD matches every
        domain under it. Contrived for "com", but real for short brands
        on live TLDs (co, ai, io, sh, me). If that asymmetry is ever
        fixed, this test should fail and be updated deliberately.
        """
        matched, _ = run(
            "com", ["example.com", "anything.com", "foo.net"], confidence=0
        )
        self.assertEqual(["example.com", "anything.com"], matched)


class TestPunycodeHomographBranch(TestCase):
    """
    Regression tests for the punycode bypass: NRD feeds publish IDNs as
    "xn--..." labels, which used to sail through undetected because the
    homograph gate only ever saw the raw ASCII punycode string. The
    detector now decodes and folds them. These six vectors are the attack
    classes validated against a live 100k feed (6/6 caught, 0 new false
    positives).
    """

    # (feed entry, keyword that must catch it)
    ATTACKS = [
        ("xn--mirosoft-gch.com", "microsoft"),   # mixed-script Cyrillic с
        ("xn--ggle-55da.net", "google"),         # Cyrillic о ×2
        ("xn--pypal-4ve.com", "paypal"),         # Cyrillic а
        ("xn--amazn-mye.shop", "amazon"),        # Cyrillic о
        ("xn--80ak6aa92e.com", "apple"),         # whole-script Cyrillic (2017 PoC)
        ("xn--mirosoft-hw7c.com", "microsoft"),  # Latin small-capital ᴄ
    ]

    def test_punycode_attacks_are_detected(self):
        for feed_entry, keyword in self.ATTACKS:
            with self.subTest(domain=feed_entry, keyword=keyword):
                matched, text = run(keyword, [feed_entry])
                self.assertEqual([feed_entry], matched)
                self.assertIn("Homograph detected", text)

    def test_result_carries_the_feed_string_not_the_folded_form(self):
        """Output files must contain the domain as it exists in DNS."""
        matched, _ = run("microsoft", ["xn--mirosoft-hw7c.com"])
        self.assertEqual(["xn--mirosoft-hw7c.com"], matched)

    def test_console_shows_the_unicode_rendering(self):
        """
        A bare "xn--..." match gives the operator no clue why it fired;
        the unicode form must be shown alongside.
        """
        _, text = run("microsoft", ["xn--mirosoft-hw7c.com"])
        self.assertIn("miᴄrosoft.com", text)

    def test_cjk_punycode_is_not_flagged_as_homograph(self):
        """
        Live feeds are dominated by legitimate CJK/Hangul IDNs (295 of
        303 in the sampled feed). None may be reported as homographs —
        fold_to_latin() returns None for them.
        """
        cjk_feed = [
            "xn--ai-ko3cj57sidau46i.top",   # 衣食住行ai
            "xn--bg-ub3cx40n.cc",           # bg真人
            "xn--gs-xz8jsd.kr",             # gs자이
        ]
        for keyword in ("ai", "bg", "gs"):
            with self.subTest(keyword=keyword):
                _, text = run(keyword, cjk_feed)
                self.assertNotIn("Homograph detected", text)

    def test_invalid_punycode_does_not_crash(self):
        matched, _ = run(
            "google", ["xn--999999999.com", "xn--.com", "gooogle.com"]
        )
        self.assertEqual(["gooogle.com"], matched)

    def test_attack_needs_the_right_keyword(self):
        """A decoded homograph still has to be near the keyword."""
        matched, _ = run("netflix", ["xn--mirosoft-hw7c.com"])
        self.assertEqual([], matched)

    def test_confidence_zero_still_catches_exact_folds(self):
        """miᴄrosoft folds to exactly "microsoft" — distance 0."""
        matched, _ = run(
            "microsoft", ["xn--mirosoft-hw7c.com"], confidence=0
        )
        self.assertEqual(["xn--mirosoft-hw7c.com"], matched)


class TestDNSValidatorIntegration(TestCase):
    """The detector annotates matches via the injected DNSValidator."""

    def test_validator_is_called_for_each_match(self):
        validator = MagicMock(use_dns=True)
        matched, _ = run(
            "google", ["gooogle.com"], dns_validator=validator
        )
        self.assertEqual(["gooogle.com"], matched)
        self.assertEqual(1, validator.check_domain.call_count)
        self.assertEqual(
            "gooogle.com", validator.check_domain.call_args[0][0]
        )

    def test_validator_is_not_called_for_non_matches(self):
        validator = MagicMock(use_dns=True)
        run("google", ["totallyunrelated.org"], dns_validator=validator)
        validator.check_domain.assert_not_called()

    def test_detector_works_without_a_validator(self):
        matched, _ = run("google", ["gooogle.com"], dns_validator=None)
        self.assertEqual(["gooogle.com"], matched)


class TestDoppelgangerBranch(TestCase):
    """--doppelganger: substring match plus reachability and CT checks."""

    def _run_doppelganger(self, keyword, domains, response=None, cert=True):
        buffer = io.StringIO()
        detector = SquattingDetector(
            confidence_level=1, doppelganger_only=True
        )
        with patch(
            "opensquat.squatting_detector.requests.get"
        ) as mock_get, patch(
            "opensquat.squatting_detector.ct.CRTSH.check_certificate"
        ) as mock_cert:
            if isinstance(response, Exception):
                mock_get.side_effect = response
            else:
                mock_get.return_value = response or MagicMock(
                    status_code=200, text="hello"
                )
            mock_cert.return_value = cert
            matched = detector.check(keyword, domains, buffer)
        return matched, buffer.getvalue()

    def test_reachable_doppelganger_is_matched(self):
        matched, text = self._run_doppelganger(
            "paypal", ["paypal-login.ru"]
        )
        self.assertEqual(["paypal-login.ru"], matched)
        self.assertIn("Site reachable", text)

    def test_unreachable_domain_is_not_matched(self):
        matched, text = self._run_doppelganger(
            "paypal", ["paypal-x.ru"], response=Exception("boom")
        )
        self.assertEqual([], matched)
        self.assertIn("Not reachable", text)

    def test_keyword_in_page_body_is_reported(self):
        _, text = self._run_doppelganger(
            "paypal",
            ["paypal-login.ru"],
            response=MagicMock(status_code=200, text="welcome to paypal"),
        )
        self.assertIn("Site contains paypal", text)

    def test_missing_certificate_is_reported_as_suspicious(self):
        _, text = self._run_doppelganger(
            "paypal", ["paypal-login.ru"], cert=False
        )
        self.assertIn("suspicious certificate", text)

    def test_valid_certificate_is_reported(self):
        _, text = self._run_doppelganger(
            "paypal", ["paypal-login.ru"], cert=True
        )
        self.assertIn("valid certificate", text)

    def test_indeterminate_ct_reports_neither_verdict(self):
        """
        check_certificate() returns None when crt.sh could not answer.
        That must not be reported as either a valid or a suspicious
        certificate — previously a failed lookup printed "valid
        certificate", hiding genuinely suspicious domains.
        """
        _, text = self._run_doppelganger(
            "paypal", ["paypal-login.ru"], cert=None
        )
        self.assertIn("CT check unavailable", text)
        self.assertNotIn("valid certificate", text)
        self.assertNotIn("suspicious certificate", text)

    def test_indeterminate_ct_still_flags_the_domain(self):
        """A CT failure must not drop an otherwise-matching domain."""
        matched, _ = self._run_doppelganger(
            "paypal", ["paypal-login.ru"], cert=None
        )
        self.assertEqual(["paypal-login.ru"], matched)

    def test_domain_without_the_keyword_is_skipped(self):
        matched, text = self._run_doppelganger("paypal", ["unrelated.com"])
        self.assertEqual([], matched)
        self.assertEqual("", text.strip())

    def test_doppelganger_matches_on_label_only_not_tld(self):
        """
        Counterpart to test_contains_matches_against_the_full_domain_
        including_tld: this path checks the label, so a TLD-shaped keyword
        matches nothing here.
        """
        matched, _ = self._run_doppelganger(
            "com", ["example.com", "anything.com"]
        )
        self.assertEqual([], matched)


class TestOutputBuffering(TestCase):
    """
    Workers must write to the supplied buffer, never to stdout — the parent
    prints buffers in submission order to keep output deterministic across
    parallel workers.
    """

    def test_all_output_goes_to_the_buffer(self):
        buffer = io.StringIO()
        with patch("sys.stdout") as mock_stdout:
            SquattingDetector(confidence_level=1).check(
                "google", ["gooogle.com"], buffer
            )
        mock_stdout.write.assert_not_called()
        self.assertIn("gooogle.com", buffer.getvalue())

    def test_check_works_without_an_explicit_buffer(self):
        """A None buffer is replaced by an internal one, not a crash."""
        detector = SquattingDetector(confidence_level=1)
        self.assertEqual(["gooogle.com"], detector.check(
            "google", ["gooogle.com"], None
        ))

    def test_empty_feed_returns_no_matches(self):
        matched, _ = run("google", [])
        self.assertEqual([], matched)
