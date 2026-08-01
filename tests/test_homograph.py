# -*- coding: utf-8 -*-
"""
Tests for opensquat.homograph — IDN homograph detection and normalisation.

This module is a thin wrapper over two third-party libraries
(confusable_homoglyphs and homoglyphs), both pinned only by a floor version
in pyproject.toml. These tests exist mainly as an upstream canary: if either
library changes behaviour on a fresh install, IDN detection breaks silently
and nothing else in the suite would notice.
"""
from unittest import TestCase

from opensquat.homograph import (
    check_homograph,
    decode_punycode,
    fold_to_latin,
    homograph_to_latin,
)


# Cyrillic lookalikes: а=U+0430, с=U+0441, о=U+043E
CYRILLIC_A = "а"
CYRILLIC_C = "с"
CYRILLIC_O = "о"


class TestCheckHomograph(TestCase):
    """check_homograph() returns a plain bool, never None."""

    def test_pure_latin_is_not_homograph(self):
        for domain in ("google", "paypal", "gooogle", "faceb00k", "123"):
            with self.subTest(domain=domain):
                self.assertFalse(check_homograph(domain))

    def test_empty_string_is_not_homograph(self):
        self.assertFalse(check_homograph(""))

    def test_cyrillic_substitution_is_homograph(self):
        self.assertTrue(check_homograph("mi" + CYRILLIC_C + "rosoft"))
        self.assertTrue(check_homograph(CYRILLIC_A + "pple"))
        self.assertTrue(check_homograph("g" + CYRILLIC_O + CYRILLIC_O + "gle"))

    def test_punycode_form_is_not_flagged(self):
        """
        Already-encoded punycode is pure ASCII, so check_homograph() does
        not detect it. That is fine: the detector handles "xn--" labels
        via decode_punycode() + fold_to_latin() instead — this function
        only ever sees raw-unicode input.
        """
        self.assertFalse(check_homograph("xn--80ak6aa92e"))

    def test_returns_actual_bool(self):
        self.assertIsInstance(check_homograph("google"), bool)
        self.assertIsInstance(check_homograph(CYRILLIC_A + "pple"), bool)


class TestHomographToLatin(TestCase):
    """homograph_to_latin() folds confusable characters back to ASCII."""

    def test_cyrillic_folds_to_latin(self):
        self.assertEqual("apple", homograph_to_latin(CYRILLIC_A + "pple"))
        self.assertEqual(
            "microsoft", homograph_to_latin("mi" + CYRILLIC_C + "rosoft")
        )
        self.assertEqual(
            "google",
            homograph_to_latin("g" + CYRILLIC_O + CYRILLIC_O + "gle"),
        )

    def test_pure_latin_is_unchanged(self):
        for domain in ("google", "paypal", "gooogle"):
            with self.subTest(domain=domain):
                self.assertEqual(domain, homograph_to_latin(domain))

    def test_empty_string_is_unchanged(self):
        self.assertEqual("", homograph_to_latin(""))

    def test_conversion_makes_the_brand_an_exact_match(self):
        """
        The end-to-end property the detector relies on: a homograph of a
        brand must fold to the brand itself, so the Levenshtein distance
        afterwards is 0 and the match is caught at any confidence level.
        """
        self.assertEqual(
            "microsoft", homograph_to_latin("mi" + CYRILLIC_C + "rosoft")
        )
        self.assertEqual("apple", homograph_to_latin(CYRILLIC_A + "pple"))


class TestDecodePunycode(TestCase):
    """decode_punycode() — lenient per-label punycode decoding."""

    def test_decodes_known_attack_labels(self):
        # xn--80ak6aa92e is the whole-Cyrillic apple.com PoC (2017);
        # xn--mirosoft-hw7c is the Latin small-capital microsoft example.
        self.assertEqual("аррӏе", decode_punycode("xn--80ak6aa92e"))
        self.assertEqual("miᴄrosoft", decode_punycode("xn--mirosoft-hw7c"))
        self.assertEqual("miсrosoft", decode_punycode("xn--mirosoft-gch"))

    def test_non_punycode_label_returns_none(self):
        self.assertIsNone(decode_punycode("google"))
        self.assertIsNone(decode_punycode(""))

    def test_invalid_punycode_returns_none_not_raises(self):
        self.assertIsNone(decode_punycode("xn--999999999"))
        self.assertIsNone(decode_punycode("xn--abcdef-!!!"))

    def test_bare_prefix_decodes_to_empty_string(self):
        """
        "xn--" alone decodes to "" — falsy, so the detector's
        `if decoded:` guard treats it the same as undecodable.
        """
        self.assertEqual("", decode_punycode("xn--"))


class TestFoldToLatin(TestCase):
    """
    fold_to_latin() — the gate that replaced is_dangerous() in the
    detector. Must catch what is_dangerous() misses (whole-script and
    same-script confusables) while returning None for anything that is
    not a Latin-lookalike label.
    """

    def test_mixed_script_attacks_fold_to_the_brand(self):
        self.assertEqual("microsoft", fold_to_latin("mi" + CYRILLIC_C + "rosoft"))
        self.assertEqual(
            "google", fold_to_latin("g" + CYRILLIC_O + CYRILLIC_O + "gle")
        )
        self.assertEqual("paypal", fold_to_latin("p" + CYRILLIC_A + "ypal"))

    def test_whole_script_cyrillic_folds(self):
        """is_dangerous() misses this (no script mixing); fold must not."""
        self.assertEqual("appie", fold_to_latin("аррӏе"))

    def test_latin_small_capital_folds(self):
        """Same-script confusable — also invisible to is_dangerous()."""
        self.assertEqual("microsoft", fold_to_latin("miᴄrosoft"))

    def test_pure_ascii_passes_through(self):
        self.assertEqual("google", fold_to_latin("google"))
        self.assertEqual("", fold_to_latin(""))

    def test_cjk_labels_return_none(self):
        """
        The false-positive guard: real feeds carry CJK/Hangul IDNs that
        are legitimate registrations, not lookalikes. Any unmappable
        character must abort the fold entirely — otherwise "衣食住行ai"
        would fold to "ai" and spuriously homograph-match short keywords.
        """
        for label in ("衣食住行ai", "bg真人", "서울아산병원pc개선사업", "小人さんのお店"):
            with self.subTest(label=label):
                self.assertIsNone(fold_to_latin(label))

    def test_accented_latin_returns_none(self):
        """ü/é are distinct characters, not homoglyphs of u/e."""
        self.assertIsNone(fold_to_latin("münchen"))
        self.assertIsNone(fold_to_latin("café"))
