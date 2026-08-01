# -*- coding: utf-8 -*-
"""Tests for opensquat.validations — the Levenshtein core."""
from unittest import TestCase

from opensquat.validations import levenshtein


class TestValidations(TestCase):
    def test_levenshtein(self):
        self.assertEqual(7, levenshtein("netflix", "netflix123.com"))
        self.assertEqual(16, levenshtein("netflix", "888888888888.com"))


class TestLevenshteinDistance(TestCase):
    """Unthresholded distances — the plain edit-distance contract."""

    def test_identical_strings_are_zero(self):
        self.assertEqual(0, levenshtein("google", "google"))

    def test_both_empty_is_zero(self):
        self.assertEqual(0, levenshtein("", ""))

    def test_empty_against_nonempty_is_length(self):
        self.assertEqual(3, levenshtein("", "abc"))
        self.assertEqual(3, levenshtein("abc", ""))

    def test_single_insertion(self):
        self.assertEqual(1, levenshtein("google", "gooogle"))

    def test_single_deletion(self):
        self.assertEqual(1, levenshtein("google", "gogle"))

    def test_single_substitution(self):
        self.assertEqual(1, levenshtein("google", "gongle"))

    def test_is_symmetric(self):
        self.assertEqual(
            levenshtein("paypal", "paypa1"), levenshtein("paypa1", "paypal")
        )


class TestLevenshteinThresholdContract(TestCase):
    """
    The threshold path is what production actually uses:
    SquattingDetector calls levenshtein(keyword, domain, confidence_level).

    Critical contract: when the distance exceeds `threshold`, the function
    returns `threshold + 1` — NOT the true distance and NOT a sentinel.
    Callers rely only on `result <= threshold` staying correct, but anything
    that "fixes" this to return the real distance silently shifts every
    confidence level in the tool. These tests pin it.
    """

    def test_exceeding_threshold_returns_threshold_plus_one(self):
        # True distance is 7; every threshold below it reports threshold + 1.
        self.assertEqual(7, levenshtein("netflix", "netflix123.com"))
        for threshold in range(0, 5):
            with self.subTest(threshold=threshold):
                self.assertEqual(
                    threshold + 1,
                    levenshtein("netflix", "netflix123.com", threshold),
                )

    def test_length_difference_shortcut_returns_threshold_plus_one(self):
        # abs(len0 - len1) > threshold exits before any matrix work.
        self.assertEqual(2, levenshtein("", "abc", 1))
        self.assertEqual(1, levenshtein("ab", "abcdef", 0))

    def test_within_threshold_returns_true_distance(self):
        self.assertEqual(1, levenshtein("google", "gooogle", 1))
        self.assertEqual(1, levenshtein("google", "gooogle", 4))
        self.assertEqual(0, levenshtein("google", "google", 0))

    def test_result_never_exceeds_threshold_plus_one(self):
        """Whatever the input, a thresholded call is bounded."""
        for threshold in range(0, 5):
            for domain in ("a", "abcdefghijklmnop", "google", "gooogle", ""):
                with self.subTest(threshold=threshold, domain=domain):
                    self.assertLessEqual(
                        levenshtein("google", domain, threshold), threshold + 1
                    )

    def test_threshold_preserves_the_match_decision(self):
        """
        The property the detector actually depends on: thresholding must
        never change the outcome of `distance <= threshold`.
        """
        pairs = [
            ("google", "gooogle"), ("google", "gogle"), ("google", "google"),
            ("google", "netflix"), ("paypal", "paypa1"), ("amazon", "arnazon"),
            ("microsoft", "rnicrosoft"), ("facebook", "faceb00k"),
        ]
        for keyword, domain in pairs:
            true_distance = levenshtein(keyword, domain)
            for threshold in range(0, 5):
                with self.subTest(pair=(keyword, domain), threshold=threshold):
                    self.assertEqual(
                        true_distance <= threshold,
                        levenshtein(keyword, domain, threshold) <= threshold,
                    )
