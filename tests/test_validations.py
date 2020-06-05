from unittest import TestCase
from opensquat.validations import levenshtein, jaro_winkler


class TestValidations(TestCase):
    def test_jaro_winkler(self):
        self.assertEqual(0.9166666666666667, jaro_winkler("netflix", "netflix123.com"))
        self.assertEqual(0.0, jaro_winkler("netflix", "888888888888.com"))

    def test_levenshtein(self):
        self.assertEqual(7, levenshtein("netflix", "netflix123.com"))
        self.assertEqual(16, levenshtein("netflix", "888888888888.com"))
