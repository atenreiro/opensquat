from unittest import TestCase
from opensquat.validations import levenshtein


class TestValidations(TestCase):
    def test_levenshtein(self):
        self.assertEqual(7, levenshtein("netflix", "netflix123.com"))
        self.assertEqual(16, levenshtein("netflix", "888888888888.com"))
