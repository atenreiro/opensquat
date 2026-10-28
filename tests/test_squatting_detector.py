"""Case-insensitive synthetic matching for DNS domain names."""
import io
from unittest import TestCase
from unittest.mock import Mock, patch

from opensquat.squatting_detector import SquattingDetector


class TestSquattingDetector(TestCase):
    def test_levenshtein_matching_normalizes_keyword_case(self):
        detector = SquattingDetector(confidence_level=1)
        output = io.StringIO()

        with patch(
            "opensquat.squatting_detector.homograph.check_homograph",
            return_value=False,
        ):
            domains = detector.check("GOOGLE", ["go0gle.invalid"], output)

        self.assertEqual(["go0gle.invalid"], domains)
        self.assertIn("Similarity detected between GOOGLE", output.getvalue())

    def test_doppelganger_matching_normalizes_keyword_case(self):
        detector = SquattingDetector(doppelganger_only=True)
        response = Mock(status_code=200, text="google")

        with (
            patch(
                "opensquat.squatting_detector.homograph.check_homograph",
                return_value=False,
            ),
            patch(
                "opensquat.squatting_detector.requests.get",
                return_value=response,
            ) as get,
            patch(
                "opensquat.squatting_detector.ct.CRTSH.check_certificate",
                return_value=True,
            ),
        ):
            domains = detector.check("Google", ["google.invalid"])

        self.assertEqual(["google.invalid"], domains)
        get.assert_called_once_with("https://google.invalid", timeout=5)
