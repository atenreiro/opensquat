from unittest import TestCase
from opensquat.ct import CRTSH


class TestCRTSH(TestCase):
    def test_malicious_domains(self):
        self.assertFalse(CRTSH.check_certificate("facebookcontentmontorsettlement.com"))
        self.assertFalse(CRTSH.check_certificate("verifiedsfromfacebook.com"))
        self.assertFalse(CRTSH.check_certificate("user-login-facebook.com"))
        self.assertFalse(CRTSH.check_certificate("googlecloudarchitecture.com"))

    def test_valid_domains(self):
        self.assertTrue(CRTSH.check_certificate("facebook.com"))
        self.assertTrue(CRTSH.check_certificate("paypal.com"))
        self.assertTrue(CRTSH.check_certificate("netflix.com"))
        self.assertTrue(CRTSH.check_certificate("google.com"))

    def test_certificates_not_found(self):
        self.assertFalse(CRTSH.check_certificate("escortgooglee.com"))
