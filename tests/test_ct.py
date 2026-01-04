from unittest import TestCase
from unittest.mock import patch, MagicMock
from opensquat.ct import CRTSH, CTLog


class TestCRTSH(TestCase):
    """Tests for Certificate Transparency checking."""
    
    def test_certificates_not_found(self):
        """Test that non-existent domains return False."""
        self.assertFalse(CRTSH.check_certificate("thisisnotarealdomain12345xyz.com"))

    @patch('opensquat.ct.requests.get')
    def test_network_error_returns_true(self, mock_get):
        """Test that network errors are handled gracefully."""
        mock_get.side_effect = Exception("Network error")
        # Should return True (fail-safe) when network is unavailable
        result = CRTSH.check_certificate("example.com")
        self.assertTrue(result)

    @patch('opensquat.ct.requests.get')
    def test_empty_ct_logs_returns_false(self, mock_get):
        """Test that no CT logs for a domain returns False."""
        mock_response = MagicMock()
        mock_response.text = "<html><body><table></table><table></table></body></html>"
        mock_get.return_value = mock_response
        result = CRTSH.check_certificate("nodomain.test")
        self.assertFalse(result)


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
