import unittest
from pysecurex.network_security import check_ssl_certificate, detect_mitm_attack
from unittest.mock import patch

class TestNetworkSecurity(unittest.TestCase):

    def test_check_ssl_certificate(self):
        # Mock the requests.get method to simulate SSL certificate check
        with patch('requests.get') as mocked_get:
            mocked_get.return_value.status_code = 200
            result = check_ssl_certificate("https://example.com")
            self.assertTrue(result)

    def test_detect_mitm_attack(self):
        # Mock the scapy.sniff method to simulate MITM attack detection
        with patch('scapy.all.sniff') as mocked_sniff:
            mocked_sniff.return_value = []
            result = detect_mitm_attack("eth0")
            self.assertFalse(result)

if __name__ == "__main__":
    unittest.main()