import unittest
from validators import verify_A_record



class TestVerifyARecord(unittest.TestCase):
    def test_known_good_domain_ip_pair(self):
        domain = "one.one.one.one"  # Cloudflare's domain
        ip = "1.1.1.1"  # Hosted by cloudflare
        self.assertTrue(verify_A_record(domain, ip))

    def test_known_bad_domain_ip_pair(self):
        domain = "one.one.one.one"
        ip = "171.67.70.3"  # An IP within Stanford's IP range, not Cloudflare's
        self.assertFalse(verify_A_record(domain, ip))

    CLOUDFLARE_HOSTING_IP = "104.21.96.65"
    AWS_HOSTING_IP = "75.2.60.5"
    cloudflare_domain = "prstephens.com"
    aws_hosted_domain = "clifbar.com"
    def test_good_domain_ip_pair_with_sni(self):
        # Since this IP address is a hosting endpoint for Cloudflare, it requires SNI to access cloudflare.com
        self.assertTrue(verify_A_record(self.cloudflare_domain, self.CLOUDFLARE_HOSTING_IP))
        self.assertTrue(verify_A_record(self.aws_hosted_domain, self.AWS_HOSTING_IP))

    def test_bad_domain_ip_pair_with_sni(self):
        self.assertFalse(verify_A_record(self.cloudflare_domain, self.AWS_HOSTING_IP))
        self.assertFalse(verify_A_record(self.aws_hosted_domain, self.CLOUDFLARE_HOSTING_IP))




if __name__ == '__main__':
    unittest.main()
