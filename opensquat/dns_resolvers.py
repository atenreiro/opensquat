# -*- coding: utf-8 -*-
# Module: dns_resolvers.py
"""
openSquat.

(c) CERT-MZ

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import dns.resolver


class Quad9:

    """
    The Quad9 is responsible for to check if the doman is malicious

    To use:
        Quad9().main(domain)

    Attribute:
        domain: the domain name to validate
        resolver: the Quad9 resolver (default is 9.9.9.9)
        dns_resp: (string) DNS response
    """
    def __init__(self):
        """initiator."""
        self.resolver = "9.9.9.9"
        self.dns_resp = None
        self.domain = None

    def set_domain(self, domain):
        self.domain = domain

    def dns_query(self):

        my_resolver = dns.resolver.Resolver()
        my_resolver.nameservers = [self.resolver]
        my_resolver.search = []

        try:
            my_resolver.query(self.domain, "A")
            self.dns_resp = "non-malicious"

        except dns.resolver.NXDOMAIN as e:

            for (name, resp) in e.responses().items():
                RA = resp.flags & dns.flags.RA

                if(RA == 0):
                    self.dns_resp = "malicious"
                else:
                    self.dns_resp = "NXDOMAIN"
        except dns.resolver.NoAnswer:
            self.dns_resp = "NoAnswer"
        except dns.resolver.Timeout:
            self.dns_resp = "Timeout"
        except dns.resolver.NoNameservers:
            self.dns_resp = "NoNameservers"

        return self.dns_resp

    def main(self, domain):
        """
        main function that will call other functions.

        Args:
            domain: the domain name (duh)

        Return:
            none
        """
        self.set_domain(domain)
        return self.dns_query()
