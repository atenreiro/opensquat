# -*- coding: utf-8 -*-
# Module: doh_resolver.py
"""
openSquat

(c) CERT-MZ

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import requests


class DoH:
    """The Quad9 is responsible for to check if the doman is malicious

    To use:
        Quad9().main(domain)

    Attribute:
        domain: the domain name to validate
        resolver: the Quad9 resolver (default is 9.9.9.9)
    """
    def __init__(self):
        self.domain = ""
        self.doh_url = ""
        self.provider = ""

    def set_doh_url(self, provider):

        if (provider == "cloudflare"):
            self.doh_url = """
                           https://security.cloudflare-dns.com/dns-query?name="
                           """
            self.provider = "Cloudflare"

        elif (provider == "quad9"):
            self.doh_url = "https://dns.quad9.net:5053/dns-query?name="
            self.provider = "Quad9"

        else:
            print("[ERROR] Unkown DNS provider:", provider)
            exit(-1)

    def set_domain(self, domain):
        self.domain = domain

    def cloudflare_query(self):
        doh_url = self.doh_url + self.domain

        try:
            session = requests.session()
            r = session.get(doh_url, headers={"Accept": "application/dns-json"})
            status_code = r.status_code
            r = r.json()

            if (status_code == 400):
                print(
                    "[ERROR] DNS query not specified or too small " +
                    "(status code: 400)"
                    )

            elif (status_code == 413):
                print(
                    "[ERROR] DNS query is larger than maximum allowed" +
                    "DNS message size (status code: 413)"
                    )
            elif (status_code == 415):
                print(
                    "[ERROR] Unsupported content type (status code: 415)"
                    )
            elif (status_code == 504):
                print(
                    "[ERROR] Resolver timeout while waiting for the query" +
                    "response. (status code: 504)"
                    )

        except requests.exceptions.ConnectionError:
            return None

        IP = r['Answer'][-1]['data']

        if (IP == "0.0.0.0"):
            blocked_domain = True
        else:
            blocked_domain = False

        return blocked_domain
        
    def quad9_query(self):
        doh_url = self.doh_url + self.domain

        try:
            session = requests.session()
            r = session.get(doh_url)
            r = r.json()

            # Want to learn more about IANA DNS RCODES?
            # https://bit.ly/2ZXSWJq --> (original link over 80 chars)

            try:
                rcode = r['Status']
                RA = bool(r['RA'])
            except KeyError:
                return None

            if (rcode == 0):
                blocked_domain = 0  # No error
            elif (rcode == 1):
                blocked_domain = 1  # format error
            elif (rcode == 2):
                blocked_domain = 2  # Server failure
            elif ((rcode == 3) and (RA is True)):
                blocked_domain = 3  # Non-Existent Domain"
            elif ((rcode == 3) and (RA is False)):
                blocked_domain = 300  # Domain Blocked
            else:
                blocked_domain = rcode

        except requests.exceptions.ConnectionError:
            return None

        return blocked_domain

    def main(self, domain, provider):
        """main function that will call other functions

        Args:
            domain: the domain name (duh)

        Return:
            none
        """
        self.set_domain(domain)
        self.set_doh_url(provider)

        if (self.provider == "Cloudflare"):
            return self.cloudflare_query()
        elif (self.provider == "Quad9"):
            return self.quad9_query()
