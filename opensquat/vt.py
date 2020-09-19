# -*- coding: utf-8 -*-
# Module: virustotal.py
"""
openSquat

(c) CERT-MZ

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import requests
import json


class VirusTotal:
    def __init__(self):
        """Initiator."""
        self.domain = ""
        self.subdomains = []
        self.URL = ""

    def set_domain(self, domain):
        self.domain = domain

    def check_subdomain(self):

        self.URL = "https://www.virustotal.com/ui/domains/" + self.domain \
                   + "/subdomains"

        # User-Agent Headers
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            "AppleWebKit/537.36 (KHTML, like Gecko)"
            "Chrome/78.0.3904.108 Safari/537.36"
        }

        response = requests.get(self.URL, stream=True, headers=headers)
        content = json.loads(response.content)

        try:
            if "error" in content:
                print(" \_ VirusTotal might be throttling/blocking")
                return False
            elif content.get('data'):
                for item in content['data']:
                    if item['type'] == 'domain':
                        subdomain = item['id']
                        self.subdomains.append(subdomain)
        except Exception:
            return False

        if self.subdomains:
            return self.subdomains
        else:
            return False

    def main(self, domain):
        self.set_domain(domain)
        subdomains = self.check_subdomain()

        if subdomains:
            return subdomains
        else:
            return False
