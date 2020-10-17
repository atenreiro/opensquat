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
import time


class VirusTotal:
    def __init__(self):
        """Initiator."""
        self.domain = ""
        self.subdomains = []
        self.URL = ""
        self.content = ""
        self.op = ""

    def set_domain(self, domain):
        self.domain = domain

    def set_operation(self, op):
        self.op = op

    def get_content(self):

        if self.op == "subdomains":
            self.URL = "https://www.virustotal.com/ui/domains/" + self.domain \
                       + "/subdomains"
        else:
            self.URL = "https://www.virustotal.com/ui/domains/" + self.domain

        # User-Agent Headers
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            "AppleWebKit/537.36 (KHTML, like Gecko)"
            "Chrome/78.0.3904.108 Safari/537.36"
        }

        # Get response content
        response = requests.get(self.URL, stream=True, headers=headers)
        content = json.loads(response.content)

        self.content = content

    def get_subdomains(self):

        try:
            if "error" in self.content:
                print(" \_ VirusTotal might be throttling/blocking")
                return False
            elif self.content.get('data'):
                for item in self.content['data']:
                    if item['type'] == 'domain':
                        subdomain = item['id']
                        self.subdomains.append(subdomain)
        except Exception:
            return False

        if self.subdomains:
            return self.subdomains
        else:
            return False

    def get_malicious(self):

        try:
            malicious = (
                self.content
                ['attributes']
                ['last_analysis_stats']
                ['malicious']
                )
        except KeyError:
            return -1

        return malicious

    def main(self, domain, op):
        self.set_domain(domain)
        self.set_operation(op)
        self.get_content()

        if (op == "subdomains"):
            return self.get_subdomains()
        else:
            return self.get_malicious()
