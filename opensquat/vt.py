# -*- coding: utf-8 -*-
# Module: virustotal.py
"""
openSquat

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import os
import json
import requests


class VirusTotal:
    """
    This domain class validates a domain on VirusTotal 

    To use:
        VirusTotal.main("opensquat.com")

    Attribute:
        domain: a domain name
    """
    def __init__(self):
        """Initiator."""
        self.domain = ""
        self.api_key = ""
        self.api_key_file = ""

    def set_apikey(self, api_key_file):

        self.api_key_file = api_key_file

        if not os.path.isfile(self.api_key_file):
            print(
                "[*] VT API Key File",
                self.api_key_file ,
                "not found or not readable! Exiting... \n",
            )
            exit(-1)

        file_vt = open(self.api_key_file, "r")

        for line in file_vt:
            if (
                (line[0] != "#") and
                (line[0] != " ") and
                (line[0] != "") and
                (line[0] != "\n")
            ):
                self.api_key = line

        file_vt.close()

        return True


    def set_domain(self, domain):
        self.domain = domain

    def domain_report(self):

        url = "https://www.virustotal.com/api/v3/domains/" + self.domain

        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

        response = requests.get(url, headers=headers, timeout=30)

        json_data = json.loads(response.text)

        if response.status_code == 200:

            if "data" in json_data and \
                "attributes" in json_data['data'] and \
                "total_votes" in json_data['data']['attributes']:

                harmless = json_data['data']['attributes']['total_votes']['harmless']
                malicious = json_data['data']['attributes']['total_votes']['malicious']
                harmless = int(harmless)
                malicious = int(malicious)
                total_votes = [harmless, malicious]

                return total_votes

        else:

            if "error" in json_data:
                message = json_data['error']['message']
                print("[*] VT API ERROR:", message)
                exit(-1)
            else:
                print(
                    "[*] Unexpected VT Response. HTTP Code: ",
                    response.status_code,
                    " Exiting... \n",
                )
                exit(-1)

    def main(self, domain, api_key_file="vt_key.txt"):
        self.set_domain(domain)
        self.set_apikey(api_key_file)
        return self.domain_report()
