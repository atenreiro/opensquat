# -*- coding: utf-8 -*-
# Module: phishing.py
"""
openSquat

(c) Andre Tenreiro

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import requests
import time
from opensquat import file_input

from colorama import Fore, Style


class Phishing:

    """
    Class Phishing.

    To use:
        Phishing().main(keyword)

    Attribute:
        keyword: list of keywords
    """
    def __init__(self):
        self.phishing_db = "https://phish.co.za" \
                           "/latest/" \
                           "phishing-domains-ACTIVE.txt"
        # Used when the Phishing Database cannot be downloaded: the domains
        # that public threat feeds reported for phishing or malware in the
        # last 24 hours, one per line, free and without a key.
        self.fallback_db = "https://netapi.com/api2/" \
                           "?method=compromised&dataset_type=url"
        self.phishing_filename = "phishing.db"
        self.keyword = ""
        self.keywords_filename = ""
        self.list_domains = []
        self.keywords_total = 0

    def set_keywords(self, keywords):
        self.keywords_filename = keywords

    @staticmethod
    def URL_contains(keyword, phishing):
        if keyword in phishing:
            return True

        return False

    def count_keywords(self):
        self.keywords_total = file_input.InputFile().main(
            self.keywords_filename,
            None
            )

    def check_phishing(self):
        # keyword iteration
        i = 0

        # Open phishing DB
        with open(self.keywords_filename, mode='r', encoding='utf-8') as f_key:
            for raw_keyword in f_key:
                keyword = raw_keyword.strip().lower()

                # Skip blank, whitespace-only, and comment lines. Replaces
                # the old line[0] indexing pattern that crashed on empty
                # input and also miscounted whitespace-only lines.
                if not keyword or keyword.startswith("#"):
                    continue

                i += 1
                print(
                    Fore.WHITE + "\n[*] Verifying keyword:",
                    keyword,
                    "[",
                    i,
                    "/",
                    self.keywords_total,
                    "]" + Style.RESET_ALL,
                )

                with open(self.phishing_filename, mode='r', encoding='utf-8') as f_phishing:
                    for site in f_phishing:
                        # Lowercase AND strip newline in one pass. The old
                        # version assigned site.lower() then overwrote it
                        # with site.replace("\n", ""), producing a case-
                        # sensitive comparison that missed mixed-case hits.
                        phishing_site = site.replace("\n", "").lower()

                        # A list may start with a "#" header line, which is
                        # not a site and must not match a keyword.
                        if phishing_site.startswith("#"):
                            continue

                        if self.URL_contains(keyword, phishing_site):
                            print(
                                Style.BRIGHT + Fore.YELLOW +
                                "  \\_ Similarity detected between",
                                keyword,
                                "and",
                                phishing_site,
                                "" + Style.RESET_ALL
                                )
                            self.list_domains.append(phishing_site)

        return self.list_domains

    def download_db(self, url):
        """
        Download one phishing list.

        Return the body, or None when the source did not answer with a
        non-empty list. A server that is down answers with an error page
        (phish.co.za returns a short 503 or 403 HTML page), and that page
        must not be saved as the database: every keyword would then
        silently match nothing.
        """
        print("[*] Downloading fresh Phishing DB from", url)
        try:
            # Timeout so a hung phishing DB server cannot freeze the CLI.
            r = requests.get(url, timeout=60)
        except requests.exceptions.RequestException as e:
            print("[!] Phishing DB not reachable:", e)
            return None

        data = r.content
        r.close()

        if r.status_code != 200:
            print("[!] Phishing DB unavailable: HTTP", r.status_code)
            return None

        if len(data) == 0:
            print("[!] Phishing DB is empty")
            return None

        return data

    def update_db(self):

        data = self.download_db(self.phishing_db)
        if data is None:
            print("[*] Trying the fallback list")
            data = self.download_db(self.fallback_db)

        if data is None:
            print(
                "[ERROR] No phishing list could be downloaded. " +
                "Try again later. Exiting...\n",
            )
            exit(-1)

        total_size_mb = round(float(len(data) / 1024 / 1024), 2)
        print("[*] Download volume:", total_size_mb, "MB")

        with open(self.phishing_filename, "wb") as f:
            f.write(data)

        return True

    def main(self, keywords):
        """
        main function that will call other functions.

        Args:
            keyword: keyword to search for(duh)

        Return:
            none
        """
        print("")
        print("+---------- Checking Phishing sites ----------+")
        time.sleep(2)
        self.set_keywords(keywords)
        self.update_db()
        self.count_keywords()
        return self.check_phishing()
