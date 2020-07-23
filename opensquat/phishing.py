# -*- coding: utf-8 -*-
# Module: phishing.py
"""
openSquat

(c) CERT-MZ

* https://www.cert.mz
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
        self.phishing_db = "https://raw.githubusercontent.com/mitchellkrogza" \
                           "/Phishing.Database/master/" \
                           "phishing-domains-ACTIVE.txt"
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

        # Open phishing DB
        f_phishing = open(self.phishing_filename, "r")
        f_key = open(self.keywords_filename, "r")

        # keyword iteration
        i = 0

        for keyword in f_key:
            keyword = keyword.replace("\n", "")
            keyword = keyword.lower()

            if not keyword:
                continue

            if (
                (keyword[0] != "#") and
                (keyword[0] != " ") and
                (keyword[0] != "") and
                (keyword[0] != "\n")
            ):
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

                for site in f_phishing:
                    phishing_site = site.lower()
                    phishing_site = site.replace("\n", "")

                    if self.URL_contains(keyword, phishing_site):
                        print(
                            Style.BRIGHT + Fore.YELLOW +
                            "  \_ Similarity detected between",
                            keyword,
                            "and",
                            phishing_site,
                            "" + Style.RESET_ALL
                            )
                        self.list_domains.append(phishing_site)

        return self.list_domains

    def update_db(self):

        try:
            print(
                "[*] Downloading fresh Phishing DB from",
                self.phishing_db
                )
            session = requests.session()
            r = session.get(self.phishing_db, stream=True)

            # Get total file size in bytes from the request header
            total_size = int(r.headers.get("content-length", 0))
            total_size_mb = round(float(total_size / 1024 / 1024), 2)

            # Validate if the URL file is not found
            if total_size_mb == 0:

                print(
                    "[ERROR] File not found or empty! Contact the authors " +
                    "or try again later. Exiting...\n",
                )
                exit(-1)

            print("[*] Download volume:", total_size_mb, "MB")

            data = r.content
            r.close()

            with open(self.phishing_filename, "wb") as f:
                f.write(data)

            f.close()

        except requests.exceptions.ConnectionError:
            print("")
            exit(-1)

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
