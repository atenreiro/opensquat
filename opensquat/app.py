# -*- coding: utf-8 -*-
# Module: app.py
"""
openSquat

(c) CERT-MZ

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import requests
import bisect
import hashlib
import os
from opensquat import __VERSION__

from colorama import Fore, Style
from datetime import date
from opensquat import validations, homograph, ct, dns_resolvers, file_input


class Domain:
    """
    The Domain class with handle all the functions related to
    the domain verifications.

    To use:
        Domain().main(keywords, confidence, domains)

    Attribute:
        URL: The URL to download the updated domain list
        URL_file: The URL file name
        today: today's date in the format yyyy-mm-dd
        domain_filename: If no URL download is required, the local file
                         containing the domains
        keywords_filename: File containing the keywords (plain text)
        domain_total: Total count number of domains from domain_filename
        keywords_total: Total count number of keywords from keywords_filename
        list_domains: A list containing all the flagged domains
        confidence_level: An int containing the confidence of
                          sensitiveness level
        confidence: Dictionary containing the respective confidence string
    """

    def __init__(self):
        """Initiator."""
        self.URL = ("https://feeds.opensquat.com/")
        self.URL_backup = (
            "https://raw.githubusercontent.com/CERT-MZ/projects"
            "/master/Domain-squatting/"
        )
        self.URL_file = None
        self.today = date.today().strftime("%Y-%m-%d")
        self.domain_filename = None
        self.keywords_filename = None
        self.domain_total = 0
        self.keywords_total = 0
        self.list_domains = []
        self.confidence_level = 2
        self.period = "day"
        self.doppelganger_only = False
        self.dns_validation = False
        self.list_dns_domains = []
        self.list_file_domains = []
        self.list_file_keywords = []

        self.confidence = {
            0: "very high confidence",
            1: "high confidence",
            2: "medium confidence",
            3: "low confidence",
            4: "very low confidence",
        }

        self.jaro_winkler = {
            0.8: "Low",
            0.89: "Medium",
            0.949: "High",
            0.95: "Very high",
        }

        self.method = "Levenshtein"

    def count_files(self):

        (self.keywords_total, self.domain_total) = file_input.InputFile().main(
            self.keywords_filename,
            self.domain_filename
            )

    @staticmethod
    def domain_contains(keyword, domain):
        if keyword in domain:
            return True

        return False

    def read_files(self):
        """
        Method to read domain files

        Args:
            none

        Return:
            none
        """
        file_domains = open(self.domain_filename, "r")
        file_keywords = open(self.keywords_filename, "r")

        for mydomains in file_domains:
            domain = mydomains.replace("\n", "")
            domain = domain.lower()
            self.list_file_domains.append(domain)

        for line in file_keywords:
            if (
                (line[0] != "#") and
                (line[0] != " ") and
                (line[0] != "") and
                (line[0] != "\n")
            ):
                self.list_file_keywords.append(line)

    def check_latest_feeds(self):

        URL = self.URL + self.URL_file + ".md5"

        print("[*] Checking for the latest feeds...")

        # User-Agent
        ver = "openSquat-" + __VERSION__
        headers = {'User-Agent': ver}

        try:
            response = requests.get(URL, headers=headers)
        except requests.exceptions.RequestException:
            return False

        if (response.status_code != 200):
            return False

        latest_checksum = response.content.decode('utf-8')
        latest_checksum = latest_checksum.replace("\n", "")
        latest_checksum = latest_checksum.strip()

        response.close()

        # Compare if local file is the latest
        if os.path.exists(self.domain_filename):
            with open(self.domain_filename, "rb") as f:
                try:
                    local_checksum = hashlib.md5(f.read()).hexdigest()

                    if latest_checksum == local_checksum:
                        print("[*] You have the latest feeds\n")
                        # print("-> ", latest_checksum, " ", local_checksum)
                        return True
                    else:
                        # print("-> ", latest_checksum, " ", local_checksum)
                        return False

                except:
                    return False
        return False

    def download(self):
        """
        Download the latest newly registered domains and save locally.

        Args:
            none

        Return:
            none
        """
        URL = self.URL + self.URL_file

        print("[*] Downloading fresh domain list:", self.URL_file)

        # User-Agent
        ver = "openSquat-" + __VERSION__
        headers = {'User-Agent': ver}
        response = requests.get(URL, stream=True, headers=headers)

        # fault tolerance in case the "domain-names.txt is not found"
        if (response.status_code == 403 or response.status_code == 404):
            print(
                Style.BRIGHT+Fore.RED+"[ERROR]", self.URL_file, "not found," +
                "trying the backup URL."+Style.RESET_ALL
                )
            URL = self.URL_backup + self.URL_file
            print("[*] Downloading fresh domain list from backup URL", URL)
            response = requests.get(URL, stream=True, headers=headers)

        # Get total file size in bytes from the request header
        total_size = int(response.headers.get("content-length", 0))
        total_size_mb = round(float(total_size / 1024 / 1024), 2)

        # Validate if the URL file is not found
        if total_size_mb == 0:

            print(
                Style.BRIGHT+Fore.RED+"[ERROR]", self.URL_file, "not found, " +
                "Please notify the authors or try again later."+Style.RESET_ALL
                )
            exit(-1)

        print("[*] Download volume:", total_size_mb, "MB")

        data = response.content
        response.close()

        with open(self.URL_file, "wb") as f:
            f.write(data)

        f.close()

        self.domain_filename = self.URL_file

        return True

    def set_domain_filename(self, domain_filename):
        """
        Method to set the domain filename.

        Args:
            domain_filename

        Returns:
            none
        """
        if domain_filename == "":
            self.domain_filename = "domain-names.txt"
        else:
            self.domain_filename = domain_filename

    def set_filename(self, filename):
        """
        Method to set the filename.

        Args:
            keywords_filename

        Returns:
            none
        """
        self.keywords_filename = filename

    def set_searchPeriod(self, search_period):
        """
        Method to set the search_period.

        Args:
            search_period

        Return:
            none
        """
        self.period = search_period

        if self.period == "day":
            self.URL_file = "domain-names.txt"
        elif self.period == "week":
            self.URL_file = "domain-names-week.txt"
        elif self.period == "month":
            self.URL_file = "domain-names-month.txt"

    def set_dns_validation(self, dns):
        """
        Method to set the search_period.

        Args:
            dns provider

        Return:
            none
        """
        if dns:
            self.dns_validation = True
        else:
            self.dns_validation = False

    def print_info(self):
        """
        Method to print some configuration information.

        Args:
            none

        Return:
            none
        """
        print("[*] keywords:", self.keywords_filename)
        print("[*] keywords total:", self.keywords_total)
        print("[*] Total domains:", f"{self.domain_total:,}")
        print("[*] Threshold:", self.confidence[self.confidence_level])

    def worker(self):
        """
        Method that will compute all the similarity calculations between
        the keywords and domain names.

        Args:
            none

        Return:
            list_domains: list containing all the flagged domains
        """
        # keyword iteration
        i = 0

        # Domains iteration
        j = 0

        domain_total_lines = self.domain_total * self.keywords_total

        for keyword in self.list_file_keywords:
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

                for domains in self.list_file_domains:
                    domain = domains.split(".")
                    domain = domain[0].replace("\n", "")
                    domain = domain.lower()
                    domains = domains.replace("\n", "")

                    # Show Progress every 50.000 line
                    if ((j % 50000 == 0) and (j != 0)):
                        progress = round(((j * 100) / domain_total_lines), 1)
                        print(">> Progress:", progress, "%")

                    # Check if the domain contains homograph character
                    #   Yes: returns True
                    #   No:  returns False
                    homograph_domain = homograph.check_homograph(domain)

                    if homograph_domain:
                        domain = homograph.homograph_to_latin(domain)

                    if self.doppelganger_only:
                        self._process_doppelgagner_only(
                            keyword,
                            domain,
                            domains
                            )
                        continue

                    if self.method.lower() == "levenshtein":
                        self._process_levenshtein(
                            keyword, domain, homograph_domain, domains
                        )
                    elif self.method.lower() == "jarowinkler":
                        self._process_jarowinkler(
                            keyword, domain, homograph_domain, domains
                        )
                    else:
                        print(
                            f"No such method: {self.method}. "
                            "Levenshtein will be used as default."
                        )
                        self._process_levenshtein(
                            keyword, domain, homograph_domain, domains
                        )
                    j += 1

        return self.list_domains

    def _process_doppelgagner_only(self, keyword, domain, domains):
        def print_info(_info):
            print(
                Style.BRIGHT + Fore.RED + f"[+] {_info} between",
                keyword,
                "and",
                domains,
                "" + Style.RESET_ALL,
            )

        doppelganger = self.domain_contains(keyword, domain)

        if doppelganger:
            if not ct.CRTSH.check_certificate(domains):
                print_info("suspicious certificate detected")
            else:
                print_info("suspicious certificate detected")
            self.list_domains.append(domain)

    def _process_levenshtein(self, keyword, domain, homograph_domain, domains):
        leven_dist = validations.levenshtein(keyword, domain)

        if (leven_dist <= self.confidence_level) and not homograph_domain:
            self.on_similarity_detected(
                keyword,
                domains,
                self.confidence[leven_dist]
                )

            #  DNS Validation
            if(self.dns_validation):
                self.dns_reputation(domains)

        elif (leven_dist <= self.confidence_level) and homograph_domain:
            self.on_homograph_detected(
                keyword,
                domains,
                self.confidence[leven_dist]
                )

            #  DNS Validation
            if(self.dns_validation):
                self.dns_reputation(domains)

        elif self.domain_contains(keyword, domains):
            self.on_domain_contains(keyword, domains)

            # DNS validation
            if(self.dns_validation):
                self.dns_reputation(domains)

    @staticmethod
    def dns_error_NoAnswer():
        print(
            Fore.YELLOW + "  \_ DNS Server error: No Answer\n" +
            Style.RESET_ALL,
        )

    @staticmethod
    def dns_error_NoNameservers():
        print(
            Fore.YELLOW + "  \_ DNS Server error: No Name Servers (SRVFAIL)" +
            "\n" + Style.RESET_ALL,
        )

    @staticmethod
    def dns_error_timeout():
        print(
            Fore.YELLOW + "  \_ DNS Server error: " +
            "Possible Provider throttling\n" + Style.RESET_ALL,
        )

    @staticmethod
    def dns_error_nxdomain():
        print(
            Fore.YELLOW + "  \_ DNS response: Non-Existent Domain\n" +
            Style.RESET_ALL,
        )

    @staticmethod
    def dns_error(dns_resp):
        print(
            Fore.YELLOW + "  \_ DNS response:",
            dns_resp,
            "\n" + Style.RESET_ALL,
        )

    @staticmethod
    def dns_malicious():
        print(
            Style.BRIGHT + Fore.RED + "  \_ Domain Reputation: Malicious\n" +
            Style.RESET_ALL,
        )

    @staticmethod
    def dns_non_malicious():
        print(
            Fore.GREEN + "  \_ Domain Reputation: Non-malicious\n" +
            Style.RESET_ALL,
        )

    def dns_reputation(self, domain):

        dns_resp = dns_resolvers.Quad9().main(domain)

        # Check response based on DNS rcodes
        if (dns_resp == "non-malicious"):
            self.dns_non_malicious()  # No error / Non-malicous
        elif (dns_resp == "malicious"):
            self.dns_malicious()  # Domain Malicious
            self.list_dns_domains.append(domain)
        elif (dns_resp == "Timeout"):
            self.dns_error_timeout()  # Connection timeout
        elif (dns_resp == "NXDOMAIN"):
            self.dns_error_nxdomain()  # NXDOMAIN / Non-existent Domain
        elif (dns_resp == "NoNameservers"):
            self.dns_error_NoNameservers()  # SRVFAIL / No Name servers
        elif (dns_resp == "NoAnswer"):
            self.dns_error_NoAnswer()
        else:
            self.dns_error(dns_resp)

    def _process_jarowinkler(self, keyword, domain, homograph_domain, domains):
        similarity = validations.jaro_winkler(keyword, domain)
        keys = list(self.jaro_winkler.keys())
        values = list(self.jaro_winkler.values())
        triggered_values = values[1:]  # every value except Low will trigger
        insertion_point = bisect.bisect_left(keys, similarity)

        if insertion_point == len(keys):
            insertion_point -= 1

        value = values[insertion_point]
        if value in triggered_values and not homograph_domain:
            self.on_similarity_detected(keyword, domains, value)

        elif value in triggered_values and homograph_domain:
            self.on_homograph_detected(keyword, domains, value)

        elif self.domain_contains(keyword, domains):
            self.on_domain_contains(keyword, domains)

    def on_similarity_detected(self, keyword, domains, value):
        print(
            Style.BRIGHT + Fore.RED + "[+] Similarity detected between",
            keyword,
            "and",
            domains,
            "(%s)" % value,
            "" + Style.RESET_ALL,
        )
        self.list_domains.append(domains)

    def on_homograph_detected(self, keyword, domains, value):
        print(
            Style.BRIGHT + Fore.RED + "[+] Homograph detected between",
            keyword,
            "and",
            domains,
            "(%s)" % value,
            "" + Style.RESET_ALL,
        )
        self.list_domains.append(domains)

    def on_domain_contains(self, keyword, domains):
        print(Fore.YELLOW + "[+] Found", domains, "" + Style.RESET_ALL)
        self.list_domains.append(domains)

    def main(
        self,
        keywords_file,
        confidence_level,
        domains_file,
        search_period,
        method,
        dns,
        doppelganger_only=False,
    ):
        """
        Method to call the class functions.

        Args:
            none

        Return:
            none
        """
        print("+---------- Checking Domain Squatting ----------+")
        self.set_filename(keywords_file)
        self.domain_filename = domains_file
        self.set_searchPeriod(search_period)
        self.confidence_level = confidence_level
        self.doppelganger_only = doppelganger_only
        self.set_dns_validation(dns)
        self.method = method

        if self.domain_filename == "":
            self.domain_filename = self.URL_file
            if not self.check_latest_feeds():
                self.download()

        self.count_files()
        self.read_files()
        self.print_info()

        return self.worker()
