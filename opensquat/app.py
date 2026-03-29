# -*- coding: utf-8 -*-
# Module: app.py
"""
openSquat

(c) Andre Tenreiro

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import concurrent.futures
import functools
import io
from colorama import Fore, Style

from opensquat import file_input
from opensquat.feed_manager import FeedManager
from opensquat.dns_validator import DNSValidator
from opensquat.squatting_detector import SquattingDetector


class Domain:
    """
    Main orchestration class for OpenSquat.
    """

    def __init__(self):
        """Initiator."""
        self.domain_filename = None
        self.keywords_filename = None
        self.domain_total = 0
        self.keywords_total = 0
        self.list_domains = []
        self.confidence_level = 2
        self.doppelganger_only = False

        self.feed_manager = None
        self.dns_validator = None
        self.squatting_detector = None

        self.list_file_domains = []
        self.list_file_keywords = []

    def count_files(self):
        (self.keywords_total, self.domain_total) = file_input.InputFile().main(
            self.keywords_filename,
            self.domain_filename
        )

    def read_files(self):
        """
        Method to read domain files
        """
        with open(self.domain_filename, mode='r', encoding='utf-8') as file_domains:
            for mydomains in file_domains:
                domain = mydomains.replace("\n", "")
                domain = domain.lower().strip()
                # Skip comments and empty lines
                if domain and not domain.startswith("#"):
                    self.list_file_domains.append(domain)

        with open(self.keywords_filename, mode='r', encoding='utf-8') as file_keywords:
            for line in file_keywords:
                line = line.strip()
                if line and not line.startswith("#"):
                    self.list_file_keywords.append(line)

    def print_info(self):
        """
        Method to print some configuration information.
        """
        print("[*] keywords:", self.keywords_filename)
        print("[*] keywords total:", self.keywords_total)
        print("[*] Total domains:", f"{self.domain_total:,}")

        print("[*] Threshold:", self.squatting_detector.confidence.get(self.confidence_level, "unknown"))

    @staticmethod
    def verify_keyword_task(detector, domains_list, keyword_info):
        """
        Static worker method for parallel execution.
        """
        keyword, keyword_line_number, keywords_total = keyword_info

        result_buffer = io.StringIO()
        print(
            f"[+] Starting Domain Squatting verification for '{keyword}' [{keyword_line_number}/{keywords_total}]",
            file=result_buffer
        )

        print(
            Fore.WHITE + "\n[*] Verifying keyword:",
            keyword,
            "[",
            keyword_line_number,
            "/",
            keywords_total,
            "]" + Style.RESET_ALL,
            file=result_buffer
        )

        result_domains = detector.check(keyword, domains_list, result_buffer)
        return result_buffer, result_domains

    def worker(self):
        """
        Method that will compute all the similarity calculations between
        the keywords and domain names.
        """
        with concurrent.futures.ProcessPoolExecutor() as executor:
            keyword_infos = [
                (keyword, i + 1, self.keywords_total)
                for i, keyword in enumerate(self.list_file_keywords) if keyword
            ]

            worker_func = functools.partial(self.verify_keyword_task, self.squatting_detector, self.list_file_domains)

            futs = [executor.submit(worker_func, k_info) for k_info in keyword_infos]

        for fut in futs:
            result_buffer, result_domains = fut.result()
            print(result_buffer.getvalue())
            self.list_domains.extend(result_domains)

        return self.list_domains

    def main(
        self,
        keywords_file,
        confidence_level,
        domains_file,
        dns,
        doppelganger_only=False,
        feed_url="https://feeds.opensquat.com/opensquat-nrd-latest.txt",
    ):
        print("+---------- Checking Domain Squatting ----------+")
        self.keywords_filename = keywords_file
        self.domain_filename = domains_file
        self.confidence_level = confidence_level
        self.doppelganger_only = doppelganger_only

        self.dns_validator = DNSValidator(use_dns=dns)
        self.squatting_detector = SquattingDetector(
            confidence_level=confidence_level,
            doppelganger_only=doppelganger_only,
            dns_validator=self.dns_validator
        )

        # Feed Management
        self.feed_manager = FeedManager(feed_url=feed_url)
        if self.domain_filename == "":
            self.domain_filename = self.feed_manager.local_filename
            self.feed_manager.ensure_feeds()

        self.count_files()
        self.read_files()
        self.print_info()

        return self.worker()
