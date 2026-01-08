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
from datetime import date
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
        self.today = date.today().strftime("%Y-%m-%d")
        self.domain_filename = None
        self.keywords_filename = None
        self.domain_total = 0
        self.keywords_total = 0
        self.list_domains = []
        self.confidence_level = 2
        self.doppelganger_only = False
        self.method = "Levenshtein"

        self.feed_manager = FeedManager()
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
        with open(self.domain_filename, mode='r') as file_domains:
            for mydomains in file_domains:
                domain = mydomains.replace("\n", "")
                domain = domain.lower().strip()
                # Skip comments and empty lines
                if domain and not domain.startswith("#"):
                    self.list_file_domains.append(mydomains)  # Keep original line for detector

        with open(self.keywords_filename, mode='r') as file_keywords:
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

        # Detector confidence mapping is internal now, but we can print level
        # self.squatting_detector.confidence[self.confidence_level] access might be needed or hardcoded
        # Replicating original behavior hardcoded or accessing detector
        confidence_map = {
            0: "very high confidence",
            1: "high confidence",
            2: "medium confidence",
            3: "low confidence",
            4: "very low confidence",
        }
        print("[*] Threshold:", confidence_map.get(self.confidence_level, "unknown"))

    @staticmethod
    def verify_keyword_task(detector, domains_list, keyword_info):
        """
        Static worker method for parallel execution.
        """
        keyword, keyword_line_number, keywords_total = keyword_info

        result_buffer = io.StringIO()
        print(f"[+] Starting Domain Squatting verification for '{keyword}' [{keyword_line_number}/{keywords_total}]")

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
        # We pass the detector instance. Ideally pickling it is cheap as it has no heavy state.
        # The list_file_domains is passed explicitly to partial, so it's pickled once per process start (fork) or task?
        # On spawn (macOS), arguments to partial are pickled and sent.
        # Sending the full list_file_domains (360k items) for EVERY keyword task is what we wanted to avoid.
        # But here we are still passing it.
        # However, verifying 5-10 keywords means 5-10 tasks.
        # If we use ProcessPoolExecutor, we submit tasks.
        # To truly optimize, we need to avoid sending the list every time.
        # But given the current architecture without shared memory or a Manager,
        # passing it is the standard way.
        # EXCEPT: If we use `initializer` in Executor to load domains once per worker process?
        # But let's stick to the structure refactor first.
        # The `detector` is now lightweight (no domain list in it).

        # NOTE: For true optimization on Spawn systems, we should load domains inside the worker process
        # or use shared memory. But standard refactoring is the first step.

        with concurrent.futures.ProcessPoolExecutor() as executor:
            # We must be careful not to pass `self` methods if they pickle `self`.
            # That's why verify_keyword_task is static.

            # Prepare task arguments
            keyword_infos = [
                (keyword, i, self.keywords_total)
                for i, keyword in enumerate(self.list_file_keywords) if keyword
            ]

            # Partial: detector and domains are constant for all tasks
            # Optimization note: This still sends domains_list to each process.
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
        method,
        dns,
        doppelganger_only=False,
    ):
        print("+---------- Checking Domain Squatting ----------+")
        self.keywords_filename = keywords_file
        self.domain_filename = domains_file
        self.confidence_level = confidence_level
        self.doppelganger_only = doppelganger_only
        self.method = method

        self.dns_validator = DNSValidator(use_dns=dns)
        self.squatting_detector = SquattingDetector(
            method=method,
            confidence_level=confidence_level,
            doppelganger_only=doppelganger_only,
            dns_validator=self.dns_validator
        )

        # Feed Management
        if self.domain_filename == "":
            self.domain_filename = self.feed_manager.url_file
            self.feed_manager.ensure_feeds(self.domain_filename)

        self.count_files()
        self.read_files()
        self.print_info()

        return self.worker()
