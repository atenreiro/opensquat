# -*- coding: utf-8 -*-
# Module: squatting_detector.py
"""
SquattingDetector module for openSquat.
Handles the core logic for detecting squatting domains.
Designed to be lightweight for parallel execution.
"""
import bisect
import io
import requests
from colorama import Fore, Style
from opensquat import validations, homograph, ct

class SquattingDetector:
    def __init__(self, method="Levenshtein", confidence_level=2, doppelganger_only=False, dns_validator=None):
        self.method = method.lower()
        self.confidence_level = confidence_level
        self.doppelganger_only = doppelganger_only
        
        # We don't pickle the DNS validator if we don't have to, 
        # but for now we pass it in. If parallel execution fails we might need to rethink this,
        # but DNSValidator is lightweight.
        self.dns_validator = dns_validator
        
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

    def check(self, keyword, domains_list, result_buffer=None):
        """
        Checks a single keyword against a list of domains.
        This method is designed to be run in a separate process.
        """
        if result_buffer is None:
            # If no buffer provided (e.g. testing), create a dummy stringIO
            # But normally the caller (worker) provides one to capture output.
            result_buffer = io.StringIO()

        result_domains = []
        domain_total_lines = len(domains_list)
        
        # Progress logic moved to caller or handled simply here
        # We don't want to print progress from worker easily unless we pass total lines context
        
        for i, domains in enumerate(domains_list):
            domain_part = domains.split(".")[0].replace("\n", "").lower()
            original_domain_line = domains.replace("\n", "") # The full line from file

            # Progress check (optional, if needed inside worker)
            if i > 0 and i % 50000 == 0 and domain_total_lines > 0:
                 progress = round(((i * 100) / domain_total_lines), 1)
                 print(f">> Progress: {progress} %", file=result_buffer)

            homograph_domain = homograph.check_homograph(domain_part)
            if homograph_domain:
                domain_part = homograph.homograph_to_latin(domain_part)

            if self.doppelganger_only:
                self._process_doppelganger(keyword, domain_part, original_domain_line, result_buffer, result_domains)
                continue

            if self.method == "levenshtein":
                self._process_levenshtein(keyword, domain_part, homograph_domain, original_domain_line, result_buffer, result_domains)
            elif self.method == "jarowinkler":
                self._process_jarowinkler(keyword, domain_part, homograph_domain, original_domain_line, result_buffer, result_domains)
            else:
                # Default fallback
                self._process_levenshtein(keyword, domain_part, homograph_domain, original_domain_line, result_buffer, result_domains)

        return result_domains

    def _domain_contains(self, keyword, domain):
         return keyword in domain

    def _process_levenshtein(self, keyword, domain, homograph_domain, original_domain, result_buffer, result_domains):
        leven_dist = validations.levenshtein(keyword, domain)

        if (leven_dist <= self.confidence_level) and not homograph_domain:
            self._on_similarity(keyword, original_domain, self.confidence.get(leven_dist, "unknown"), result_buffer, result_domains)
            if self.dns_validator: self.dns_validator.check_domain(original_domain, result_buffer)

        elif (leven_dist <= self.confidence_level) and homograph_domain:
            self._on_homograph(keyword, original_domain, self.confidence.get(leven_dist, "unknown"), result_buffer, result_domains)
            if self.dns_validator: self.dns_validator.check_domain(original_domain, result_buffer)
            
        elif self._domain_contains(keyword, original_domain):
            self._on_contains(keyword, original_domain, result_buffer, result_domains)
            if self.dns_validator: self.dns_validator.check_domain(original_domain, result_buffer)

    def _process_jarowinkler(self, keyword, domain, homograph_domain, original_domain, result_buffer, result_domains):
        similarity = validations.jaro_winkler(keyword, domain)
        keys = list(self.jaro_winkler.keys())
        values = list(self.jaro_winkler.values())
        triggered_values = values[1:] 
        insertion_point = bisect.bisect_left(keys, similarity)

        if insertion_point == len(keys):
            insertion_point -= 1

        value = values[insertion_point]
        if value in triggered_values and not homograph_domain:
            self._on_similarity(keyword, original_domain, value, result_buffer, result_domains)

        elif value in triggered_values and homograph_domain:
             self._on_homograph(keyword, original_domain, value, result_buffer, result_domains)

        elif self._domain_contains(keyword, original_domain):
            self._on_contains(keyword, original_domain, result_buffer, result_domains)

    def _process_doppelganger(self, keyword, domain, original_domain, result_buffer, result_domains):
        if self._domain_contains(keyword, domain):
             # Simplified doppelganger check embedded here primarily relies on reachability which requires network
             # Network calls inside parallel workers might be slow.
             # Original code did requests.get inside the worker.
             # We will keep it but it might be better to move network I/O out if possible?
             # For now, replicating original logic.
             try:
                 response = requests.get(f"https://{original_domain}", timeout=5)
                 print(Fore.GREEN + f"[+] https://{original_domain}/: Site reachable ({response.status_code})" + Style.RESET_ALL, file=result_buffer)
                 
                 if keyword in response.text:
                     print(Style.BRIGHT + Fore.RED + f"[+] Site contains {keyword} ! between {keyword} and {original_domain}" + Style.RESET_ALL, file=result_buffer)
                 
                 if not ct.CRTSH.check_certificate(original_domain):
                     print(Style.BRIGHT + Fore.RED + f"[+] suspicious certificate detected between {keyword} and {original_domain}" + Style.RESET_ALL, file=result_buffer)
                 else:
                     print(Style.BRIGHT + Fore.RED + f"[+] valid certificate between {keyword} and {original_domain}" + Style.RESET_ALL, file=result_buffer)

                 result_domains.append(original_domain)
             except Exception as e:
                 print(Fore.YELLOW + f"[*] {original_domain} Not reachable: {e}" + Style.RESET_ALL, file=result_buffer)

    def _on_similarity(self, keyword, domain, value, result_buffer, result_domains):
        print(
            Style.BRIGHT + Fore.RED + f"[+] Similarity detected between {keyword} and {domain} ({value})" + Style.RESET_ALL,
            file=result_buffer
        )
        result_domains.append(domain)

    def _on_homograph(self, keyword, domain, value, result_buffer, result_domains):
        print(
            Style.BRIGHT + Fore.RED + f"[+] Homograph detected between {keyword} and {domain} ({value})" + Style.RESET_ALL,
            file=result_buffer
        )
        result_domains.append(domain)

    def _on_contains(self, keyword, domain, result_buffer, result_domains):
        print(Fore.YELLOW + f"[+] Found {domain} " + Style.RESET_ALL, file=result_buffer)
        result_domains.append(domain)
