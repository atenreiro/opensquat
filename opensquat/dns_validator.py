# -*- coding: utf-8 -*-
# Module: dns_validator.py
"""
DNSValidator module for openSquat.
Handles DNS reputation checks and validation.
"""
from colorama import Fore, Style
from opensquat import dns_resolvers

class DNSValidator:
    def __init__(self, use_dns=False):
        self.use_dns = use_dns
        self.malicious_domains = []

    def check_domain(self, domain, result_buffer=None):
        """
        Check the domain reputation using DNS resolvers (Quad9).
        Prints results (or writes to buffer) and updates malicious list.
        """
        if not self.use_dns:
            return

        dns_resp = dns_resolvers.Quad9().main(domain)

        # Check response based on DNS rcodes
        if dns_resp == "non-malicious":
            self._print_result(Fore.GREEN + "  \\_ Domain Reputation: Non-malicious\n", result_buffer)
        elif dns_resp == "malicious":
            self._print_result(Style.BRIGHT + Fore.RED + "  \\_ Domain Reputation: Malicious\n", result_buffer)
            self.malicious_domains.append(domain)
        elif dns_resp == "Timeout":
            self._print_result(Fore.YELLOW + "  \\_ DNS Server error: Possible Provider throttling\n", result_buffer)
        elif dns_resp == "NXDOMAIN":
            self._print_result(Fore.YELLOW + "  \\_ DNS response: Non-Existent Domain\n", result_buffer)
        elif dns_resp == "NoNameservers":
            self._print_result(Fore.YELLOW + "  \\_ DNS Server error: No Name Servers (SRVFAIL)\n", result_buffer)
        elif dns_resp == "NoAnswer":
             self._print_result(Fore.YELLOW + "  \\_ DNS Server error: No Answer\n", result_buffer)
        else:
            self._print_result(Fore.YELLOW + f"  \\_ DNS response: {dns_resp}\n", result_buffer)

    def _print_result(self, message, result_buffer):
        """Helper to print to buffer or stdout (with reset style)"""
        if result_buffer:
            print(message + Style.RESET_ALL, file=result_buffer)
        else:
            print(message + Style.RESET_ALL)
