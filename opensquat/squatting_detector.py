# -*- coding: utf-8 -*-
# Module: squatting_detector.py
"""
SquattingDetector module for openSquat.
Handles the core logic for detecting squatting domains.
Designed to be lightweight for parallel execution.
"""
import io
import requests
from colorama import Fore, Style
from opensquat import validations, homograph, ct


class SquattingDetector:
    def __init__(self, confidence_level=2, doppelganger_only=False, dns_validator=None):
        self.confidence_level = confidence_level
        self.doppelganger_only = doppelganger_only
        self.dns_validator = dns_validator

        self.confidence = {
            0: "very high confidence",
            1: "high confidence",
            2: "medium confidence",
            3: "low confidence",
            4: "very low confidence",
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

        for i, domain_line in enumerate(domains_list):
            domain_part = domain_line.split(".")[0].lower()
            original_domain = domain_line

            # Progress check (optional, if needed inside worker)
            if i > 0 and i % 50000 == 0 and domain_total_lines > 0:
                progress = round(((i * 100) / domain_total_lines), 1)
                print(f">> Progress: {progress} %", file=result_buffer)

            # Homograph normalisation. NRD feeds publish IDNs in punycode
            # ("xn--..."), so those must be decoded before folding; raw
            # unicode (e.g. from a -d file) is folded directly. In both
            # cases fold_to_latin() is the gate: it returns None for
            # labels that are not Latin-lookalike (CJK, Hangul, accented
            # Latin), which is what keeps false positives out.
            homograph_domain = False
            unicode_form = None
            if domain_part.startswith("xn--"):
                decoded = homograph.decode_punycode(domain_part)
                if decoded:
                    folded = homograph.fold_to_latin(decoded)
                    if folded:
                        if folded != decoded:
                            homograph_domain = True
                            # Full-domain unicode rendering for display,
                            # e.g. "xn--mirosoft-hw7c.com" -> "miᴄrosoft.com"
                            unicode_form = ".".join(
                                [decoded] + original_domain.split(".")[1:]
                            )
                        domain_part = folded
            elif not domain_part.isascii():
                folded = homograph.fold_to_latin(domain_part)
                if folded and folded != domain_part:
                    homograph_domain = True
                    domain_part = folded

            if self.doppelganger_only:
                self._process_doppelganger(
                    keyword, domain_part, original_domain, result_buffer, result_domains
                )
                continue

            self._process_levenshtein(
                keyword, domain_part, homograph_domain, original_domain, result_buffer, result_domains,
                unicode_form=unicode_form
            )

        return result_domains

    def _domain_contains(self, keyword, domain):
        return keyword in domain

    def _process_levenshtein(self, keyword, domain, homograph_domain, original_domain, result_buffer, result_domains,
                             unicode_form=None):
        leven_dist = validations.levenshtein(keyword, domain, self.confidence_level)

        if (leven_dist <= self.confidence_level) and not homograph_domain:
            self._on_similarity(
                keyword, original_domain, self.confidence.get(leven_dist, "unknown"), result_buffer, result_domains
            )
            if self.dns_validator:
                self.dns_validator.check_domain(original_domain, result_buffer)

        elif (leven_dist <= self.confidence_level) and homograph_domain:
            self._on_homograph(
                keyword, original_domain, self.confidence.get(leven_dist, "unknown"), result_buffer, result_domains,
                unicode_form=unicode_form
            )
            if self.dns_validator:
                self.dns_validator.check_domain(original_domain, result_buffer)

        elif self._domain_contains(keyword, original_domain):
            self._on_contains(keyword, original_domain, result_buffer, result_domains)
            if self.dns_validator:
                self.dns_validator.check_domain(original_domain, result_buffer)

    def _process_doppelganger(self, keyword, domain, original_domain, result_buffer, result_domains):
        if self._domain_contains(keyword, domain):
            try:
                response = requests.get(f"https://{original_domain}", timeout=5)
                print(
                    Fore.GREEN + f"[+] https://{original_domain}/: Site reachable ({response.status_code})" +
                    Style.RESET_ALL,
                    file=result_buffer
                )

                if keyword in response.text:
                    print(
                        Style.BRIGHT + Fore.RED +
                        f"[+] Site contains {keyword} ! between {keyword} and {original_domain}" +
                        Style.RESET_ALL,
                        file=result_buffer
                    )

                # Tri-state: None means crt.sh could not answer, which is
                # not evidence either way. Reporting it as "valid" (the old
                # behaviour on network errors) hid real suspicious domains.
                ct_status = ct.CRTSH.check_certificate(original_domain)
                if ct_status is None:
                    print(
                        Fore.YELLOW +
                        f"[!] CT check unavailable for {original_domain} "
                        "(crt.sh error) - no certificate verdict" +
                        Style.RESET_ALL,
                        file=result_buffer
                    )
                elif not ct_status:
                    print(
                        Style.BRIGHT + Fore.RED +
                        f"[+] suspicious certificate detected between {keyword} and {original_domain}" +
                        Style.RESET_ALL,
                        file=result_buffer
                    )
                else:
                    print(
                        Style.BRIGHT + Fore.RED +
                        f"[+] valid certificate between {keyword} and {original_domain}" +
                        Style.RESET_ALL,
                        file=result_buffer
                    )

                result_domains.append(original_domain)
            except Exception as e:
                print(Fore.YELLOW + f"[*] {original_domain} Not reachable: {e}" + Style.RESET_ALL, file=result_buffer)

    def _on_similarity(self, keyword, domain, value, result_buffer, result_domains):
        print(
            Style.BRIGHT + Fore.RED + f"[+] Similarity detected between {keyword} and {domain} ({value})" + Style.RESET_ALL,
            file=result_buffer
        )
        result_domains.append(domain)

    def _on_homograph(self, keyword, domain, value, result_buffer, result_domains, unicode_form=None):
        # For punycode homographs, show the unicode rendering so the
        # operator can see the actual characters being impersonated —
        # a bare "xn--..." string gives no hint of why it matched.
        # The clean feed string (domain) is what goes into results.
        shown = f"{domain} ({unicode_form})" if unicode_form else domain
        print(
            Style.BRIGHT + Fore.RED + f"[+] Homograph detected between {keyword} and {shown} ({value})" + Style.RESET_ALL,
            file=result_buffer
        )
        result_domains.append(domain)

    def _on_contains(self, keyword, domain, result_buffer, result_domains):
        print(Fore.YELLOW + f"[+] Found {domain} " + Style.RESET_ALL, file=result_buffer)
        result_domains.append(domain)
