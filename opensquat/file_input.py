# -*- coding: utf-8 -*-
# Module: file_input.py
"""
openSquat

(c) CERT-MZ

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import os


class InputFile:
    def __init__(self):
        """Initiator."""
        self.domain_filename = None
        self.keywords_filename = None
        self.domain_total = 0
        self.keywords_total = 0

    def set_domains_file(self, domains_file):
        self.domain_filename = domains_file

    def set_keywords_file(self, keywords_file):
        self.keywords_filename = keywords_file

    def count_domains(self):
        """
        Count number of domains (lines) from the domains file.

        Args:
            none

        Return:
            self.domain_total: total number of domains in the file
        """
        if not os.path.isfile(self.domain_filename):
            print(
                "[*] File",
                self.domain_filename,
                "not found or not readable! Exiting...\n",
            )
            exit(-1)

        for line in open(self.domain_filename):
            self.domain_total += 1

        return self.domain_total

    def count_keywords(self):
        """
        Count number of keywords from the keyword file
        the counter will ignore the chars "#", "\n" and " ".

        Args:
            none

        Return:
            none
        """
        if not os.path.isfile(self.keywords_filename):
            print(
                "[*] File",
                self.keywords_filename,
                "not found or not" "readable! Exiting... \n",
            )
            exit(-1)

        for line in open(self.keywords_filename):
            if (
                (line[0] != "#") and
                (line[0] != " ") and
                (line[0] != "") and
                (line[0] != "\n")
            ):
                self.keywords_total += 1

        return self.keywords_total

    def main(self, keywords_file, domains_file):
        self.set_keywords_file(keywords_file)
        count_keywords = self.count_keywords()

        if domains_file is not None:
            self.set_domains_file(domains_file)
            count_domains = self.count_domains()

        # return tuple
        if domains_file is None:
            return count_keywords
        else:
            return (count_keywords, count_domains)
