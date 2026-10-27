# -*- coding: utf-8 -*-
# Module: phishing.py
"""
openSquat

(c) Andre Tenreiro

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import os
import re
import sys
import tempfile
import time
from urllib.parse import urlparse

import requests
from opensquat import file_input

from colorama import Fore, Style

# Phishing lists come from third parties and are untrusted input. These
# limits keep a compromised or misbehaving source from exhausting memory
# or disk, or from smuggling anything but hostnames/URLs into the local DB.
MAX_DB_BYTES = 256 * 1024 * 1024
MAX_LINE_LENGTH = 2048
CHUNK_SIZE = 64 * 1024
# Minimum share of non-comment lines that must look like a host or URL.
# Below this the source is treated as broken (HTML page, wrong dataset...).
MIN_VALID_RATIO = 0.5
# Content types that can never be a plain-text list.
REJECTED_CONTENT_TYPES = ("html", "xml", "json")

# One entry per line: a hostname (optionally with a port) or an http(s)
# URL. Strict allow-list of characters: no whitespace, control characters,
# quotes or backslashes can pass. Matched against the lowercased line.
LINE_RE = re.compile(
    r"(?:https?://)?[a-z0-9][a-z0-9_.-]*"
    r"(?::[0-9]{1,5})?"
    r"(?:[/?#][a-z0-9._~:/?#@!$&()*+,;=%-]*)?"
)


def redact_url(url):
    """
    Return scheme://host[:port]/path without userinfo, query or fragment.

    A user-supplied list URL may carry credentials or an API token; only
    this form is ever printed or kept for display.
    """
    parsed = urlparse(str(url))
    host = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port:
        host = host + ":" + str(port)
    return parsed.scheme + "://" + host + parsed.path


class Phishing:

    """
    Class Phishing.

    To use:
        Phishing().main(keyword)

    Attribute:
        keyword: list of keywords
    """
    def __init__(self, fallback_db=None):
        self.phishing_db = "https://phish.co.za" \
                           "/latest/" \
                           "phishing-domains-ACTIVE.txt"
        # Optional second https list, tried only when the Phishing Database
        # cannot be downloaded. There is no default: it is chosen by the
        # user with --phishing-fallback.
        self.fallback_db = fallback_db
        # URL of the list that produced the local database in this run.
        self.source = None
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

    @staticmethod
    def sanitize_db(data):
        """
        Reduce a downloaded list to safe lines.

        Return (lines, rejected): the lowercased lines that look like a
        hostname or an http(s) URL, and how many non-comment lines were
        dropped. Bad bytes, control characters, ANSI escape sequences,
        spaces and over-long lines never pass, so they cannot reach the
        terminal, the output file or the matching code.
        """
        text = data.decode("utf-8", errors="replace")
        lines = []
        rejected = 0

        for raw in text.split("\n"):
            line = raw.strip().lower()
            if not line or line.startswith("#"):
                continue
            if len(line) > MAX_LINE_LENGTH or not LINE_RE.fullmatch(line):
                rejected += 1
                continue
            lines.append(line)

        return lines, rejected

    def download_db(self, url):
        """
        Download one phishing list.

        Return the raw body, or None when the source is not usable: not
        https, unreachable, not a 200, an HTML/XML/JSON page, empty or
        larger than MAX_DB_BYTES. A server that is down answers with an
        error page (phish.co.za returns a short 503 or 403 HTML page), and
        that page must not be saved as the database: every keyword would
        then silently match nothing.
        """
        print("[*] Downloading fresh Phishing DB from", redact_url(url))

        if urlparse(url).scheme != "https":
            print("[!] Phishing DB must be served over https:", redact_url(url))
            return None

        r = None
        try:
            # Timeout so a hung phishing DB server cannot freeze the CLI.
            r = requests.get(url, timeout=60, stream=True)

            if r.status_code != 200:
                print("[!] Phishing DB unavailable: HTTP", r.status_code)
                return None

            # No hop of a redirect chain may use plain http, even when the
            # chain ends on https: that hop could have been tampered with.
            hops = list(r.history) + [r]
            if any(urlparse(str(h.url)).scheme != "https" for h in hops):
                print("[!] Phishing DB redirected through a non-https URL")
                return None

            content_type = str(r.headers.get("content-type", "")).lower()
            if any(t in content_type for t in REJECTED_CONTENT_TYPES):
                # The header is server-controlled: never echo it.
                print("[!] Phishing DB is not a text list")
                return None

            try:
                declared = int(r.headers.get("content-length", 0))
            except (TypeError, ValueError):
                declared = 0
            if declared > MAX_DB_BYTES:
                print("[!] Phishing DB is too large:", declared, "bytes")
                return None

            body = bytearray()
            for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
                body.extend(chunk)
                if len(body) > MAX_DB_BYTES:
                    print("[!] Phishing DB is too large, aborting download")
                    return None
        except requests.exceptions.RequestException as e:
            print("[!] Phishing DB not reachable:", type(e).__name__)
            return None
        finally:
            if r is not None:
                r.close()

        if len(body) == 0:
            print("[!] Phishing DB is empty")
            return None

        return bytes(body)

    def fetch_list(self, url):
        """
        Download one list and return its sanitized lines, or None when the
        source is unusable.
        """
        data = self.download_db(url)
        if data is None:
            return None

        lines, rejected = self.sanitize_db(data)
        total = len(lines) + rejected

        if not lines or len(lines) / total < MIN_VALID_RATIO:
            print(
                "[!] Phishing DB rejected: only", len(lines), "of", total,
                "lines are valid hosts or URLs"
            )
            return None

        if rejected:
            print("[*] Ignored", rejected, "invalid lines from the list")

        return lines

    def save_db(self, lines):
        """
        Write the database atomically: a failed run never leaves a half
        written phishing.db, nor replaces the previous one.
        """
        target = os.path.abspath(self.phishing_filename)
        fd, tmp_path = tempfile.mkstemp(
            dir=os.path.dirname(target), prefix=".phishing.db."
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(lines) + "\n")
            os.replace(tmp_path, target)
        except BaseException:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def update_db(self):

        sources = [self.phishing_db]
        if self.fallback_db:
            sources.append(self.fallback_db)

        lines = None
        for url in sources:
            lines = self.fetch_list(url)
            if lines is not None:
                self.source = redact_url(url)
                break
            if url != sources[-1]:
                print("[*] Trying the fallback list")

        if lines is None:
            print(
                "[ERROR] No phishing list could be downloaded. " +
                "Try again later. Exiting...\n",
            )
            sys.exit(-1)

        print("[*] Phishing list source:", self.source)
        print("[*] Phishing entries:", len(lines))
        self.save_db(lines)

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
