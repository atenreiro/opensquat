# -*- coding: utf-8 -*-
# Module: ct.py
"""
openSquat.

(c) Andre Tenreiro

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import requests
from bs4 import BeautifulSoup, NavigableString

NOT_TRUSTED_CA = ["Let's Encrypt Authority X3"]


class CTLog:
    def __init__(
        self, _id, logget_at, not_before, not_after, matching_ident, issuer_name
    ):
        self._id = _id
        self.logget_at = logget_at
        self.not_before = not_before
        self.not_after = not_after
        self.matching_ident = matching_ident
        self.issuer_name = issuer_name


class CRTSH:
    """Class responsible for checking given domain for CT logs."""

    URL = "https://crt.sh/"

    # Column layout of a crt.sh result row. The header has an extra leading
    # "Certificates" grouping cell, so header index != data index — these are
    # the <td> offsets of a DATA row, which is what we parse:
    #   0 crt.sh ID | 1 Logged At | 2 Not Before | 3 Not After
    #   4 Common Name | 5 Matching Identities | 6 Issuer Name
    COL_ID = 0
    COL_LOGGED_AT = 1
    COL_NOT_BEFORE = 2
    COL_NOT_AFTER = 3
    COL_MATCHING_IDENT = 5
    COL_ISSUER = 6
    MIN_COLUMNS = 7

    @classmethod
    def check_certificate(cls, domain: str):
        """
        Look up a domain's Certificate Transparency logs on crt.sh.

        Tri-state on purpose — a boolean cannot distinguish "no certificates
        exist" (a real signal) from "we could not find out" (no signal at
        all). Collapsing those two caused crt.sh outages to be reported as
        suspicious certificates, and unreachable hosts to be reported as
        valid ones.

        Return:
            True  - CT logs found for the domain
            False - crt.sh answered and has no CT logs for the domain
            None  - indeterminate: crt.sh unreachable, non-200, or a
                    response we could not parse. Callers must NOT treat
                    this as evidence in either direction.
        """
        url = f"{cls.URL}?q={domain}"

        try:
            response = requests.get(url, timeout=10)
        except Exception as e:
            print(f"[!] CT lookup failed for {domain}: {e}")
            return None

        # crt.sh serves 502/503 error pages as HTML. Parsing one yields no
        # results table, which would otherwise be indistinguishable from a
        # genuine "no certificates found" answer.
        if response.status_code != 200:
            print(
                f"[!] CT lookup unavailable for {domain}: "
                f"crt.sh returned HTTP {response.status_code}"
            )
            return None

        soup = BeautifulSoup(response.text, "html.parser")

        # Results live in the SECOND table (the first is the page header).
        # Fewer than two tables means crt.sh rendered its "None found" page:
        # a real answer, so False rather than None.
        tables = soup.find_all("table")
        if len(tables) < 2:
            return False

        collected_logs = []
        for table in tables[1]:
            if isinstance(table, NavigableString):
                continue

            for table_row in table.find_all("tr")[1:]:
                tds = table_row.find_all("td")
                if len(tds) < cls.MIN_COLUMNS:
                    # Layout drift, or a spacer/summary row. Skip it rather
                    # than aborting the whole lookup on one odd row.
                    continue
                collected_logs.append(
                    CTLog(
                        tds[cls.COL_ID].text,
                        tds[cls.COL_LOGGED_AT].text,
                        tds[cls.COL_NOT_BEFORE].text,
                        tds[cls.COL_NOT_AFTER].text,
                        [
                            x for x in tds[cls.COL_MATCHING_IDENT]
                            if isinstance(x, NavigableString)
                        ],
                        tds[cls.COL_ISSUER].text,
                    )
                )

        for ca in NOT_TRUSTED_CA:
            for ctlog in collected_logs:
                if domain in ctlog.matching_ident:  # checking domain matching
                    if ca in ctlog.issuer_name:  # checking CA
                        return False

        if not collected_logs:
            return False

        return True
