# -*- coding: utf-8 -*-
# Module: ct.py
"""openSquat

(c) CERT-MZ

* https://www.cert.mz
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
    """Class responsible for checking given domain for CT logs"""

    URL = "https://crt.sh/"

    @classmethod
    def check_certificate(cls, domain: str) -> bool:
        url = f"{cls.URL}?q={domain}"

        try:
            html_text = requests.get(url).text
        except Exception as e:
            print("Cannot fetch data from {url}")
            return True

        soup = BeautifulSoup(html_text, "html.parser")

        collected_logs = []
        for table in soup.find_all("table")[1]:
            if isinstance(table, NavigableString):
                continue

            for table_row in table.find_all("tr")[1:]:
                tds = [td for td in table_row.find_all("td")]
                try:
                    collected_logs.append(
                        CTLog(
                            tds[0].text,
                            tds[1].text,
                            tds[2].text,
                            tds[3].text,
                            [x for x in tds[4] if isinstance(x, NavigableString)],
                            tds[5].text,
                        )
                    )
                except Exception as e:
                    print(f"Could not retreive CT logs from {domain}, {e}")
                    return False

        for ca in NOT_TRUSTED_CA:
            for ctlog in collected_logs:
                if domain in ctlog.matching_ident:  # checking domain matching
                    if ca in ctlog.issuer_name:  # checking CA
                        return False

        if not collected_logs:
            return False

        return True
