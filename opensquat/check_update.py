# -*- coding: utf-8 -*-
# Module: check_update.py
"""
openSquat

(c) CERT-MZ

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import requests
import random
from colorama import Fore, Style
from opensquat import __VERSION__


class CheckUpdate:
    """
    This domain class verifies if there is a newer upgrade avaiable

    To use:
        CheckUpdate.main()

    Attribute:
        URL: The URL with the latest upgrade version
        current: The current running version
    """

    def __init__(self):
        """Initiator."""
        self.URL = ("https://feeds.opensquat.com/latest.txt")
        self.current = __VERSION__

    def check(self):

        # User-Agent
        ver = "openSquat " + self.current
        headers = {'User-Agent': ver}

        try:
            response = requests.get(self.URL, headers=headers)
        except requests.exceptions.RequestException:
            return False

        if (response.status_code != 200):
            return False

        latest_ver = float(response.content)
        response.close()

        current_ver = float(self.current)

        if current_ver < latest_ver:
            print(
                Style.BRIGHT+Fore.MAGENTA +
                "[INFO] New version avaiable!" +
                Style.RESET_ALL)
            print(
                Style.BRIGHT+Fore.WHITE +
                "-> Current ver:", current_ver, Style.RESET_ALL)
            print(
                Style.BRIGHT+Fore.WHITE +
                "-> Latest ver:", latest_ver, Style.RESET_ALL)
            print(
                Style.BRIGHT+Fore.WHITE +
                "-> Changelog: https://github.com/atenreiro/opensquat/blob/" +
                "master/CHANGELOG" +
                Style.RESET_ALL)
            print(
                Style.BRIGHT+Fore.WHITE + "-> update now: $ git pull\n" +
                Style.RESET_ALL)

        return True

    def main(self):

        # I don't want to nag people about upgrades all times.
        rand = random.randint(1, 3)

        if rand == 1:
            self.check()
