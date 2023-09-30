#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# opensquat.py
"""
openSquat.

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""

# Import the SQLite library
import sqlite3  # Add this line

conn = sqlite3.connect("opensquat.db")
cursor = conn.cursor()

create_table_sql = """
CREATE TABLE IF NOT EXISTS hijacked_urls (
    id INTEGER PRIMARY KEY,
    original_url TEXT,
    hijacked_url TEXT
);
"""
cursor.execute(create_table_sql)

import time
import signal
import functools
import concurrent.futures

#Imported libraries for URL hijacking
import re
#import sys
import argparse

from colorama import init, Fore, Style
from opensquat import __VERSION__, vt
from opensquat import arg_parser, output, app, phishing, check_update
from opensquat import port_check

# Changes for URL hijacking
from urllib.parse import urlparse


#Function Definition for URL Hijacking
def is_url_hijacked(url, original_domain):
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in ["http", "https"]:
            return True
        if original_domain not in parsed_url.netloc:
            return True
        lookalike_pattern = re.compile(r'(\w+\.)+' + re.escape(original_domain))
        if not lookalike_pattern.match(parsed_url.netloc):
            return True
        # Customize the list of suspicious keywords
        suspicious_keywords = ["admin", "login", "account", "signin"]
        for keyword in suspicious_keywords:
            if keyword in parsed_url.path.lower():
                return True
        return False
    except ValueError:
        return True

def signal_handler(sig, frame):
    """Function to catch CTR+C and terminate."""
    print("\n[*] openSquat is terminating...\n")
    exit(0)

if __name__ == "__main__":

    original_url = "https://example.com"  # Replace with your original URL

    signal.signal(signal.SIGINT, signal_handler)

    init()

    RED, WHITE, GREEN, END, YELLOW, BOLD = (
        "\033[91m",
        "\33[97m",
        "\033[1;32m",
        "\033[0m",
        "\33[93m",
        "\033[1m",
    )

    logo = (
        Style.BRIGHT + Fore.GREEN +
        """
                                             █████████                                  █████
                                            ███░░░░░███                                ░░███
      ██████  ████████   ██████  ████████  ░███    ░░░   ████████ █████ ████  ██████   ███████
     ███░░███░░███░░███ ███░░███░░███░░███ ░░█████████  ███░░███ ░░███ ░███  ░░░░░███ ░░░███░
    ░███ ░███ ░███ ░███░███████  ░███ ░███  ░░░░░░░░███░███ ░███  ░███ ░███   ███████   ░███
    ░███ ░███ ░███ ░███░███░░░   ░███ ░███  ███    ░███░███ ░███  ░███ ░███  ███░░███   ░███ ███
    ░░██████  ░███████ ░░██████  ████ █████░░█████████ ░░███████  ░░████████░░████████  ░░█████
     ░░░░░░   ░███░░░   ░░░░░░  ░░░░ ░░░░░  ░░░░░░░░░   ░░░░░███   ░░░░░░░░  ░░░░░░░░    ░░░░░
              ░███                                          ░███
              █████                                         █████
             ░░░░░                                         ░░░░░
                    (c) Andre Tenreiro - https://github.com/atenreiro/opensquat
    """ + Style.RESET_ALL
    )

    print(logo)
    print("\t\t\tversion " + __VERSION__ + "\n")

    #Changes for URL Hijacking --2

    # Command-line argument for the original URL
    parser = argparse.ArgumentParser()
    parser.add_argument("--urlhijack", help="Original URL for URL hijacking detection")
    args = parser.parse_args()

    # Code 1: URL hijacking detection integrated into Code 2
    original_url = "https://facebook.com"  # Replace with your original URL
    test_urls = [
        #"https://example.com",
        #"https://example.com/login",
        "https://example.org",  # Different domain
        "https://facebo0kk.com",   # Look-alike domain
        #"https://example.com?phishing=true",
        "https://example.com",
        #"https://example.com/login"

    ]

    for url in test_urls:
        if url == original_url:
            print(f"Skipping identical URL: {url}")
        elif is_url_hijacked(url, urlparse(original_url).netloc):
            print(f"Potentially hijacked URL: {url}")
             
            conn = sqlite3.connect("opensquat.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO hijacked_urls (original_url, hijacked_url) VALUES (?, ?)", (original_url, url))
            conn.commit()
            conn.close()
        else:
            print(f"Valid URL: {url}")


    args = arg_parser.get_args()

    start_time_squatting = time.time()

    file_content = app.Domain().main(
        args.keywords,
        args.confidence,
        args.domains,
        args.period,
        args.method,
        args.dns,
        args.ct
    )

    if args.subdomains or args.vt or args.subdomains or args.phishing \
        or args.portcheck:
        print("\n[*] Total found:", len(file_content))


    #Check for URL hijacking
    if args.urlhijack:
        print("\n+---------- Checking for URL Hijacking ----------+")
        time.sleep(1)
        list_aux = []
        original_url = args.urlhijack
        original_domain = urlparse(original_url).netloc
        for domain in file_content:
            if is_url_hijacked(domain, original_domain):
                print(
                    Style.BRIGHT + Fore.RED +
                    "[*] Potential URL Hijacking:", domain +
                    Style.RESET_ALL,
                )
                list_aux.append(domain)
        file_content = list_aux

    # Check for subdomains
    if (args.subdomains):
        list_aux = []
        print("\n+---------- Checking for Subdomains ----------+")
        time.sleep(1)
        for domain in file_content:
            print("[*]", domain)
            subdomains = vt.VirusTotal().main(domain, "subdomains")

            if subdomains:
                for subdomain in subdomains:
                    print(
                        Style.BRIGHT + Fore.YELLOW +
                        " \\_", subdomain +
                        Style.RESET_ALL,
                        )
                    list_aux.append(subdomain)
        file_content = list_aux
        print("[*] Total found:", len(file_content))

    # Check for VirusTotal (if domain is flagged as malicious)
    if (args.vt):
        list_aux = []
        print("\n+---------- VirusTotal ----------+")
        time.sleep(1)
        for domain in file_content:
            total_votes = vt.VirusTotal().main(domain)

            # total votes
            harmless = total_votes[0]
            malicious = total_votes[1]

            if malicious > 0:
                print(
                    Style.BRIGHT + Fore.RED +
                    "[*] found:", domain, "({})".format(str(malicious)) +
                    Style.RESET_ALL,
                    )
                list_aux.append(domain)
            elif malicious < 0:
                print(
                    Style.BRIGHT + Fore.YELLOW +
                    "[*] VT is throttling the response:", domain +
                    Style.RESET_ALL,
                    )
                list_aux.append(domain)
        file_content = list_aux
        print("[*] Total found:", len(file_content))

    # Check for phishing
    if (args.phishing != ""):
        file_phishing = phishing.Phishing().main(args.keywords)
        output.SaveFile().main(args.phishing, "txt", file_phishing)

    # Check if domain has webserver port opened
    if (args.portcheck):
        list_aux = []
        print("\n+---------- Domains with open webserver ports ----------+")
        time.sleep(1)
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futs = [ (domain, executor.submit(functools.partial(port_check.PortCheck().main, domain)))
                for domain in file_content ]
        
        for tested_domain, result_domain_port_check in futs:
            ports = result_domain_port_check.result()
            if ports:
                list_aux.append(tested_domain)
                print(
                    Fore.YELLOW +
                    "[*]", tested_domain, ports, "" +
                    Style.RESET_ALL
                    )
        
        file_content = list_aux
        print("[*] Total found:", len(file_content))

    output.SaveFile().main(args.output, args.type, file_content)
    end_time_squatting = round(time.time() - start_time_squatting, 2)

    # Print summary
    print("\n")
    print(
        Style.BRIGHT+Fore.GREEN +
        "+---------- Summary Squatting ----------+" +
        Style.RESET_ALL)

    print("[*] Domains flagged:", len(file_content))
    print("[*] Domains result:", args.output)

    if (args.phishing != ""):
        print("[*] Phishing results:", args.phishing)
        print("[*] Active Phishing sites:", len(file_phishing))

    print("[*] Running time: %s seconds" % end_time_squatting)
    print("")

    check_update.CheckUpdate().main()
