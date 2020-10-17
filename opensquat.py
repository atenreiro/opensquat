# -*- coding: utf-8 -*-
# opensquat.py
"""
openSquat.

(c) CERT-MZ

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import time
import signal

from colorama import init, Fore, Style
from opensquat import __VERSION__
from opensquat import arg_parser, output, app, phishing, check_update, vt
from opensquat import port_check


def signal_handler(sig, frame):
    """Function to catch CTR+C and terminate."""
    print("\n[*] openSquat is terminating...\n")
    exit(0)

if __name__ == "__main__":

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
                    (c) CERT-MZ - https://github.com/atenreiro/opensquat
    """ + Style.RESET_ALL
    )

    print(logo)
    print("\t\t\tversion " + __VERSION__ + "\n")

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
        or args.portscheck:
        print("\n[*] Total found:", len(file_content))

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
                        " \_", subdomain +
                        Style.RESET_ALL,
                        )
                    list_aux.append(subdomain)
        file_content = list_aux
        print("[*] Total found:", len(file_content))

    # Check for VirusTotal
    if (args.vt):
        list_aux = []
        print("\n+---------- VirusTotal ----------+")
        time.sleep(1)
        for domain in file_content:
            malicious = vt.VirusTotal().main(domain, "malicious")

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

        for domain in file_content:
            ports = port_check.PortCheck().main(domain)

            if ports:
                list_aux.append(domain)
                print(
                    Fore.YELLOW +
                    "[*]", domain, ports, "" +
                    Style.RESET_ALL,
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
