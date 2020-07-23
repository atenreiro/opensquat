# -*- coding: utf-8 -*-
# main.py
"""openSquat

(c) CERT-MZ

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import time
import signal

from colorama import init, Fore, Style
from opensquat import __VERSION__
from opensquat import arg_parser, output, app, phishing


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
    print("\t\t\t" + __VERSION__ + "\n")

    args = arg_parser.get_args()

    start_time_squatting = time.time()

    file_content = app.Domain().main(
        args.keywords,
        args.confidence,
        args.domains,
        args.period,
        args.method,
        args.dns,
        args.doppelganger_only,
    )

    end_time_squatting = round(time.time() - start_time_squatting, 2)

    if (args.phishing != ""):
        start_time_phishing = time.time()
        file_phishing = phishing.Phishing().main(args.keywords)
        end_time_phishing = round(time.time() - start_time_phishing, 2)

    # Print summary output for domain squatting
    print("\n")
    print("+---------- Summary Squatting ----------+")
    output.SaveFile().main(args.output, args.type, file_content)
    print("[*] Domains flagged:", len(file_content))
    print("[*] Running time: %s seconds" % end_time_squatting)
    print("")

    # Print summary output for domain squatting - if argument is set
    if (args.phishing != ""):
        print("+---------- Summary Phishing ----------+")
        output.SaveFile().main(args.phishing, "txt", file_phishing)
        print("[*] Sites flagged:", len(file_phishing))
        print("[*] Running time: %s seconds" % end_time_phishing)
        print("")
