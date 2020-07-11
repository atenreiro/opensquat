# -*- coding: utf-8 -*-
# main.py
"""
openSquat

(c) CERT-MZ

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import time

from colorama import init, Fore, Style
from opensquat import __VERSION__
from opensquat import arg_parser, output, app

if __name__ == "__main__":

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
        Fore.GREEN
        + """
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
                    (c) CERT-MZ
    """
        + Style.RESET_ALL
    )

    print(logo)
    print("\t\t\t" + __VERSION__ + "\n")

    args = arg_parser.get_args()
    
    print("Args:", args)

    boink = "quad9"
    
    start_time = time.time()
    file_content = app.Domain().main(
        args.keywords,
        args.confidence,
        args.domains,
        args.period,
        args.method,
        args.dns_validation,
        args.doppelganger_only,
    )

    print("")
    print("+---------- Summary ----------+")
    output.SaveFile().main(args.output, args.type, file_content)

    end_time = round(time.time() - start_time, 2)

    print("[*] Domains flagged:", len(file_content))
    print("[*] Running time: %s seconds" % end_time)
    print("")
