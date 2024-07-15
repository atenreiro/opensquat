# -*- coding: utf-8 -*-
# Module: messages.py
"""
openSquat.

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
from colorama import init, Fore, Style

def cli_print_error(message):
    print(
        Style.BRIGHT + Fore.RED + "[ERROR] " + message +
        Style.RESET_ALL
    )
    return True

def cli_print_info(message):
    print(
        Style.BRIGHT + Fore.WHITE + "[INFO] " + message +
        Style.RESET_ALL
    )
    return True