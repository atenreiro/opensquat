# -*- coding: utf-8 -*-
# Module: file_input.py
"""
openSquat.

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import os
import sys


def keywords_count(keywords_file):
    """
    Count the number of keywords from the keyword file.
    The counter will ignore the chars "#", "\n", and " ".

    Args:
        keywords_file (str): Path to the keywords file.

    Returns:
        int: The number of valid keywords.
    """
    if not os.path.isfile(keywords_file):
        print(f"[*] File {keywords_file} not found or not readable! Exiting...")
        sys.exit(-1)

    keywords_total = 0
    with open(keywords_file, mode='r', encoding='utf-8') as fd_input:
        for line in fd_input:
            line = line.strip()
            if line and line[0] not in "# ":
                keywords_total += 1

    return keywords_total


def keywords_read(keywords_file):
    """
    Method to read domain files.

    Args:
        keywords_file (str): Path to the keywords file.

    Returns:
        list: List of valid keywords.
    """
    if not os.path.isfile(keywords_file):
        print(f"[*] File {keywords_file} not found or not readable! Exiting...")
        sys.exit(-1)

    keywords_list_aux = []

    with open(keywords_file, mode='r', encoding='utf-8') as fp:
        for line in fp:
            line = line.strip()
            if line and line[0] not in "# ":
                keywords_list_aux.append(line)

    return keywords_list_aux
