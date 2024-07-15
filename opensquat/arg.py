#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# arg.py
"""
openSquat.

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import argparse

def validate_period(search_period):
    """
    Validate period.

    Args:
        search_period (int): Integer representing the searchable period.

    Returns:
        int: Validated period, capped at 7.

    Raises:
        argparse.ArgumentTypeError: If the period is not within the valid range.
    """
    try:
        period = int(search_period)
    except ValueError:
        raise argparse.ArgumentTypeError("The period must be an integer.")

    if period < 1:
        raise argparse.ArgumentTypeError("The period (days) must be at least 1.")
    if period > 7:
        period = 7

    return period


def validate_type(file_type):
    """
    Validate file_type.

    Args:
        file_type: string containing file type, can only be txt, json or csv.

    Return:
        file_type

    Raise:
        If value is not valid, raise an exception to argparse
    """
    valid_types = {"txt", "json", "csv"}
    if file_type not in valid_types:
        raise argparse.ArgumentTypeError(f"Unknown file format: {file_type}")
    return file_type


def get_args():
    """
    Parser main function.

    Args:
        none

    Return:
        args: returns arguments
    """
    parser = argparse.ArgumentParser(description="openSquat")
    parser.add_argument(
        "-k",
        "--keywords",
        type=str,
        default="keywords.txt",
        help="keywords file (default: keywords.txt)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="domains.json",
        help="output filename (default: domains.json)",
    )
    parser.add_argument(
        "-t",
        "--filetype",
        type=validate_type,
        default="json",
        help="output file type [txt|json|csv] (default: json)",
    )
    parser.add_argument(
        "-p",
        "--period",
        type=validate_period,
        default=1,
        help="Searchable last days (default: 1)",
    )

    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default="opensquat.conf",
        help="Config file (default: opensquat.conf)",
    )

    parser.add_argument(
        "--ct",
        action="store_true",
        help="search in certificate transparency",
    )
    parser.add_argument(
        "--dns",
        action="store_true",
        help="Check if domain is flagged by Quad9 DNS",
    )
    parser.add_argument(
        "-x",
        "--openport",
        action="store_true",
        help="Verify if port 80/443 are open",
    )
    parser.add_argument(
        "--vt",
        action="store_true",
        help="validate against VirusTotal",
    )
    parser.add_argument(
        "--mx",
        action="store_true",
        help="validate if domain contains a MX record",
    )
    parser.add_argument(
        "--spf",
        action="store_true",
        help="validate if domain contains a SPF record",
    )

    return parser.parse_args()
