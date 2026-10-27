# -*- coding: utf-8 -*-
# Module: arg_parser.py
"""
openSquat.

(c) Andre Tenreiro

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3

"""
import argparse
from urllib.parse import urlparse

from colorama import Fore, Style

from opensquat import auth


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
    file_type = str(file_type)

    if (file_type != "txt") and (file_type != "json") and (file_type != "csv"):
        raise argparse.ArgumentTypeError("File format unkown!")
    return file_type


def validate_https_url(url):
    """
    Validate a URL given on the command line.

    Args:
        url: string containing the URL, must be https with a host.

    Return:
        url

    Raise:
        If value is not valid, raise an exception to argparse
    """
    parsed = urlparse(str(url))

    if parsed.scheme != "https" or not parsed.hostname:
        raise argparse.ArgumentTypeError("URL must start with https://")
    return url


def validate_confidence(confidence_level):
    """
    Validate confidence_level.

    Args:
        confidence_level: int containing confidence_level, can only be an int
        between 0 and 4.

    Return:
        confidence_level

    Raise:
        If value is not valid, raise an exception to argparse

    """
    confidence_level = int(confidence_level)

    if confidence_level not in range(0, 5):
        raise argparse.ArgumentTypeError("confidence must be between 0 and 4")
    return confidence_level


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
        default="results.txt",
        help="output filename (default: results.txt)",
    )
    parser.add_argument(
        "-c",
        "--confidence",
        type=validate_confidence,
        default=1,
        help="0 (very high), 1 (high), 2 (medium), 3 (low),"
        "4 (very low) (default: 1)",
    )
    parser.add_argument(
        "-t",
        "--type",
        type=validate_type,
        default="txt",
        help="output file type [txt|json|csv] (default: txt)",
    )
    parser.add_argument(
        "-d",
        "--domains",
        type=str,
        default="",
        help="update from FILE instead of downloading new domains",
    )
    parser.add_argument(
        "-u",
        "--url",
        type=str,
        default="https://feeds.opensquat.com/opensquat-nrd-latest.txt",
        help="URL to download domain feed (default: https://feeds.opensquat.com/opensquat-nrd-latest.txt)",
    )
    parser.add_argument(
        "-p",
        "--period",
        type=str,
        default=None,
        help=argparse.SUPPRESS,  # Hide from help since deprecated
    )

    # Mode selection: --premium and --api are mutually exclusive.
    # Default (neither flag) is community mode.
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--premium",
        action="store_true",
        help="Premium Feed mode - use the paid NRD feed (requires openSquat API key)",
    )
    mode_group.add_argument(
        "--api",
        action="store_true",
        help="Premium API mode - query the openSquat lookalike API per keyword (no local feed)",
    )

    parser.add_argument(
        "--api-key",
        type=str,
        default="",
        help="openSquat API key (or set $OPENSQUAT_API_KEY, or place in api_key.txt)",
    )
    parser.add_argument(
        "--api-history-days",
        type=int,
        default=None,
        help="API mode: NRD history window in days (clipped to plan cap)",
    )
    parser.add_argument(
        "--api-max-results",
        type=int,
        default=None,
        help="API mode: max results per keyword (clipped to plan cap)",
    )
    parser.add_argument(
        "--api-fuzziness",
        type=str,
        default=None,
        choices=["exact", "low", "high", "auto"],
        help="API mode: override the fuzziness derived from -c/--confidence",
    )
    parser.add_argument(
        "--api-rate-limit",
        type=int,
        default=None,
        help="Premium API mode: max requests per second across all workers "
             "(default: unlimited). Set at or below your backend's sustained "
             "rate policy to avoid triggering rate limits on large scans "
             "(e.g. 8 for a backend that allows 10 req/s).",
    )

    parser.add_argument(
        "--ct",
        action="store_true",
        help="search in certificate transparency",
    )

    parser.add_argument(
        "--doppelganger",
        action="store_true",
        help="doppelganger-only mode: check if domains contain the keyword and are reachable",
    )

    parser.add_argument(
        "--dns",
        action="store_true",
        help="Check if domain is flagged by Quad9 DNS"
    )

    parser.add_argument(
        "--phishing",
        type=str,
        default="",
        help="search known and active Phishing sites (arg: output.txt)",
    )
    parser.add_argument(
        "--phishing-fallback",
        type=validate_https_url,
        default=None,
        metavar="URL",
        help="https list of phishing domains/URLs (one per line) used only "
             "when the default Phishing Database cannot be downloaded",
    )
    parser.add_argument(
        "--subdomains",
        action="store_true",
        help="search for subdomains from flagged domains",
    )
    parser.add_argument(
        "--portcheck",
        action="store_true",
        help="Verify is port 80/443 is open",
    )
    parser.add_argument(
        "--vt",
        action="store_true",
        help="validate against VirusTotal",
    )

    args = parser.parse_args()

    # Check for deprecated -p/--period argument
    if args.period is not None:
        print("\n[ERROR] The weekly/monthly feeds have been deprecated. Please use the daily feeds.\n")
        exit(1)

    # Resolve mode (community is the default). The three internal values
    # correspond to the user-facing labels:
    #   community   -> "Community"
    #   premium_feed -> "Premium Feed"   (--premium)
    #   premium_api  -> "Premium API"    (--api)
    if args.premium:
        args.mode = "premium_feed"
    elif args.api:
        args.mode = "premium_api"
    else:
        args.mode = "community"

    # Resolve API key when needed (premium and api modes)
    args.resolved_api_key = None
    if args.mode != "community":
        try:
            args.resolved_api_key = auth.load_api_key(args.api_key)
        except auth.AuthError as e:
            print(
                Style.BRIGHT + Fore.RED +
                f"[ERROR] {e}" +
                Style.RESET_ALL
            )
            exit(-1)
        # Confirm which key got picked up without leaking it. Using the
        # masked form means support logs / screenshots are safe to share.
        print(
            Fore.GREEN +
            f"[*] API key loaded: {auth.mask_key(args.resolved_api_key)}" +
            Style.RESET_ALL
        )

    return args
