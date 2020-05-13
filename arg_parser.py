# Module: parser.py
"""
openSquat

(c) CERT-MZ | Andre Tenreiro | andre@cert.mz

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3

"""
import argparse


def validate_type(file_type):
    """Validate file_type

    Args:
        file_type: string containing file type, can only be txt, json or csv.

    Returns:
        file_type
        
    Raise:
        If value is not valid, raise an exception to argparse
    
    """
    file_type = str(file_type)

    if (file_type != "txt") and (file_type != "json") and (file_type != "csv"):
        raise argparse.ArgumentTypeError("File format unkown!")
    return file_type


def validate_confidence(confidence_level):

    """Validate confidence_level

    Args:
        confidence_level: int containing confidence_level, can only be an int between 0 and 4.

    Returns:
        confidence_level
        
    Raise:
        If value is not valid, raise an exception to argparse
    
    """
    confidence_level = int(confidence_level)

    if confidence_level not in range(0, 5):
        raise argparse.ArgumentTypeError("confidence must be between 0 and 4")
    return confidence_level


def get_args():
    """Parser main function

    Args:
        none

    Returns:
        args: returns arguments
    
    """

    # Parser
    parser = argparse.ArgumentParser(description="openSquat")
    parser.add_argument(
        "-k", "--keywords", type=str, default="keywords.txt", help="keywords file (default: keywords.txt)",
    )
    parser.add_argument(
        "-o", "--output", type=str, default="results.txt", help="output filename (default: results.txt)",
    )
    parser.add_argument(
        "-c",
        "--confidence",
        type=validate_confidence,
        default=1,
        help="0 (very high), 1 (high), 2 (medium), 3 (low), 4 (very low) (default: 1)",
    )
    parser.add_argument(
        "-t", "--type", type=validate_type, default="txt", help="output file type [txt|json|csv] (default: txt)",
    )
    parser.add_argument(
        "-d", "--domains", type=str, default="", help="update from FILE instead of downloading new domains",
    )

    args = parser.parse_args()

    return args
