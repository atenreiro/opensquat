# Module: validations.py
"""!
openSquat

(c) CERT-MZ | Andre Tenreiro | andre@cert.mz

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

"""
from strsimpy.levenshtein import Levenshtein
from strsimpy.jaro_winkler import JaroWinkler


def levenshtein(keyword, domain):
    """Compute Levenshtein distance

    Args:
        keyword:
        domain:

    Returns:
        leven.distance: Levenshtein Distance (int)

    """
    leven = Levenshtein()
    return leven.distance(keyword, domain)


def jaro_winkler(keyword, domain):
    """Compute Jaro Winkler similarity

    Args:
        keyword:
        domain:

    Returns:
        jarowinkler.similarity: (float) between 0.0 and 1.0

    """
    jarowinkler = JaroWinkler()
    return jarowinkler.similarity(keyword, domain)
