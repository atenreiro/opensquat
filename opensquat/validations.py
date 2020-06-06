# -*- coding: utf-8 -*-
# Module: validations.py
"""
openSquat

(c) CERT-MZ

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
from strsimpy.levenshtein import Levenshtein
from strsimpy.jaro_winkler import JaroWinkler


def levenshtein(keyword, domain):
    """Compute Levenshtein distance

    Args:
        keyword:
        domain:

    Return:
        leven.distance: Levenshtein Distance (int)

    """
    leven = Levenshtein()
    return leven.distance(keyword, domain)


def jaro_winkler(keyword, domain):
    """Compute Jaro Winkler similarity

    Args:
        keyword:
        domain:

    Return:
        jarowinkler.similarity: (float) between 0.0 and 1.0

    """
    jarowinkler = JaroWinkler()
    return jarowinkler.similarity(keyword, domain)
