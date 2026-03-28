# -*- coding: utf-8 -*-
# Module: validations.py
"""
openSquat.

(c) Andre Tenreiro

* https://github.com/atenreiro/opensquat
"""
from strsimpy.levenshtein import Levenshtein


def levenshtein(keyword, domain):
    """
    Compute Levenshtein distance.

    Args:
        keyword:
        domain:

    Return:
        leven.distance: Levenshtein Distance (int)
    """
    leven = Levenshtein()
    return leven.distance(keyword, domain)
