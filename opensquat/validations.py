# -*- coding: utf-8 -*-
# Module: validations.py
"""
openSquat.

(c) Andre Tenreiro

* https://github.com/atenreiro/opensquat
"""


def levenshtein(keyword, domain, threshold=None):
    """
    Compute Levenshtein distance using native Python.

    When threshold is provided, applies early exit optimizations:
    - Skips computation if length difference exceeds threshold
    - Stops mid-computation if no result can beat threshold
    Returns threshold + 1 for values that exceed the threshold.

    Args:
        keyword: source string
        domain: target string
        threshold: optional max distance cutoff for early exit

    Return:
        int: Levenshtein distance (or threshold + 1 if exceeded)
    """
    len0 = len(keyword)
    len1 = len(domain)

    if threshold is not None and abs(len0 - len1) > threshold:
        return threshold + 1

    if keyword == domain:
        return 0
    if len0 == 0:
        return len1
    if len1 == 0:
        return len0

    v0 = list(range(len1 + 1))
    v1 = [0] * (len1 + 1)

    for i in range(len0):
        v1[0] = i + 1
        char_i = keyword[i]
        row_min = v1[0]
        for j in range(len1):
            cost = 0 if char_i == domain[j] else 1
            val = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
            v1[j + 1] = val
            if val < row_min:
                row_min = val
        if threshold is not None and row_min > threshold:
            return threshold + 1
        v0, v1 = v1, v0

    return v0[len1]
