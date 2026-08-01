# -*- coding: utf-8 -*-
# Module: homograph.py
"""
openSquat

(c) Andre Tenreiro

* https://github.com/atenreiro/opensquat

"""
from confusable_homoglyphs import confusables
import homoglyphs as hg


# Lazy module-level singleton: hg.Homoglyphs() loads its data tables on
# construction (~2.3ms), so building it per call would dominate the cost
# of scanning a feed. One instance per process is enough — workers run in
# separate processes and each gets its own on first use.
_HOMOGLYPHS = None


def _get_homoglyphs():
    global _HOMOGLYPHS
    if _HOMOGLYPHS is None:
        _HOMOGLYPHS = hg.Homoglyphs(languages={"en"}, strategy=hg.STRATEGY_LOAD)
    return _HOMOGLYPHS


def decode_punycode(label):
    """
    Decode a single punycode DNS label ("xn--...") to its unicode form.

    Uses the raw punycode codec rather than strict IDNA2008 on purpose:
    attackers register whatever their registrar accepts, and strict IDNA
    rejects some real-world registrations (302/303 vs 303/303 on a live
    feed sample). Detection tooling wants the lenient reading.

    Args:
        label: one domain label, e.g. "xn--mirosoft-hw7c"

    Return:
        str: the decoded unicode label, or None when the label is not
        punycode or does not decode.
    """
    if not label.startswith("xn--"):
        return None
    try:
        return label[4:].encode("ascii").decode("punycode")
    except UnicodeError:
        return None


def fold_to_latin(text):
    """
    Fold a unicode label to ASCII by mapping every non-ASCII character to
    its first ASCII homoglyph.

    This is both the detector and the false-positive guard: a genuine
    Latin-lookalike attack needs EVERY character to render as a Latin
    letter, so any character with no ASCII homoglyph (CJK, Hangul,
    accented Latin like "ü") means the label is not a homograph attack
    and None is returned.

    Unlike check_homograph()/is_dangerous(), this catches whole-script
    confusables (Cyrillic "аррӏе", the 2017 apple.com PoC) and same-script
    lookalikes (Latin small-capital "miᴄrosoft"), which have no script
    mixing and therefore pass is_dangerous() undetected.

    Args:
        text: unicode label, e.g. "miᴄrosoft"

    Return:
        str: the folded ASCII form (e.g. "microsoft"), or None when any
        character cannot be mapped to ASCII.
    """
    homoglyphs = _get_homoglyphs()
    out = []
    for char in text:
        if ord(char) < 128:
            out.append(char)
            continue
        ascii_forms = homoglyphs.to_ascii(char)
        if not ascii_forms:
            return None
        out.append(ascii_forms[0])
    return "".join(out)


def check_homograph(domain):
    """
    Check if domain contain homograph character.

    Args:
        none

    Return:
        none
    """
    homograph_domain = bool(confusables.is_dangerous(domain))

    if homograph_domain:
        return True
    else:
        return False


def homograph_to_latin(domain):
    """
    Convert homograph domain to LATIN characters.

    Args:
        none

    Return:
        none
    """
    homoglyphs = hg.Homoglyphs(languages={"en"}, strategy=hg.STRATEGY_LOAD)

    new_domain = []
    str_domain = ""

    for char in domain:
        charset = hg.Categories.detect(char)
        if charset != "LATIN":
            char_converted = homoglyphs.to_ascii(char)
            char_converted = "".join(char_converted)
            new_domain.append(char_converted)
        else:
            new_domain.append(char)

    str_domain = "".join(new_domain)

    return str_domain
