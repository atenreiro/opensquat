# Module: homograph.py
"""!
openSquat

(c) CERT-MZ | Andre Tenreiro | andre@cert.mz

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

"""
from confusable_homoglyphs import confusables
import homoglyphs as hg


def check_homograph(domain):
    """Check if domain contain homograph character

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
    """Convert homograph domain to LATIN characters

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
