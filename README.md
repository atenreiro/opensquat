openSquat
====

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/9231646e8ddf4efc9fb1f62f628df34a)](https://www.codacy.com/manual/atenreiro/opensquat?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=atenreiro/opensquat&amp;utm_campaign=Badge_Grade)
[![Build Status](https://travis-ci.com/atenreiro/opensquat.svg?branch=master)](https://travis-ci.com/atenreiro/opensquat)

![alt text](https://raw.githubusercontent.com/atenreiro/opensquat/master/screenshots/openSquat.PNG)

[![DepShield Badge](https://depshield.sonatype.org/badges/atenreiro/opensquat/depshield.svg)](https://depshield.github.io)

What is openSquat?
-------------

openSquat is an opensource Intelligence (OSINT) R&D project to identify **cyber squatting** threats to specific companies or domains, such as:

*  Domain squatting
*  Typo squatting
*  IDN homograph attacks
*  Phishing
*  Scams

This is an opensource project so everyone's welcomed to contribute.

It does support some key features such as:

*  Automatic newly registered domain updating (once a day)
*  Levenshtein distance to calculate word similarity
*  IDN homograph attack detection
*  Use different levels of confidence threshold to fine tune
*  Save output into different formats (txt, JSON and CSV)
*  Can be integrated with other threat intelligence tools and DNS sinkholes


Installation
------------

```bash
    $ git clone https://github.com/atenreiro/opensquat
    $ pip3 install -r requirements.txt
```

Make sure you have Python 3.6+ and pip3 in your environment

Usage Examples
------------

```bash
    # Lazy run with default options
    $ python3 opensquat.py

    # for all the options
    $ python3 opensquat.py -h
```

To Do / Roadmap
-------------
*  Finalise the support for Jaro-Winkler (word similarity)
*  Integration with VirusTotal (VT)
*  Use certificate transparency public database as another source
*  ~~Homograph detection~~ done
*  Improve code quality from B to A grade (codacy)
*  PEP8 compliance
*  Add documentation 

Changelog
-------------
*  Check the [CHANGELOG](https://github.com/atenreiro/opensquat/blob/master/CHANGELOG) file.

Author
-------------
*  Andre Tenreiro [(LinkedInk](https://www.linkedin.com/in/andretenreiro/)
*  andre@cert.mz
