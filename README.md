openSquat
====

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/9231646e8ddf4efc9fb1f62f628df34a)](https://www.codacy.com/manual/atenreiro/opensquat?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=atenreiro/opensquat&amp;utm_campaign=Badge_Grade)
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fatenreiro%2Fopensquat&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false)](https://hits.seeyoufarm.com)

[![asciicast](https://asciinema.org/a/361931.svg)](https://asciinema.org/a/361931)

What is openSquat
-------------

openSquat is an opensource Intelligence (OSINT) security project to identify **cyber squatting** threats to specific companies or domains, such as:

*   Phishing campaigns
*   Domain squatting
*   Typo squatting
*   Bitsquatting
*   IDN homograph attacks
*   Doppenganger domains
*   Other brand/domain related scams

It does support some key features such as:

*   Automatic newly registered domain updating (once a day)
*   Levenshtein distance to calculate word similarity
*   Fetches active and known phishing domains (Phishing Database project)
*   IDN homograph attack detection
*   Integration with VirusTotal
*   Integration with Quad9 DNS service
*   Use different levels of confidence threshold to fine tune
*   Save output into different formats (txt, JSON and CSV)
*   Can be integrated with other threat intelligence tools and DNS sinkholes

This is an opensource project so everyone's welcomed to contribute.

Installation
------------

```bash
    git clone https://github.com/atenreiro/opensquat
    pip install -r requirements.txt
```

Make sure you have **Python 3.6+** and **pip3** in your environment

Usage Examples
------------

```bash
    # Lazy run with default options
    python opensquat.py

    # for all the options
    python opensquat.py -h

    # With DNS validation (quad9)
    python opensquat.py --dns
    
    # Subdomain search
    python opensquat.py --subdomains
    
    # Check for domains with open ports 80/443
    python opensquat.py --portcheck

    # With Phishing validation (Phishing Database)
    python opensquat.py --phishing phish_results.txt

    # Save output as JSON
    python opensquat.py -o example.json -t json

    # Save output as CSV
    python opensquat.py -o example.csv -t csv

    # Conduct a certificate transparency (ct) hunt
    python opensquat.py --ct

    # Period search - registrations from the last month (default: day)
    python opensquat.py -p month

    # Tweak confidence level. The lower values bring more false positives
    # (0: very high, 1: high (default), 2: medium, 3: low, 4: very low
    python opensquat.py -c 2

    # All validations options
    python opensquat.py --phishing phishing_domains.txt --dns --ct --subdomains --portcheck

```

To Do / Roadmap
-------------
*   ~~Integration with VirusTotal (VT)~~
*   ~~Use certificate transparency~~
*   ~~Homograph detection~~ done
*   ~~Improve code quality from B to A grade (codacy)~~
*   ~~PEP8 compliance~~
*   Integration with PulseDive
*   Add documentation

Feature Request
-------------
To request for a new feature, create a "new issue" and describe the feature and potential use cases. If something similar already exists, you can upvote the "issue" and contribute to the discussions.

Changelog
-------------
*   Check the [CHANGELOG](https://github.com/atenreiro/opensquat/blob/master/CHANGELOG) file.

Authors
-------------
Project founder
*   Andre Tenreiro [(LinkedInk)](https://www.linkedin.com/in/andretenreiro/)
*   [andre@cert.mz](mailto:andre@cert.mz)

Contributors
*   Please check the contributors page on GitHub

You can help this project in many ways:
*   Providing your time and coding skills to enhance the project
*   Build a decent but simple [project webpage](https://opensquat.com)
*   Provide access to OSINT feeds
*   Open new issues with new suggestions, ideas, bug report or feature requests
*   Spread this project within your network
*   Share your story how have you been using the openSquat and what impact it brought to you
*   Make a project logo
