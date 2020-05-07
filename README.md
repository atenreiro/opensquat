openSquat
====

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/f5ce26137ad34f0b8940ce6d21fbbc68)](https://www.codacy.com/manual/atenreiro/opensquat?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=atenreiro/opensquat&amp;utm_campaign=Badge_Grade)


What is openSquat?
-------------

openSquat is a OSINT R&D project to detect **cybersquatting** threats to specific companies or domains, such as:

* Cyber squatting
* Typo squatting
* Phishing
* Scams

This is an opensource project so everyone's welcomed to contribute.


It does support some features such as:

* Automatic newly registered domain updating (once a day)
* Levenshtein distance to calculate word similarity
* Use different levels of confidence threshold to fine tune
* Save output into different formats (txt, JSON and CSV)
* Can be integrated with other threat intelligence tools and DNS sinkholes


Installation
------------

```bash
    $ git clone https://github.com/atenreiro/opensquat
    $ pip3 -r requirements.txt
```

Make sure you have Python 3.6+ and pip3 in your environment


OpenSquat Running Examples
------------

```bash
    # Lazy run with default options
    $ python3 opensquat.py

    # for all the options
    $ python3 opensquat.py -h
```

To Do / Roadmap
-------------

* Support for hamming distance algorithm
* Integration with VirusTotal (VT)
* Use certificate transparency public database as another source
* Improve code quality from B to A grade (codacy)


Author
-------------
* Andre Tenreiro [(LinkedInk)](https://www.linkedin.com/in/andretenreiro/)
* andre@cert.mz
