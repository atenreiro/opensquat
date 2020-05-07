openSquat
====

.. image:: https://travis-ci.org/lorien/grab.png?branch=master
    :target: https://travis-ci.org/lorien/grab?branch=master

.. image:: https://ci.appveyor.com/api/projects/status/uxj24vjin7gptdlg
    :target: https://ci.appveyor.com/project/lorien/grab

.. image:: https://coveralls.io/repos/lorien/grab/badge.svg?branch=master
    :target: https://coveralls.io/r/lorien/grab?branch=master

.. image:: https://api.codacy.com/project/badge/Grade/18465ca1458b4c5e99026aafa5b58e98
   :target: https://www.codacy.com/app/lorien/grab?utm_source=github.com&utm_medium=referral&utm_content=lorien/grab&utm_campaign=badger

.. image:: https://readthedocs.org/projects/grab/badge/?version=latest
    :target: http://docs.grablib.org/en/latest/

What is OpenSquat?
-------------

openSquat is a OSINT R&D project to detect **cybersquatting** threats to specific companies or domains, such as:

* Cyber squatting
* Typo squatting
* Phishing
* Scams

This is an opensource project so everyone's welcomed to contribute.


It does support some features such as:

* Automatic newly registered domain updating
* Levenshtein distance to calculate word similarity
* Use different levels of confidence threshold to fine tune
* Save output into different formats (txt, JSON and CSV)
* Can be integrated with other threat intelligence tools and DNS sinkholes

Installation
------------

.. code:: bash

    $ pip -r requirements.txt

Make sure you have Python 3.6+ and pip3 in your environment


OpenSquat Running Examples
------------

.. code:: bash

    # Lazy run with default options
    $ python3 opensquat.py

    # for all the options
    $ python3 opensquat.py -h



To Do / Roadmap
-------------

* Support for hamming distance algorithm
* Integration with VirusTotal (VT)
* Use certificate transparency public database as another source
* Improve code quality from B to A grade (codacy)


Author
-------------
* Andre Tenreiro [LinkedInk](https://www.linkedin.com/in/andretenreiro/)
* andre@cert.mz


