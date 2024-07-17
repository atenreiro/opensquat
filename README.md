:warning: **this page for the release v3.0.0 (Merlion) is still being updated**

openSquat
====
![alt text](https://raw.githubusercontent.com/atenreiro/opensquat/master/screenshots/openSquat_logo.png)

## Table of Contents
- [What is openSquat](#what-is-opensquat)
- [Screenshot / Video Demo](#screenshot--video-demo)
- [Demo / Forks](#demo--forks)
- [How to Install](#how-to-install)
- [How to Update](#how-to-update)
- [Usage Examples](#usage-examples)
- [Automations & Integrations](#automations--integrations)
- [To Do / Roadmap](#to-do--roadmap)
- [Changelog](#changelog)
- [How to Contribute](#how-to-contribute)
- [Authors](#authors)
- [How to Help](#how-to-help)

What is openSquat
-------------

openSquat is an opensource Intelligence (OSINT) security tool to identify **cyber squatting** threats to specific companies or domains, such as:

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

As an opensource project, everyone's welcome to contribute.

Screenshot / Video Demo
-------------
![alt text](https://raw.githubusercontent.com/atenreiro/opensquat/dev/screenshots/openSquat.PNG)

Check the 21 seconds [Demo Video](https://asciinema.org/a/0A0BQ9p08uPKAd7mgCmYgp4aP) (v3.0.0-alpha)


Demo / Forks
------------
*   [Phishy Domains](https://phishydomains.com) for a simple web version of the openSquat.
*   [openSquat Bot](https://telegram.me/opensquat_bot) for a simple Telegram bot.
*   [RapidAPI](https://rapidapi.com/atenreiro/api/opensquat1) to integrate your application with openSquat using REST API.

**Note**: The forks do not contain all the openSquat features.


How to Install
------------

```bash
    git clone https://github.com/atenreiro/opensquat
    pip install -r requirements.txt
```
Make sure you have **Python 3.6+** and **pip3** in your environment

How to Update
------------
> :warning: **when updating**: especially for a major release, re-run the pip install to check for new dependencies.

To update your current version, just type the following commands inside the openSquat directory:
```bash
    git pull
    pip install -r requirements.txt
```
The "pip install" is just to make sure no new libs were added with the new upgrade. 


Usage Examples
------------
Edit the "keywords.txt" with your customised keywords to hunt.

```bash
    # Lazy run with default options
    python opensquat.py

    # for all the options
    python opensquat.py -h
    
    # Search for generic terms used in phishing campaigns (can lead to false-positives)
    python opensquat.py -k generic.txt

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

Automations & Integrations
-------------
You can set up openSquat to run automatically using a task scheduler (such as crontab for Linux) to generate a new list of results daily.

We update our feeds with a fresh new list of domains every day around 7.30 am (UTC+0 / GMT+0)

```bash
# Crontab example - run openSquat every day at 8 am
# In this example, the results are saved to a JSON file format
0 8 * * * /home/john/opensquat/opensquat.py -k keywords.txt -o results.json -t json
```
You can use this output file to feed your SIEM, SOAR, or other tools that support importing from TXT/JSON/CSV formats.

Alternatively, currently in a **Beta preview** you can integrate using REST APIs, your application with [RapidAPI](https://rapidapi.com/atenreiro/api/opensquat1)

Do you have an integration idea or would like to share an integration you developed with our community? Open a GitHub issue or send me an email.

To Do / Roadmap
-------------
*   ~~Integration with VirusTotal (VT) for subdomains validation~~
*   Integratration with VirusTotal (VT) for malware detection
*   ~~Use certificate transparency~~
*   ~~Homograph detection~~ done
*   ~~Improve code quality from B to A grade (codacy)~~
*   ~~PEP8 compliance~~
*   AND logical condition for keywords search (e.g: google+login) - Thanks to Steff T.
*   Enhanced documentation

Changelog
-------------
*   Check the [CHANGELOG](https://github.com/atenreiro/opensquat/blob/master/CHANGELOG) file.

How to Contribute
-------------
We welcome and encourage contributions from the community! If you're interested in helping improve openSquat, here are a variety of ways you can contribute:

- **Reporting Bugs:** To report bugs, open an issue on our [GitHub issues page](https://github.com/atenreiro/opensquat/issues). You should include as much detail as possible to help us understand the problem and what the ideal solution would be.
- **Feature Requests:** To request a new feature, create a "new issue" and describe the feature and potential use cases. You can upvote the "issue" and contribute to the discussions if something similar already exists.
- **Code Contributions:** To help advance openSquat with coding, you can look at open issues or feature requests. Be sure to fork the repository, make your changes, and submit a pull request.
- **Documentation:** You can help improve documentation by fixing typos, clarifying instructions, or adding new, valuable sections.

Thank you for your interest in contributing to openSquat!

Authors
-------------
Project founder
*   Andre Tenreiro [(LinkedIn)](https://www.linkedin.com/in/andretenreiro/)
*   andre+nospam@opensquat.com - remove the "nospam" - [PGP Key](https://mail-api.proton.me/pks/lookup?op=get&search=andre@opensquat.com)

Contributors
*   Please check the contributors page on GitHub

How to Help
-------------
You can help this project in many ways:
*   Providing your time and coding skills to enhance the project
*   Build a decent but simple [project webpage](https://opensquat.com)
*   Provide access to OSINT feeds
*   Open new issues with new suggestions, ideas, bug report or feature requests
*   Spread this project within your network
*   Share your story how have you been using the openSquat and what impact it brought to you
