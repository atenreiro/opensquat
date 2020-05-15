# -*- coding: utf-8 -*-
"""
openSquat

(c) CERT-MZ | Andre Tenreiro | andre@cert.mz

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3

"""
import requests
import os
import time
from colorama import Fore, Style
from datetime import date

import output
import arg_parser
import validations
import homograph

__VERSION__ = "version 1.2"


class Domain:
    """The Domain class with handle all the functions related to the domain verifications
     
    To use:
        Domain().main(keywords, confidence, domains)
    
    Attributes:
        URL: The URL to download the updated domain list
        today: today's date in the format yyyy-mm-dd
        domain_filename: If no URL download is required, the local file containing the domains
        keywords_filename: File containing the keywords (plain text)
        domain_total: Total count number of domains from domain_filename
        keywords_total: Total count number of keywords from keywords_filename
        list_domains: A list containing all the flagged domains
        confidence_level: An int containing the confidence of sensitiveness level
        confidence: Dictionary containing the respective confidence string
    """

    def __init__(self):
        self.URL = "https://raw.githubusercontent.com/CERT-MZ/projects/master/Domain-squatting/"
        self.URL_file = None
        self.today = date.today().strftime("%Y-%m-%d")
        self.domain_filename = None
        self.keywords_filename = None
        self.domain_total = 0
        self.keywords_total = 0
        self.list_domains = []
        self.confidence_level = 2
        self.period = "day"
        
        self.confidence = {
            0: "very high confidence",
            1: "high confidence",
            2: "medium confidence",
            3: "low confidence",
            4: "very low confidence",
        }

    @staticmethod
    def domain_contains(keyword, domain):
        if keyword in domain:
            return True

        return False

    def download(self):
        """Download the latest newly registered domains and save locally

        Args:
            none

        Returns:
            none
    
        """

        if (self.period == "day"):
            self.URL_file = "domain-names.txt"
        elif (self.period == "week"):
            self.URL_file = "domain-names-week.txt"
            
        URL = self.URL + self.URL_file
        
        print("[*] Downloading fresh domain list from", URL)
        
        response = requests.get(URL, stream=True)

        # Get total file size in bytes from the request header
        total_size = int(response.headers.get('content-length', 0))
        total_size_mb = round(float(total_size / 1024 / 1024), 2)

        print("[*] Download volume:", total_size_mb, "MB")

        data = response.content
        response.close()
        
        with open(self.URL_file, "wb") as f:
            f.write(data)
        
        f.close()
        
        self.domain_filename = self.URL_file

        return True

    def count_domains(self):
        """Count number of domains (lines) from the domains file

        Args:
            none

        Returns:
            self.domain_total: total number of domains in the file
    
        """

        if not os.path.isfile(self.domain_filename):
            print(
                "[*] File", self.domain_filename, "not found or not readable! Exiting...\n",
            )
            exit(-1)

        for line in open(self.domain_filename):
            self.domain_total += 1

        return self.domain_total

    def count_keywords(self):
        """Count number of keywords from the keyword file
           the counter will ignore the chars "#", "\n" and " "

        Args:
            none

        Returns:
            none
    
        """

        if not os.path.isfile(self.keywords_filename):
            print(
                "[*] File", self.keywords_filename, "not found or not readable! Exiting... \n",
            )
            exit(-1)

        for line in open(self.keywords_filename):
            if (line[0] != "#") and (line[0] != " ") and (line[0] != "") and (line[0] != "\n"):
                self.keywords_total += 1

    def set_filename(self, filename):
        """Method to set the filename

        Args:
            keywords_filename

        Returns:
            none
    
        """
        self.keywords_filename = filename
        
    def set_searchPeriod(self, search_period):
        """Method to set the search_period

        Args:
            search_period

        Returns:
            none
    
        """
        self.period = search_period

    def print_info(self):
        """Method to print some configuration information

        Args:
            none

        Returns:
            none
    
        """
        print("[*] keywords:", self.keywords_filename)
        print("[*] keywords total:", self.keywords_total)
        print("[*] Total domains:", self.domain_total)
        print("[*] Threshold:", self.confidence[self.confidence_level])

    def check_squatting(self):
        """Method that will compute all the similarity calculations between the keywords and domain names

        Args:
            none

        Returns:
            list_domains: list containing all the flagged domains
    
        """

        f_key = open(self.keywords_filename, "r")
        f_dom = open(self.domain_filename, "r")

        # keyword iteration
        i = 0

        for keyword in f_key:
            keyword = keyword.replace("\n", "")
            keyword = keyword.lower()

            if not keyword:
                continue

            if (keyword[0] != "#") and (keyword[0] != " ") and (keyword[0] != "") and (keyword[0] != "\n"):
                i += 1
                print(
                    Fore.GREEN + "\n[*] Verifying keyword:",
                    keyword,
                    "[",
                    i,
                    "/",
                    self.keywords_total,
                    "]" + Style.RESET_ALL,
                )

                for domains in f_dom:
                    domain = domains.split(".")
                    domain = domain[0].replace("\n", "")
                    domain = domain.lower()
                    domains = domains.replace("\n", "")

                    # Check if the domain contains homograph character
                    #   Yes: returns True
                    #   No:  returns False
                    homograph_domain = homograph.check_homograph(domain)

                    if homograph_domain:
                        domain = homograph.homograph_to_latin(domain)

                    # Calculate Levenshtein distance
                    leven_dist = validations.levenshtein(keyword, domain)

                    if (leven_dist <= self.confidence_level) and not (homograph_domain):
                        print(
                            Fore.RED + "[+] Similarity detected between",
                            keyword,
                            "and",
                            domains,
                            "(%s)" % self.confidence[leven_dist],
                            "" + Style.RESET_ALL,
                        )
                        self.list_domains.append(domains)
                    elif (leven_dist <= self.confidence_level) and (homograph_domain):
                        print(
                            Fore.RED + "[+] Homograph detected between",
                            keyword,
                            "and",
                            domains,
                            "(%s)" % self.confidence[leven_dist],
                            "" + Style.RESET_ALL,
                        )
                        self.list_domains.append(domains)
                    elif self.domain_contains(keyword, domains):
                        print(
                            Fore.YELLOW + "[+] The word", keyword, "is contained in", domains, "" + Style.RESET_ALL,
                        )
                        self.list_domains.append(domains)

            f_dom.seek(0)

        return self.list_domains

    def main(self,
             keywords_file,
             confidence_level, 
             domains_file,
             search_period):
        """Method to call the class functions

        Args:
            none

        Returns:
            none
    
        """

        self.set_filename(keywords_file)
        self.domain_filename = domains_file
        self.set_searchPeriod(search_period)
        self.confidence_level = confidence_level
        self.count_keywords()

        if self.domain_filename == "":
            self.download()

        self.count_domains()
        

        self.print_info()
        return self.check_squatting()


if __name__ == "__main__":

    RED, WHITE, GREEN, END, YELLOW, BOLD = (
        "\033[91m",
        "\33[97m",
        "\033[1;32m",
        "\033[0m",
        "\33[93m",
        "\033[1m",
    )

    logo = (
        Fore.GREEN
        + """
                                             █████████                                  █████   
                                            ███░░░░░███                                ░░███    
      ██████  ████████   ██████  ████████  ░███    ░░░   ████████ █████ ████  ██████   ███████  
     ███░░███░░███░░███ ███░░███░░███░░███ ░░█████████  ███░░███ ░░███ ░███  ░░░░░███ ░░░███░   
    ░███ ░███ ░███ ░███░███████  ░███ ░███  ░░░░░░░░███░███ ░███  ░███ ░███   ███████   ░███    
    ░███ ░███ ░███ ░███░███░░░   ░███ ░███  ███    ░███░███ ░███  ░███ ░███  ███░░███   ░███ ███
    ░░██████  ░███████ ░░██████  ████ █████░░█████████ ░░███████  ░░████████░░████████  ░░█████ 
     ░░░░░░   ░███░░░   ░░░░░░  ░░░░ ░░░░░  ░░░░░░░░░   ░░░░░███   ░░░░░░░░  ░░░░░░░░    ░░░░░  
              ░███                                          ░███                                
              █████                                         █████                               
             ░░░░░                                         ░░░░░   
                    (c) CERT-MZ | Andre Tenreiro | andre@cert.mz
    """
        + Style.RESET_ALL
    )

    print(logo)
    print("\t\t\t" + __VERSION__ + "\n")

    args = arg_parser.get_args()

    start_time = time.time()

    file_content = Domain().main(args.keywords, args.confidence,
                                 args.domains, args.period)

    print("")
    print("+---------- Summary ----------+")
    output.SaveFile().main(args.output, args.type, file_content)

    end_time = round(time.time() - start_time, 2)

    print("[*] Domains flagged:", len(file_content))
    print("[*] Running time: %s seconds" % end_time)
    print("")
#EOF
