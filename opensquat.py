# -*- coding: utf-8 -*-
"""
openSquat

(c) CERT-MZ | Andre Tenreiro | andre@cert.mz

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3

"""
import io
import requests
import zipfile
import json
import os
import time
import subprocess as call
from datetime import date
from lxml import etree 

# external files
from output import *
from parser import *
from validations import *

__VERSION__ = "version 1.1"


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
        self.URL = 'https://raw.githubusercontent.com/CERT-MZ/projects/master/Domain-squatting/domain-names.txt'
        self.today = date.today().strftime("%Y-%m-%d")
        self.domain_filename = None
        self.keywords_filename = None
        self.domain_total = 0
        self.keywords_total = 0
        self.list_domains = []
        self.confidence_level = 2
        self.confidence = {0: "very high confidence",
                           1: "high confidence", 
                           2: "medium confidence",
                           3: "low confidence", 
                           4: "very low confidence"}


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

        print("[*] Downloading fresh domain list from", self.URL)
        
        response = requests.get(self.URL)
        data = response.content

        with open('domain-names.txt', 'wb') as f:
            f.write(data)
        
        f.close()
        self.domain_filename = "domain-names.txt"
        return True
        

    def count_domains(self):
        """Count number of domains (lines) from the domains file

        Args:
            none

        Returns:
            self.domain_total: total number of domains in the file
    
        """
        
        if not os.path.isfile(self.domain_filename):
            print('[*] File', self.domain_filename, 'not found or not readable! Exiting...\n')
            exit(-1)
        
        for line in open(self.domain_filename): self.domain_total += 1
        
        return self.domain_total
        
    def count_keywords(self):
        """Count number of keywords from the keyword file
           the counter will ignore the chars "#", "\n" and " "

        Args:
            none

        Returns:
            none
    
        """ 
        my_list = []
        
        if not os.path.isfile(self.keywords_filename):
            print('[*] File', self.keywords_filename, 'not found or not readable! Exiting... \n')
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
            keyword = keyword.replace('\n', '')
            keyword = keyword.lower()
    
            if (keyword[0] != "#") and (keyword[0] != " ") and (keyword[0] != "") and (keyword[0] != "\n"):
                i += 1
                print("\n[*] Verifying keyword:",keyword, "[",i,"/",self.keywords_total,"]")
                
                for domains in f_dom:
                    domain  = domains.split(".")
                    domain = domain[0].replace('\n', '')
                    domain = domain.lower()
                    domains = domains.replace('\n', '')
                    leven_dist = levenshtein(keyword, domain)

                    if leven_dist <= self.confidence_level:
                        print("[+] Similarity detected between", keyword, "and", domains, "(%s)" % self.confidence[leven_dist])
                        self.list_domains.append(domains)
                    elif self.domain_contains(keyword, domains):
                        print("[+] Similarity detected between", keyword, "and", domains, "(high confidence)")
                        self.list_domains.append(domains)

    
            f_dom.seek(0)
    
        return self.list_domains 
    
        
        
    def main(self, keywords_file, confidence_level, domains_file):
        """Method to call the class functions

        Args:
            none

        Returns:
            none
    
        """
        
        self.set_filename(keywords_file)
        self.domain_filename = domains_file
        self.confidence_level = confidence_level
        self.count_keywords()
        
        if self.domain_filename is '': 
            self.download()

        self.count_domains()

        self.print_info()
        return self.check_squatting()

    
if __name__ == '__main__':


    banner = """
                          _____                   _   
                         / ____|                 | |  
   ___  _ __   ___ _ __ | (___   __ _ _   _  __ _| |_ 
  / _ \| '_ \ / _ \ '_ \ \___ \ / _` | | | |/ _` | __|
 | (_) | |_) |  __/ | | |____) | (_| | |_| | (_| | |_ 
  \___/| .__/ \___|_| |_|_____/ \__, |\__,_|\__,_|\__|
       | |                         | |                
       |_|                         |_|      
                    
    (c) CERT-MZ | Andre Tenreiro | andre@cert.mz
    """
    
    print(banner)
    print("\t\t"+__VERSION__+"\n")    

    args = parser()

    start_time = time.time()
  
    file_content = Domain().main(args.keywords, args.confidence, args.domains)
    
    print("")
    print("+---------- Summary ----------+")
    SaveFile().main(args.output, args.type, file_content)

    end_time = round(time.time() - start_time, 2)
    
    print("[*] Domains flagged:", len(file_content))
    print("[*] Running time: %s seconds" % end_time)
    print("")
    