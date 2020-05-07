import io
import requests
import zipfile
import json
import os
import argparse
import time
import subprocess as call
from datetime import date
from datetime import datetime
from lxml import etree 

# external files
from levenshtein import *
from output import *
#from parser import *


class Domain:
    def __init__(self):
        self.URL = 'https://raw.githubusercontent.com/CERT-MZ/projects/master/Domain-squatting/domain-names.txt'
        self.today = date.today().strftime("%Y-%m-%d")
        self.domain_filename = None
        self.keywords_filename = None
        self.domain_total = 0
        self.keywords_total = 0
        self.list_domains = []
        self.confidence_level = 2
        self.confidence = {0: "very high confidence", 1: "high confidence", 
                           2: "medium confidence", 3: "low confidence", 
                           4: "very low confidence"}

    def download(self):
        """Download the latest newly registered domains

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
            none
    
        """
        
        if not os.path.isfile(self.domain_filename):
            print('[*] File', self.domain_filename, 'not found or not readable! Exiting...\n')
            exit(-1)
        
        for line in open(self.domain_filename): self.domain_total += 1
        
        
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
            print('[*] File', keywords_filename, 'not found or not readable! Exiting...\n')
            exit(-1)
        
        for line in open(self.keywords_filename):
            if (line[0] != "#") and (line[0] != " ") and (line[0] != "") and (line[0] != "\n"): 
                self.keywords_total += 1
                
    def set_filename(self, filename):
        """Method to set the filename 

        Args:
            (string): keywords_filename

        Returns:
            none
    
        """
        self.keywords_filename = filename
        
        
    def print_info(self):
        print("[*] keywords filename:", self.keywords_filename)
        print("[*] keywords total:", self.keywords_total)
        print("[*] Total domains:", self.domain_total)

        
    def check_squatting(self):
        
        f_key = open(self.keywords_filename, "r")
        f_dom = open(self.domain_filename, "r")

        # keyword iteration
        i = 0
        
        for keyword in f_key:
            keyword = keyword.replace('\n', '')
    
            if (keyword[0] != "#") and (keyword[0] != " ") and (keyword[0] != "") and (keyword[0] != "\n"):
                i += 1
                print("\n[*] Verifying keyword:",keyword, "[",i,"/",self.keywords_total,"]")
                
                for domains in f_dom:
                    domain  = domains.split(".")
                    domain = domain[0].replace('\n', '')
                    domains = domains.replace('\n', '')
                    leven_dist = levenshtein(keyword, domain)
    
                    if (leven_dist <= self.confidence_level):
                        print("[+] Similarity detected between", keyword, "and", domains, "(%s)" % self.confidence[leven_dist])
                        self.list_domains.append(domains)
    
            f_dom.seek(0)
    
        return self.list_domains 
    
        
        
    def main(self, keywords_file, confidence_level, domains_file):
        
        self.set_filename(keywords_file)
        self.domain_filename = domains_file
        self.confidence_level = confidence_level
        self.count_keywords()
        
        if not domains_file: 
            self.download()

        self.count_domains()

        self.print_info()
        return self.check_squatting()


def validate_type(file_type):
    
    file_type = str(file_type)
    
    if (file_type != "txt") and (file_type != "json") and (file_type != "csv"):
        raise argparse.ArgumentTypeError("File format unkown!")
    return file_type

def validate_confidence(confidence_level):
    confidence_level = int(confidence_level)
    
    if confidence_level not in range(0, 5):
        raise argparse.ArgumentTypeError("confidence must be between 0 and 4")
    return confidence_level


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
    

    # Parser
    parser = argparse.ArgumentParser(description="openSquat")
    parser.add_argument('-k', '--keywords', type=str, default='results.json', 
                         help="keywords file (default: keywords.txt)")
    parser.add_argument('-o', '--output', type=str, default="domains.txt", 
                         help="output filename (default: domains.txt)")
    parser.add_argument('-c', '--confidence', type=validate_confidence, default=1, 
                         help="0 (very high), 1 (high), 2 (medium), 3 (low), 4 (very low) (default: 1)")
    parser.add_argument('-t', '--type', type=validate_type, default="txt", 
                         help="output file type [txt|json|csv] (default: txt)")
    parser.add_argument('-d', '--domains', type=str, default='domain-names.txt',
                        help='update from FILE instead of downloading new domains')
    args = parser.parse_args()
    
    
    start_time = time.time()
  
    file_content = Domain().main(args.keywords, args.confidence, args.domains)
    SaveFile().main(args.output, args.type, file_content)

    end_time = time.time() - start_time
    print("[*] Running time: %s seconds" % e