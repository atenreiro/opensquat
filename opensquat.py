import io
import requests
import zipfile
import numpy as np
import json
import os
import argparse
import subprocess as call
from datetime import date
from datetime import datetime
from lxml import etree 


def levenshtein(s, t, ratio_calc = False):
    """ levenshtein_ratio_and_distance:
        Calculates levenshtein distance between two strings.
        If ratio_calc = True, the function computes the
        levenshtein distance ratio of similarity between two strings
        For all i and j, distance[i,j] will contain the Levenshtein
        distance between the first i characters of s and the
        first j characters of t
        
        original credits: Unkown, internet sourced
    """
    # Initialize matrix of zeros
    rows = len(s)+1
    cols = len(t)+1
    distance = np.zeros((rows,cols),dtype = int)

    # Populate matrix of zeros with the indeces of each character of 
    # both strings
    for i in range(1, rows):
        for k in range(1,cols):
            distance[i][0] = i
            distance[0][k] = k
            
    # Iterate over the matrix to compute the cost of deletions,insertions and/or
    # substitutions    
    for col in range(1, cols):
        for row in range(1, rows):
            if s[row-1] == t[col-1]:
                cost = 0 # If the characters are the same in the two strings
                         # in a given position [i,j] then the cost is 0
            else:
                if ratio_calc == True:
                    cost = 2
                else:
                    cost = 1
            distance[row][col] = min(distance[row-1][col] + 1, # Cost deletions
                                 distance[row][col-1] + 1,     # Cost insertions
                                 distance[row-1][col-1] + cost) # Cost substitutions
    if ratio_calc == True:
        Ratio = ((len(s)+len(t)) - distance[row][col]) / (len(s)+len(t))
        return Ratio
    else:
        return distance[row][col]


class Domain:
    def __init__(self):
        self.URL = 'https://www.whoisdownload.com/newly-registered-domains'
        self.today = date.today().strftime("%Y-%m-%d")
        self.domain_filename = None
        self.keywords_filename = None
        self.json_filename = None
        self.jsonfile_path = None
        self.domain_total = 0
        self.keywords_total = 0
        self.json_filename = None
        self.list_json = []
        self.json_filename = self.today + ".json"
        self.jsonfile_path = date.today().strftime("%Y") + "/" + date.today().strftime("%m") + "/"
        self.sensitiveness = 2
        self.confidence = {0: "very high confidence", 1: "high confidence", 
                           2: "medium confidence", 3: "low confidence", 
                           4: "very low confidence"}

    def download(self):

        print("* Downloading fresh domain list from", self.URL)
        
        session = requests.Session()
        response1 = session.get(self.URL)

        dom = etree.HTML(response1.text)

        index = 0
        for row in dom.xpath("//div[@class='post_content']//div[@id='table_wraper']//table[@class='cart_table table table-striped table-bordered']/tbody")[0]:
            cells = row.xpath("./td")
            links = row.xpath("./td[@class='price_td']/div[@class='add_cart']/a[@class='btn btn-success']")
            if cells[2].text.strip() == self.today and len(links)>0:
                response2 = session.get(links[0].attrib['href'])

                filebytes = io.BytesIO(response2.content)
                myzipfile = zipfile.ZipFile(filebytes)

                print("* uncompressing file...")
                for name in myzipfile.namelist():
                    uncompressed = myzipfile.read(name)
                    output = open(name ,'wb')
                    output.write(uncompressed)
                    output.close()

            index = index + 1

        self.domain_filename = name
        x = 1
        return True
        

    def count_domains(self):
        for line in open(self.domain_filename): self.domain_total += 1
        
        
    def count_keywords(self):
    
        for line in open(self.keywords_filename): 
            if (line[0] != "#") and (line[0] != " ") and (line[0] != ""): 
                self.keywords_total += 1
                
    def set_filename(self, filename):
        self.keywords_filename = filename
        
        
    def print_all(self):
        print("* keywords filename:", self.keywords_filename)
        print("* keywords total:", self.keywords_total)

    def check_folders(self):
        
        path_year = date.today().strftime("%Y")
        path_month = os.path.join(path_year, date.today().strftime("%m"))
        
        i = 0
        
        if not os.path.exists(path_year):
             os.makedirs(path_year)
             print("* folder for 'year' created")
             
        if not os.path.exists(path_month):
             os.makedirs(path_month)    
             print("* folder for 'month' created")
             
        
        
    def check_squatting(self):
        
        f_key = open(self.keywords_filename, "r")
        f_dom = open(self.domain_filename, "r")
        
        path = os.path.join(self.jsonfile_path, self.json_filename)
        f_json = open(path, 'w')
        
        # keyword iteration
        i = 0
        
        print("* Total domains:", self.domain_total)

        for keyword in f_key:
            keyword = keyword.replace('\n', '')
    
            if (keyword[0] != "#") and (keyword[0] != " ") and (keyword[0] != ""):
                i += 1
                print("\n* Verifying keyword:",keyword, "[",i,"/",self.keywords_total,"]")
                
                for domains in f_dom:
                    domain  = domains.split(".")
                    domain = domain[0].replace('\n', '')
                    domains = domains.replace('\n', '')
                    leven_dist = levenshtein(keyword, domain)
    
                    if (leven_dist <= self.sensitiveness):
                        print("** Similarity detected between", keyword, "and", domains, "(", self.confidence[leven_dist], ")")
                        self.list_json.append(domains)
    
            f_dom.seek(0)
    
        json.dump(self.list_json, f_json)
        f_json.close()

        print("* Domains flagged:", self.list_json)
    
        
        
    def main(self, keywords_file):
        self.download()
        self.count_domains()
        self.set_filename(keywords_file)
        self.count_keywords()
        self.print_all()
        self.check_folders()
        self.check_squatting()

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
    
    #parser = argparse.ArgumentParser()
    #parser.add_argument('-k', '--keywords', action='store_true', default='keywords.txt', help="keywords file (default: keywords.txt)")
    #parser.add_argument('-o', '--output', action='store_true', help="output json file (default: yyyy-mm-dd.json)")
    #parser.add_argument('-f', '--folders', action='store_true', help="output save into folder: yyyy/mm")    
    
    #args = parser.parse_args()
    
    #keywords = args.k
    #output = args.o
    
    #print("keywords:", args.k)
    #print("output:", args.o)
    
    
    Domain().main("keywords.txt")
    
    