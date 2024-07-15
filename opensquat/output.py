# -*- coding: utf-8 -*-
# Module: output.py
"""
openSquat.

* https://github.com/atenreiro/opensquat

Software licensed under GNU version 3
"""
import json
import csv
from opensquat.messages import cli_print_error

def save_results(domains, file_name, file_type="json"):
    """
    Saves the content of a dictionary to a file in JSON, TXT, or CSV format.

    Parameters:
    domains (dict): The dictionary to be saved.
    file_name (str): The name of the file to save the dictionary to.
    file_type (str): The type of file to save (json, txt, csv). Default is json.
    """

    try:
        if file_type == "json":
            with open(file_name, 'w') as file:
                json.dump(domains, file, indent=4)
        elif file_type == "txt":
            with open(file_name, 'w') as file:
                for values in domains.values():
                    file.write('\n'.join(values) + '\n')
        elif file_type == "csv":
            with open(file_name, 'w', newline='') as file:
                writer = csv.writer(file, delimiter=',')
                all_domains = [domain for values in domains.values() for domain in values]
                writer.writerow(all_domains)
        else:
            cli_print_error("Unknown file type! Data not saved.")
            return False
    except Exception as e:
        cli_print_error(f"An error occurred: {e}")
        return False
    
    return True
