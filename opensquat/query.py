# -*- coding: utf-8 -*-
# Module: query.py
"""
openSquat.

* https://github.com/atenreiro/opensquat

Software licensed under GNU version 3
"""
import requests
from opensquat import __VERSION__
from colorama import init, Fore, Style

API_URL = "https://api.domainsec.io/v1/keyword/"
API_URL_UNAUTH = "https://api.domainsec.io/v1/free/keyword/"

def api_print_error(message):
    print(
        Style.BRIGHT + Fore.RED + "[ERROR] " + message +
        Style.RESET_ALL
    )

def api_print_info(message):
    print(
        Style.BRIGHT + Fore.WHITE + "[INFO] " + message +
        Style.RESET_ALL
    )

def api_query(keyword, api_key, log_level):
    """
    Query the API with the given keyword.

    Args:
        keyword (str): The keyword to query.
        api_key (str): The API key to use for the query.
        log_level (str): The logging level to use.

    Returns:
        list: List of domains.
    """
    # User-Agent
    ver = f"openSquat-{__VERSION__}"

    # List of domains
    domains_list = []

    headers = {'User-Agent': ver}
    url = API_URL_UNAUTH + keyword
    if api_key:
        headers['x-api'] = api_key
        url = API_URL + keyword

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if data.get("response") == "success":
            domains = data.get("domains", [])
            if domains:
                domains_list = domains
        else:
            api_print_error(data.get("message", "Unknown error occurred."))
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 400:
            error_message = response.json().get("response", "Unknown 403 error occurred.")
            api_print_error(f"{error_message}")
        else:
            api_print_error(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError as conn_err:
        api_print_error(f"Connection error occurred: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        api_print_error(f"Timeout error occurred: {timeout_err}")
    except requests.exceptions.RequestException as req_err:
        api_print_error(f"An error occurred: {req_err}")
    except Exception as e:
        api_print_error(f"An unexpected error occurred: {e}")

    return domains_list
