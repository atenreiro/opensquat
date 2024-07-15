# -*- coding: utf-8 -*-
# Module: opensquat.py
"""
openSquat.

* https://github.com/atenreiro/opensquat

Software licensed under GNU version 3
"""

import concurrent.futures
import copy
import multiprocessing
import time

from opensquat import arg, update
from opensquat.banner import print_banner
from opensquat.config import read_config
from opensquat.file_input import keywords_count, keywords_read
from opensquat.messages import cli_print_info
from opensquat.output import save_results
from opensquat.open_ports import is_port_open
from opensquat.email_checks import has_spf_record, has_mx_record


def mask_api_key(s):
    if len(s) <= 4:
        return s
    return '*' * (len(s) - 4) + s[-4]


def check_port(domain, port):
    """
    Check if a port is open on a domain.

    Args:
        domain (str): The domain to check.
        port (int): The port to check.

    Returns:
        bool: True if the port is open, False otherwise.
    """
    return is_port_open(domain, port)


def get_cpu_cores():
    """
    Get the number of CPU cores minus one.

    Returns:
        int: Optimal number of threads.
    """
    cpu_count = multiprocessing.cpu_count()
    return max(1, cpu_count - 1)


def query_worker(keywords, max_workers, api_key, log_level, counter_queue, keywords_total):
    """
    Fetch domains for a list of keywords concurrently.

    Args:
        keywords (list): List of keywords to query.
        max_workers (int): The maximum number of threads to use.
        api_key (str): API key to use for queries.
        log_level (str): Logging level to use.
        counter_queue (Queue): Queue to keep track of the counter.
        keywords_total (int): Total number of keywords.

    Returns:
        dict: A dictionary with keywords as keys and lists of domains as values.
    """
    from opensquat.query import api_query  # Moved import inside function to avoid circular import

    results = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_keyword = {
            executor.submit(api_query, keyword, api_key, log_level): keyword for keyword in keywords
        }

        for future in concurrent.futures.as_completed(future_to_keyword):
            keyword = future_to_keyword[future]
            counter = counter_queue.get()

            try:
                domains = future.result()
                results[keyword] = domains
                print(f"Pattern search: {keyword} [{counter}/{keywords_total}]")
                print(f"Total found: {len(domains)}")
                if VERBOSE:
                    print(domains)
                print("\n")
            except Exception as exc:
                print(f"Keyword {keyword} generated an exception: {exc}")
                results[keyword] = []

            counter_queue.put(counter + 1)
    return results


def check_spf_records_worker(results):
    """
    Check SPF records for each domain in the results.

    Args:
        results (dict): The initial results dictionary.

    Returns:
        dict: The updated results dictionary with SPF records information.
    """
    corrected_results = {
        keyword: {domain: {} for domain in domains} if isinstance(domains, list) else domains
        for keyword, domains in results.items()
    }

    updated_results = copy.deepcopy(corrected_results)

    with concurrent.futures.ThreadPoolExecutor(max_workers=get_cpu_cores()) as executor:
        future_to_domain = {
            executor.submit(has_spf_record, domain): (keyword, domain)
            for keyword, domains in corrected_results.items()
            for domain in domains
        }

        for future in concurrent.futures.as_completed(future_to_domain):
            keyword, domain = future_to_domain[future]
            try:
                spf_record = future.result()
                if not spf_record:
                    spf_record = "no"
                if 'spf_record' not in updated_results[keyword][domain]:
                    updated_results[keyword][domain]['spf_record'] = spf_record
            except Exception as exc:
                print(f"Domain {domain} generated an exception: {exc}")
                updated_results[keyword][domain]['spf_record'] = "no"

    return updated_results


def check_mx_records_worker(results):
    """
    Check MX records for each domain in the results.

    Args:
        results (dict): The initial results dictionary.

    Returns:
        dict: The updated results dictionary with MX records information.
    """
    corrected_results = {
        keyword: {domain: {} for domain in domains} if isinstance(domains, list) else domains
        for keyword, domains in results.items()
    }

    updated_results = copy.deepcopy(corrected_results)

    with concurrent.futures.ThreadPoolExecutor(max_workers=get_cpu_cores()) as executor:
        future_to_domain = {
            executor.submit(has_mx_record, domain): (keyword, domain)
            for keyword, domains in corrected_results.items()
            for domain in domains
        }

        for future in concurrent.futures.as_completed(future_to_domain):
            keyword, domain = future_to_domain[future]
            try:
                has_mx = future.result()
                if 'mx_record' not in updated_results[keyword][domain]:
                    updated_results[keyword][domain]['mx_record'] = "yes" if has_mx else "no"
            except Exception as exc:
                print(f"Domain {domain} generated an exception: {exc}")
                updated_results[keyword][domain]['mx_record'] = "no"

    return updated_results


def check_ports_worker(results, open_ports):
    """
    Check open ports for each domain in the results.

    Args:
        results (dict): The initial results dictionary.
        open_ports (list): List of ports to check.

    Returns:
        dict: The updated results dictionary with open ports information.
    """
    corrected_results = {
        keyword: {domain: {} for domain in domains} if isinstance(domains, list) else domains
        for keyword, domains in results.items()
    }

    updated_results = copy.deepcopy(corrected_results)

    with concurrent.futures.ThreadPoolExecutor(max_workers=get_cpu_cores()) as executor:
        future_to_domain_port = {
            executor.submit(check_port, domain, int(port)): (keyword, domain, port)
            for keyword, domains in corrected_results.items()
            for domain in domains
            for port in open_ports
        }

        for future in concurrent.futures.as_completed(future_to_domain_port):
            keyword, domain, port = future_to_domain_port[future]
            try:
                result = future.result()
                if result:
                    if 'open_ports' not in updated_results[keyword][domain]:
                        updated_results[keyword][domain]['open_ports'] = []
                    updated_results[keyword][domain]['open_ports'].append(port)
            except Exception as exc:
                print(f"Domain {domain} port {port} generated an exception: {exc}")

    for keyword, domains in corrected_results.items():
        for domain in domains:
            if 'open_ports' not in updated_results[keyword][domain]:
                updated_results[keyword][domain]['open_ports'] = []

    return updated_results


if __name__ == "__main__":
    print_banner()

    # Read Arguments
    args = arg.get_args()

    # Configuration Section
    config_file = args.config
    output_file = args.output
    file_type = args.filetype
    open_port = args.openport
    mx_record = args.mx
    spf_record = args.spf

    # Configuration file
    config = read_config(config_file)
    API = config['API']
    VERBOSE = config['Verbose']
    OPENPORTS = config['Open_Ports']
    UPDATE = config['Update']
    LOG_FILE = config['Logging']['LogFile']
    LOG_LEVEL = config['Logging']['LogLevel']

    # Get optimal vCPU
    optimal_threads = get_cpu_cores()

    # Read the keywords from the file
    keywords_file = args.keywords
    try:
        keywords_list = keywords_read(keywords_file)
    except Exception as e:
        print(f"Error reading keywords file: {e}")
        exit(1)

    # Total keywords count
    keywords_total = keywords_count(keywords_file)

    # Start timer
    start_time = time.time()

    # Fetch domains concurrently
    if API:
        api_key_masked = mask_api_key(API)
        print(f"[*] API Key: {api_key_masked}")
    else:
        cli_print_info("No Authentication - register at https://opensquat.com for higher API queries quotas")

    print("\n\n")
    print("+---------- Execution Parameters ----------+")
    print(f"> Total keywords: {keywords_total}")
    print(f"> Keywords file: {keywords_file}")
    print(f"> Thread concurrency: {optimal_threads}")
    print(f"> Config file: {config_file}")
    print(f"> Verbosity: {VERBOSE}")
    print("\n")

    # Total domains
    counter_queue = multiprocessing.Queue()
    counter_queue.put(1)
    # Total domains MX
    mx_counter_queue = multiprocessing.Queue()
    mx_counter_queue.put(1)
    # Total domains SPF
    spf_counter_queue = multiprocessing.Queue()
    spf_counter_queue.put(1)

    results = query_worker(
        keywords_list,
        max_workers=optimal_threads,
        api_key=API,
        log_level=LOG_LEVEL,
        counter_queue=counter_queue,
        keywords_total=keywords_total
    )
    total_domains = sum(len(entries) for entries in results.values())

    # Check for other validations
    if open_port:
        print("\n+---------- Checking the domains with open ports ----------+")
        results = check_ports_worker(results, OPENPORTS)

    if mx_record:
        print("\n+---------- Validate if found domains contain any MX Record ----------+")
        results = check_mx_records_worker(results)

    if spf_record:
        print("\n+---------- Validate if found domains contain any SPF Record ----------+")
        results = check_spf_records_worker(results)

    # End timer
    end_time = round(time.time() - start_time, 2)

    print("\n")
    print("+---------- Results ----------+")
    print(f"> Total results: {total_domains}")
    print(f"> Running time: {end_time} seconds")
    print(f"> Results file: {output_file}\n")

    save_results(results, output_file, file_type)

    if UPDATE:
        update.CheckUpdate().main()
