#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# opensquat.py
"""
openSquat.

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import time
import signal
import functools
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning

import os
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v2.api.logs_api import LogsApi
from datadog_api_client.v2.model.http_log_item import HTTPLogItem
from datadog_api_client.v2.api.metrics_api import MetricsApi
from datadog_api_client.v2.model.metric_payload import MetricPayload
from datadog_api_client.v2.model.metric_series import MetricSeries
from datadog_api_client.v2.model.metric_point import MetricPoint

from colorama import init, Fore, Style
from opensquat import __VERSION__, vt
from opensquat import arg_parser, output, app, phishing, check_update
from opensquat import port_check

# For sending to Datadog
def send_to_datadog_logs(args, summary_data):
    """
    Sends a summary of the opensquat run to Datadog Logs.
    """
    if "DD_API_KEY" not in os.environ:
        print(Fore.RED + "[Error] DD_API_KEY environment variable not set. Skipping Datadog submission." + Style.RESET_ALL)
        return

    configuration = Configuration()
    with ApiClient(configuration) as api_client:
        api_instance = LogsApi(api_client)

        log_payload = HTTPLogItem(
            ddsource="opensquat",
            ddtags=f"keywords:{','.join(args.keywords)},confidence:{args.confidence}",
            hostname=os.uname().nodename,
            service="security-monitoring",
            message=f"openSquat scan summary: Found {summary_data['domains_flagged']} flagged domains.",
            attributes={
                "run_args": vars(args),
                "summary": summary_data,
                "flagged_domains": summary_data['flagged_domains_list'],
                "phishing_sites": summary_data.get('phishing_sites_list', [])
            }
        )

        try:
            from datadog_api_client.v2.model.http_log import HTTPLog
            http_log = HTTPLog([log_payload])
            api_instance.submit_log(body=http_log)
            print(Fore.GREEN + "[*] Successfully sent log summary to Datadog." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[Error] Failed to send log to Datadog: {e}" + Style.RESET_ALL)

def send_to_datadog_metrics(args, summary_data):
    """
    Sends key metrics from the opensquat run to Datadog.
    """
    if "DD_API_KEY" not in os.environ:
        # You can silence this if the log function already warned the user
        return

    configuration = Configuration()
    with ApiClient(configuration) as api_client:
        api_instance = MetricsApi(api_client)
        
        # It's good practice to get the current time for the metric timestamp
        current_time = int(time.time())
        
        # Define the tags that will be applied to all metrics in this run
        metric_tags = [
            f"target_keywords:{','.join(args.keywords)}",
            f"confidence:{args.confidence}"
        ]

        # Fix: Use proper MetricIntakeType enum values
        from datadog_api_client.v2.model.metric_intake_type import MetricIntakeType

        # Define the metrics you want to send
        body = MetricPayload(
            series=[
                MetricSeries(
                    metric="opensquat.domains.flagged",
                    type=MetricIntakeType.GAUGE,
                    points=[MetricPoint(timestamp=current_time, value=float(summary_data['domains_flagged']))],
                    tags=metric_tags,
                ),
                MetricSeries(
                    metric="opensquat.phishing.found",
                    type=MetricIntakeType.GAUGE,
                    points=[MetricPoint(timestamp=current_time, value=float(summary_data['phishing_sites_found']))],
                    tags=metric_tags,
                ),
                MetricSeries(
                    metric="opensquat.run.duration_seconds",
                    type=MetricIntakeType.GAUGE,
                    points=[MetricPoint(timestamp=current_time, value=summary_data['running_time_seconds'])],
                    tags=metric_tags,
                ),
            ]
        )

        try:
            api_instance.submit_metrics(body=body)
            print(Fore.GREEN + "[*] Successfully sent metrics to Datadog." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[Error] Failed to send metrics to Datadog: {e}" + Style.RESET_ALL)

def signal_handler(sig, frame):
    """Function to catch CTR+C and terminate."""
    print("\n[*] openSquat is terminating...\n")
    exit(0)

if __name__ == "__main__":

    signal.signal(signal.SIGINT, signal_handler)

    init()

    RED, WHITE, GREEN, END, YELLOW, BOLD = (
        "\033[91m",
        "\33[97m",
        "\033[1;32m",
        "\033[0m",
        "\33[93m",
        "\033[1m",
    )

    logo = (
        Style.BRIGHT + Fore.GREEN +
        """
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
                    (c) Andre Tenreiro - https://github.com/atenreiro/opensquat
    """ + Style.RESET_ALL
    )

    print(logo)
    print("\t\t\tversion " + __VERSION__ + "\n")

    args = arg_parser.get_args()

    start_time_squatting = time.time()

    file_content = app.Domain().main(
        args.keywords,
        args.confidence,
        args.domains,
        args.period,
        args.method,
        args.dns,
        args.ct
    )

    if args.subdomains or args.vt or args.subdomains or args.phishing \
        or args.portcheck:
        print("\n[*] Total found:", len(file_content))

    # Check for subdomains
    if (args.subdomains):
        list_aux = []
        print("\n+---------- Checking for Subdomains ----------+")
        time.sleep(1)
        for domain in file_content:
            print("[*]", domain)
            subdomains = vt.VirusTotal().main(domain, "subdomains")

            if subdomains:
                for subdomain in subdomains:
                    print(
                        f"{Style.BRIGHT}{Fore.YELLOW} \\_{subdomain}{Style.RESET_ALL}"
                    )
                    list_aux.append(subdomain)
        file_content = list_aux
        print("[*] Total found:", len(file_content))

    # Check for VirusTotal (if domain is flagged as malicious)
    if (args.vt):
        list_aux = []
        print("\n+---------- VirusTotal ----------+")
        time.sleep(1)
        for domain in file_content:
            total_votes = vt.VirusTotal().main(domain)

            # Check if total_votes is not None before accessing
            if total_votes is not None:
                # total votes
                harmless = total_votes[0]
                malicious = total_votes[1]

                if malicious > 0:
                    print(
                        Style.BRIGHT + Fore.RED +
                        "[*] found: " + domain + " (" + str(malicious) + ")" +
                        Style.RESET_ALL,
                        )
                    list_aux.append(domain)
                elif malicious < 0:
                    print(
                        Style.BRIGHT + Fore.YELLOW +
                        "[*] VT is throttling the response:", domain +
                        Style.RESET_ALL,
                        )
                    list_aux.append(domain)
            else:
                print(
                    Style.BRIGHT + Fore.YELLOW +
                    "[*] VT returned no data for:", domain +
                    Style.RESET_ALL,
                    )
        file_content = list_aux
        print("[*] Total found:", len(file_content))

    # Check for phishing
    if (args.phishing != ""):
        file_phishing = phishing.Phishing().main(args.keywords)
        output.SaveFile().main(args.phishing, "txt", file_phishing)

    # Check if domain has webserver port opened
    if (args.portcheck):
        list_aux = []
        print("\n+---------- Domains with open webserver ports ----------+")
        time.sleep(1)
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futs = [ (domain, executor.submit(functools.partial(port_check.PortCheck().main, domain)))
                for domain in file_content ]
        
        for tested_domain, result_domain_port_check in futs:
            ports = result_domain_port_check.result()
            if ports:
                list_aux.append(tested_domain)
                print(
                    Fore.YELLOW +
                    "[*]", tested_domain, ports, "" +
                    Style.RESET_ALL
                    )
        
        file_content = list_aux
        print("[*] Total found:", len(file_content))

    output.SaveFile().main(args.output, args.type, file_content)
    end_time_squatting = round(time.time() - start_time_squatting, 2)

    # Print summary
    print("\n")
    print(
        Style.BRIGHT+Fore.GREEN +
        "+---------- Summary Squatting ----------+" +
        Style.RESET_ALL)

    print("[*] Domains flagged:", len(file_content))
    print("[*] Domains result:", args.output)

    if (args.phishing != ""):
        print("[*] Phishing results:", args.phishing)
        print("[*] Active Phishing sites:", len(file_phishing))

    print("[*] Running time: %s seconds" % end_time_squatting)
    print("")
    print("\n")
    print(
        Style.BRIGHT+Fore.GREEN +
        "+---------- Summary Squatting ----------+" +
        Style.RESET_ALL)

    print("[*] Domains flagged:", len(file_content))
    print("[*] Domains result:", args.output)

    if (args.phishing != ""):
        print("[*] Phishing results:", args.phishing)
        print("[*] Active Phishing sites:", len(file_phishing))
    else:
        # Define file_phishing if the block doesn't run to avoid reference errors
        file_phishing = []


    print("[*] Running time: %s seconds" % end_time_squatting)
    print("")

    # --- START NEW DATADOG INTEGRATION ---
    # Create a dictionary with all the data for Datadog
    summary_for_datadog = {
        "domains_flagged": len(file_content),
        "running_time_seconds": end_time_squatting,
        "phishing_sites_found": len(file_phishing),
        "flagged_domains_list": file_content, # This is the main list of domains
        "phishing_sites_list": file_phishing,
    }
    
    # Send the data
    send_to_datadog_logs(args, summary_for_datadog)
    send_to_datadog_metrics(args, summary_for_datadog)
    # --- END NEW DATADOG INTEGRATION ---

    check_update.CheckUpdate().main()
