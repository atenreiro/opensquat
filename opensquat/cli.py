#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Module: cli.py
"""
openSquat CLI entry point.

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import time
import signal
import functools
import concurrent.futures

from colorama import init, Fore, Style
from opensquat import __VERSION__, vt
from opensquat import arg_parser, output, app, phishing, check_update
from opensquat import ct, port_check
from opensquat.app import ApiOptions


# crt.sh is slow and flaps 5xx under load. After this many consecutive
# indeterminate lookups, stop querying and keep the remaining domains
# unfiltered rather than serialising a timeout per domain.
CT_FAILURE_LIMIT = 5


def signal_handler(sig, frame):
    """Function to catch CTR+C and terminate."""
    print("\n[*] openSquat is terminating...\n")
    exit(0)


def _serialize_domain(d):
    """
    Serialize a LookalikeDomain into a JSON-friendly dict.

    Optional fields (tld, date, unicode) are omitted when they're None so
    the output stays compact. `idn` is always emitted, even when False,
    because the boolean presence is informative: it tells consumers the
    tool checked and the domain is not a homograph (vs. not having the
    information at all, which is what community/feed modes look like).
    """
    out = {"domain": d.domain}
    if d.tld is not None:
        out["tld"] = d.tld
    if d.date is not None:
        out["date"] = d.date
    out["idn"] = d.idn
    if d.idn and d.unicode is not None:
        out["unicode"] = d.unicode
    return out


def _build_json_content(scanner, filtered_set):
    """
    Build the JSON output structure: a list of per-keyword objects, each
    with a "domains" array of {"domain": ..., ...} dicts.

    In Premium API mode, scanner.keyword_domains_meta carries rich
    LookalikeDomain objects and the output includes tld/date/idn/unicode
    fields. In community/feed modes, only the bare domain string is
    emitted as {"domain": ...}, keeping the top-level shape consistent
    across all three modes.
    """
    json_content = []
    meta = getattr(scanner, "keyword_domains_meta", {}) or {}
    for kw, doms in scanner.keyword_domains.items():
        if kw in meta:
            rich = [d for d in meta[kw] if d.domain in filtered_set]
            if rich:
                json_content.append({
                    "keyword": kw,
                    "domains": [_serialize_domain(d) for d in rich],
                })
        else:
            filtered_doms = [d for d in doms if d in filtered_set]
            if filtered_doms:
                json_content.append({
                    "keyword": kw,
                    "domains": [{"domain": d} for d in filtered_doms],
                })
    return json_content


def _build_csv_rows(scanner, filtered_set):
    """
    Build the CSV output rows: a header row followed by one data row
    per domain. Premium API mode populates the metadata columns from
    LookalikeDomain objects; community/feed modes leave them empty.
    """
    rows = [["keyword", "domain", "tld", "first_seen", "is_idn", "unicode"]]
    meta = getattr(scanner, "keyword_domains_meta", {}) or {}
    for kw, doms in scanner.keyword_domains.items():
        if kw in meta:
            for d in meta[kw]:
                if d.domain in filtered_set:
                    rows.append([
                        kw,
                        d.domain,
                        d.tld or "",
                        d.date or "",
                        "true" if d.idn else "false",
                        d.unicode or "",
                    ])
        else:
            for dom in doms:
                if dom in filtered_set:
                    rows.append([kw, dom, "", "", "", ""])
    return rows


def _filter_by_certificate_transparency(domains):
    """
    Narrow `domains` to those NOT confirmed to hold Certificate
    Transparency logs, matching the "no CT logs is the suspicious signal"
    semantic the doppelganger path already uses.

    Fails open on purpose. CRTSH.check_certificate() is tri-state, and an
    indeterminate result (crt.sh unreachable or erroring) is not evidence
    that a domain is clean — so those domains are KEPT. Only a positive
    "certificates found" answer clears a domain out of the results.

    Stops querying after CT_FAILURE_LIMIT consecutive indeterminate
    lookups and keeps everything remaining: when crt.sh is down, one
    message is more useful than a timeout per domain.

    Args:
        domains: list of domain strings to check.

    Return:
        list: the domains that were not cleared.
    """
    kept = []
    consecutive_failures = 0
    aborted = False

    for index, domain in enumerate(domains):
        if aborted:
            kept.append(domain)
            continue

        status = ct.CRTSH.check_certificate(domain)

        if status is None:
            consecutive_failures += 1
            kept.append(domain)
            print(
                Fore.YELLOW +
                f"[*] CT check unavailable, keeping: {domain}" +
                Style.RESET_ALL
            )
            if consecutive_failures >= CT_FAILURE_LIMIT:
                aborted = True
                remaining = len(domains) - index - 1
                print(
                    Style.BRIGHT + Fore.YELLOW +
                    f"[!] crt.sh unavailable after {CT_FAILURE_LIMIT} "
                    f"consecutive failures - skipping CT checks for the "
                    f"remaining {remaining} domain(s)" +
                    Style.RESET_ALL
                )
            continue

        consecutive_failures = 0
        if status:
            print(Fore.GREEN + f"[*] CT logs found: {domain}" + Style.RESET_ALL)
        else:
            print(
                Style.BRIGHT + Fore.RED +
                f"[*] No CT logs (suspicious): {domain}" +
                Style.RESET_ALL
            )
            kept.append(domain)

    return kept


def _print_mode_summary(mode, scanner):
    """Print the mode-specific lines of the run summary."""
    if mode == "premium_feed":
        print("[*] Mode: Premium Feed")
        return
    if mode != "premium_api":
        return
    print("[*] Mode: Premium API")

    # If the run was cut short (rate limit or quota exhaustion), show the
    # shortfall ratio so the user can tell at a glance that not every
    # requested keyword was processed.
    total = scanner.keywords_total
    made = scanner.api_calls_made
    if total and made < total:
        print(f"[*] API calls made: {made} (of {total})")
    else:
        print("[*] API calls made:", made)

    if scanner.api_balance is not None:
        initial = scanner.api_balance_initial
        if initial is not None and initial > scanner.api_balance:
            used = initial - scanner.api_balance
            print(
                "[*] API balance remaining:",
                f"{scanner.api_balance} (used {used} of {initial} this run)"
            )
        else:
            print("[*] API balance remaining:", scanner.api_balance)

    # Reason line when the run ended early. rate_limited is transient and
    # shown in yellow; quota exhaustion is shown in red and implied by the
    # forced-zero balance above.
    if scanner.rate_limited:
        print(
            Style.BRIGHT + Fore.YELLOW +
            "[*] Rate limit hit - wait a few seconds before retrying "
            "the remaining keywords" +
            Style.RESET_ALL
        )
    elif total and made < total and scanner.api_balance == 0:
        print(
            Style.BRIGHT + Fore.RED +
            "[*] Quota exhausted - upgrade your plan or wait for the "
            "monthly reset" +
            Style.RESET_ALL
        )


def main():
    signal.signal(signal.SIGINT, signal_handler)

    init()

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
                    (c) openSquat - https://opensquat.com
    """ + Style.RESET_ALL
    )

    print(logo)
    print("\t\t\tversion " + __VERSION__ + "\n")

    args = arg_parser.get_args()

    # Usability hint: if the user provided --api-key but didn't pick a mode
    # that uses it, tell them it's being ignored. Don't auto-switch modes.
    if args.mode == "community" and args.api_key:
        print(
            Style.BRIGHT + Fore.YELLOW +
            "[!] --api-key was provided but no mode that uses it was selected.\n"
            "    Running in community mode; the key will be ignored.\n"
            "    Add --premium (to download the paid feed) or --api (to query\n"
            "    the lookalike REST API) to use it." +
            Style.RESET_ALL
        )

    # Mode-specific incompatibilities (early-fail before any work)
    if args.mode == "premium_api" and args.doppelganger:
        print(
            Style.BRIGHT + Fore.RED +
            "[ERROR] --doppelganger is incompatible with --api.\n"
            "        --doppelganger runs local substring matching plus per-domain "
            "HTTP and CT\n"
            "        checks on a candidate set produced from a downloaded feed. "
            "The API\n"
            "        replaces candidate-set generation and does not return "
            "doppelganger\n"
            "        candidates. Workaround: omit --api to run doppelganger "
            "against the\n"
            "        local feed." +
            Style.RESET_ALL
        )
        exit(-1)

    if args.mode == "premium_api" and args.domains:
        print(
            Style.BRIGHT + Fore.RED +
            "[ERROR] -d/--domains is incompatible with --api. "
            "API mode does not read a local feed." +
            Style.RESET_ALL
        )
        exit(-1)

    start_time_squatting = time.time()

    api_options = None
    if args.mode == "premium_api":
        api_options = ApiOptions(
            api_key=args.resolved_api_key,
            fuzziness=args.api_fuzziness,
            history_days=args.api_history_days,
            max_results=args.api_max_results,
            rate_limit=args.api_rate_limit,
        )

    domain_scanner = app.Domain()
    file_content = domain_scanner.main(
        args.keywords,
        args.confidence,
        args.domains,
        args.dns,
        doppelganger_only=args.doppelganger,
        feed_url=args.url,
        mode=args.mode,
        api_options=api_options,
        premium_api_key=args.resolved_api_key if args.mode == "premium_feed" else None,
    )

    if args.subdomains or args.vt or args.ct or args.phishing or args.portcheck:
        print("\n[*] Total found:", len(file_content))

    # Check for subdomains
    if (args.subdomains):
        list_aux = []
        print("\n+---------- Checking for Subdomains ----------+")
        time.sleep(1)
        for domain in file_content:
            print("[*]", domain)
            subdomains = vt.VirusTotal().main(domain, mode="subdomains")

            if subdomains:
                for subdomain in subdomains:
                    print(
                        Style.BRIGHT + Fore.YELLOW +
                        " \\_", subdomain +
                        Style.RESET_ALL,
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

            # total_votes layout: (harmless, malicious). We only act on the
            # malicious count; the harmless count is unused but kept in the
            # tuple to preserve the vt.VirusTotal.main() return contract.
            malicious = total_votes[1]

            if malicious > 0:
                print(
                    Style.BRIGHT + Fore.RED +
                    "[*] found:", domain, "({})".format(str(malicious)) +
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
        file_content = list_aux
        print("[*] Total found:", len(file_content))

    # Check Certificate Transparency logs
    if (args.ct):
        print("\n+---------- Certificate Transparency ----------+")
        time.sleep(1)
        file_content = _filter_by_certificate_transparency(file_content)
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
            futs = [(domain, executor.submit(functools.partial(port_check.PortCheck().main, domain)))
                    for domain in file_content]

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

    if args.type == "json":
        filtered_set = set(file_content)
        json_content = _build_json_content(domain_scanner, filtered_set)
        output.SaveFile().main(args.output, args.type, json_content)
    elif args.type == "csv":
        filtered_set = set(file_content)
        rows = _build_csv_rows(domain_scanner, filtered_set)
        output.SaveFile().main(args.output, args.type, rows)
    else:
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

    _print_mode_summary(args.mode, domain_scanner)

    if (args.phishing != ""):
        print("[*] Phishing results:", args.phishing)
        print("[*] Active Phishing sites:", len(file_phishing))

    print("[*] Running time: %s seconds" % end_time_squatting)
    print("")

    check_update.CheckUpdate().main()


if __name__ == "__main__":
    main()
