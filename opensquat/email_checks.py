# -*- coding: utf-8 -*-
# Module: email_checks.py
"""
openSquat.

* https://github.com/atenreiro/opensquat

Software licensed under GNU version 3
"""
import dns.resolver
import logging
import os

# Socket connection timeout (seconds)
CONN_TIMEOUT = 2 

# Configure logging
log_dir = "logs"
log_file = os.path.join(log_dir, "opensquat.log")
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    filename=log_file,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.WARNING
)


def has_spf_record(domain):
    """
    Check if the domain has an SPF record.

    Args:
        domain (str): The domain name to check.

    Returns:
        str: The SPF record if it exists, False otherwise.
    """
    try:
        # Perform DNS query for TXT records
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=CONN_TIMEOUT)
        for rdata in answers:
            for txt_string in rdata.strings:
                if txt_string.startswith(b'v=spf1'):
                    return txt_string.decode()
        return False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        # No TXT record found or domain does not exist
        return False
    except (dns.resolver.Timeout, dns.exception.DNSException) as e:
        # Handle other DNS exceptions
        logging.error(f"An error occurred while checking SPF record for domain {domain}: {e}")
        return False
    
def has_mx_record(domain):
    """
    Check if the domain has an MX record.

    Args:
        domain (str): The domain name to check.

    Returns:
        bool: True if the domain has an MX record, False otherwise.
    """
    try:
        # Perform DNS query for MX records
        answers = dns.resolver.resolve(domain, 'MX', lifetime=CONN_TIMEOUT)
        return True if answers else False
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        # No MX record found or domain does not exist
        return False
    except (dns.resolver.Timeout, dns.exception.DNSException) as e:
        # Handle other DNS exceptions
        logging.error(f"An error occurred while checking MX record for domain {domain}: {e}")
        return False
