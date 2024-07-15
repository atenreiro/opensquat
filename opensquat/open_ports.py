# -*- coding: utf-8 -*-
# Module: open_ports.py
"""
openSquat.

* https://github.com/atenreiro/opensquat

Software licensed under GNU version 3
"""
import socket

# Connection timeout, default 1 second.
CONN_TIMEOUT = 1

def is_port_open(domain, port):
    """
    Check if a specific port on a given domain is open.

    Parameters:
    domain (str): The domain name or IP address to check.
    port (int): The port number to check.

    Returns:
    bool: True if the port is open, False if closed or any error occurs.
    """
    try:
        # Create a new socket using the given address family, socket type and protocol number
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(CONN_TIMEOUT) 
            result = sock.connect_ex((domain, port))
            return result == 0
    except (socket.gaierror, socket.timeout, socket.error):
        return False