# -*- coding: utf-8 -*-
# Module: port_check.py
"""
openSquat

(c) CERT-MZ

* https://www.cert.mz
* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import socket


class PortCheck:
    """
    This domain class verifies if a port for a number is open or not

    To use:
        PortCheck.main("opensquat.com")

    Attribute:
        domain: The URL
    """

    def __init__(self):
        """Initiator."""
        self.ports = [80, 443]
        self.ports_open = []
        self.host = None
        self.sock_timeout = 1

    def set_url(self, domain):
        self.URL = domain

    def check_socket(self, host, port):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.sock_timeout)

        try:

            if sock.connect_ex((host, port)) == 0:
                return port
            else:
                return False

        except socket.error:
            return False

    def connect(self):

        for port in self.ports:
            if self.check_socket(self.URL, port):
                self.ports_open.append(port)

        return self.ports_open

    def main(self, domain):
        self.set_url(domain)

        return self.connect()
