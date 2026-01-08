# -*- coding: utf-8 -*-
# Module: port_check.py
"""
openSquat

(c) Andre Tenreiro

* https://github.com/atenreiro/opensquat

software licensed under GNU version 3
"""
import socket
import functools
import concurrent.futures


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
        self.domain = None
        self.sock_timeout = 1

    def set_domain(self, domain):
        self.domain = domain

    def check_socket(self, host, port):
        res = False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.sock_timeout)

        try:
            if sock.connect_ex((host, port)) == 0:
                res = port
        except socket.error:
            pass
        finally:
            sock.close()
            return res

    def connect(self):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futs = [
                (port, executor.submit(functools.partial(self.check_socket, self.domain, port)))
                for port in self.ports
            ]

        for tested_port, result_port in futs:
            if result_port.result():
                self.ports_open.append(tested_port)

        return self.ports_open

    def main(self, domain):
        self.set_domain(domain)
        return self.connect()
