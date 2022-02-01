"""
    Copyright (c) 2021 David Pearson (david@seclarity.io)
    Date: 06/03/2021
    This file contains utility functions that work with IP addresses.

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.
"""

import ipaddress

def check_if_local_ip(ip_address):
    """Helper function to figure out if the provided IP address is local, private, multicast, etc...
    """
    ip = ipaddress.ip_address(ip_address)
    return ip.is_private or ip.is_multicast or ip.is_loopback or ip.is_link_local  # we only want to work with globally-routable IPs, essentially