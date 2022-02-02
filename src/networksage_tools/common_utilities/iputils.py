"""
    Copyright (c) 2021 David Pearson (david@seclarity.io)
    Date: 06/03/2021
    This file contains utility functions that work with IP addresses.

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.

    This file also leverages pcapy-ng, an Apache-licensed package that interfaces with the libpcap packet capture
    library. You can find more details about this repository at https://github.com/stamparm/pcapy-ng.
"""

import ipaddress
import pcapy

def check_if_local_ip(ip_address):
    """Helper function to figure out if the provided IP address is local, private, multicast, etc...
    """
    ip = ipaddress.ip_address(ip_address)
    return ip.is_private or ip.is_multicast or ip.is_loopback or ip.is_link_local  # we only want to work with globally-routable IPs, essentially

def collect_active_external_ips_from_capture_file(utils):
    """We want to know which IP addresses are actually active in a given input file, so we figure that out here. Active
       means that there was actually traffic to/from them, rather than just a DNS lookup that returned that IP
       address.
    """

    if len(utils.active_external_ips) > 0:
        print("Warning: there are already active external IPs stored. Results may differ from expectations.")
    with pcapy.open_offline(utils.filtered_filepath) as capfile:
        (hdr, pkt) = capfile.next()
        while hdr is not None:
            pkt_len = len(pkt)
            if pkt_len >= 34:  # length of IPv4 packet with standard header
                try:
                    if (pkt[0] == 0 and pkt[4:6] == b"\x00\x06" and pkt[14:16] == b"\x08\x00"):
                        #this IPv4 packet has a Linux-cooked header, so ignore first 2 bytes
                        pkt = pkt[2:]
                    ip_a = str(ipaddress.ip_address(pkt[26:30]))
                    ip_b = str(ipaddress.ip_address(pkt[30:34]))
                    if check_if_local_ip(ip_a):
                        pass
                    else:
                        utils.active_external_ips.add(ip_a)
                    if check_if_local_ip(ip_b):
                        pass
                    else:
                        utils.active_external_ips.add(ip_b)
                except:
                    print("IP addresses not found in range", pkt[26:34])
            hdr, pkt = capfile.next()
