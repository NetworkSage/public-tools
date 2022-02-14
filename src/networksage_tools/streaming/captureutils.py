"""
    Copyright (c) 2021 David Pearson (david@seclarity.io)
    Date: 06/02/2021
    This file contains functions that support capturing exactly what we need and nothing more.

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.

    This file also leverages pcapy-ng, an Apache-licensed package that interfaces with the libpcap packet capture
    library. You can find more details about this repository at https://github.com/stamparm/pcapy-ng.
"""

import re
import os
import sys
import magic
import pcapy
import time
import threading
from collections import deque
from filelock import SoftFileLock, Timeout
from networksage_tools.common_utilities import packet
from networksage_tools.common_utilities import iputils
from networksage_tools.common_utilities import dnsservice
from networksage_wrappers.wrappers import wrappers as networksage

my_api_key_var = "NETWORKSAGE_API_KEY"
api_key = os.environ.get(my_api_key_var)
if api_key is None:
    print("Missing API Key. Please type export NETWORKSAGE_API_KEY='<your_api_key>' in your terminal to set up.")

def create_bpf():
    """This function creates the Berkeley Packet Filter (BPF) capture filter to restrict us from capturing (and
       therefore wasting resources on) types of traffic that are not supported by NetworkSage. The steps are outlined
       below.
    """


    """1. Create a valid BPF snippet to exclude all local protocols (those that communicate only on internal networks,
          or that have sensitive-but-uninteresting [to us] data when communicated externally).
    """
    local_protocols="445 or 5355 or netbios-ssn or netbios-ns or mdns or ldap or ldaps or bootps or bootpc or 1900"

    """2. Create a BPF snippet that confirms that at least one IP address in EVERY conversation is NOT local (still
          only works for IPv4).
    """
    local_to_local_sans_dns="(src net 0.0.0.0/32 or 192.168.0.0/16 or 10.0.0.0/8 or 172.16.0.0/12 or 239.255.255.250/32 or 224.0.0.0/4 or 255.255.255.255/32 or 127.0.0.0/8) and (dst net (0.0.0.0/32 or 192.168.0.0/16 or 10.0.0.0/8 or 172.16.0.0/12 or 239.255.255.250/32 or 224.0.0.0/4 or 255.255.255.255/32 or 127.0.0.0/8)) and not port domain"

    """3. Assemble the full BPF that (in English) does the following:
          MUST be IP and no SMB or any other E-W protocols and no non-DNS local-to-local traffic and no IPv6 (since we
          do not handle IPv6 today).
    """
    bpf_to_apply="ip and ((not port (" + local_protocols + ")) and not (" + local_to_local_sans_dns + ") and not ip6)"
    return bpf_to_apply


def capture(**kwargs):
    """This function takes an interface to capture on and a BPF capture filter and begins capturing as requested.
       Because we work with flow data collected from the IP and Transport layers, we capture a much smaller amount
       of each packet to speed up processing and stay in-memory storage efficient.
    """
    utils=kwargs['utils']
    is_verbose = kwargs['is_verbose']
    # capture just 350 bytes from each packet (some multi-answer DNS packets were being cut short @ 300 bytes)
    capture_handle=pcapy.open_live(kwargs['interface'], 350, 0, 1) # setting the timeout value to -1 is unpredictable, and 0 is waiting forever.
    capture_handle.setfilter(kwargs['bpf'])

    # get the next packet and store it in our buffer
    while not utils.stop_thread:
        (hdr, pkt) = capture_handle.next()
        while hdr is not None and not utils.stop_thread:
            utils.packet_buffer.append((hdr, pkt))
            (hdr, pkt) = capture_handle.next()
    return


def process_packets(**kwargs):
    """Processes our accumulating packet buffer in a FIFO manner. Assigns each packet to the proper Secflow.
    """
    utils = kwargs['utils']
    is_verbose = kwargs['is_verbose']
    first = True # we need to collect timestamp information on the first packet
    dns = dnsservice.DnsService(utils)  # create an instance of the DnsService class to use
    while not utils.stop_thread:
        if len(utils.packet_buffer) > 0:
            packet_data = utils.packet_buffer.popleft() # get the first (hdr, pkt) item -- we want to process in FIFO order
            hdr = packet_data[0]
            pkt = packet_data[1]
            pkt_len = len(pkt)
            if pkt_len <= 34:  # length of IPv4 packet with standard header
                print("Warning: unexpectedly short packet:\n", pkt)
            else:  # maybe legit IPv4 packet
                if first: # collect timing information
                    utils.file_start_time = min(utils.file_start_time, utils.get_timestamp_from_packet_header(hdr))
                    first=False #reset it
                packet_info = packet.PacketInfo(pkt, hdr, utils)  # prep everything for later use
                if packet_info.is_ipv4_by_ip_layer:
                    if packet_info.transport_protocol not in [6, 17, 1]: #TCP, UDP, or ICMP
                        print("Warning, expected UDP, TCP, or ICMP but got this instead:", packet_info.transport_protocol)
                        continue  # something was wrong with this packet
                else:
                    if (pkt[0] == 0 and pkt[4:6] == b"\x00\x06" and pkt[14:16] == b"\x08\x00"):
                        #this IPv4 packet has a Linux-cooked header, so ignore first 2 bytes
                        packet_info = packet.PacketInfo(pkt[2:], hdr, utils) #prep everything for later use
                    else:
                        print("Warning, either something went wrong or this is not an IPv4 packet (handling for which is unimplemented)")
                        continue # skip this session
                """Since we keep local DNS lookups in the streaming version, we need to process them here and NOT save
                   them as a Secflow.
                """
                if iputils.check_if_local_ip(packet_info.dest_ip) and iputils.check_if_local_ip(packet_info.source_ip):
                    if packet_info.is_local_dns_response(pkt):
                        dns.parse_local_lookup_from_packet(packet_info, pkt)
                        continue # we don't want to capture this as a secflow
                    else:
                        #print("Either not DNS (weird...), or a DNS lookup...skipping cataloging of this result")
                        continue
                if packet_info.protocol_information in ["ICMP"]: # handle protocols without layer 4 information specially
                    ip_a_string = packet_info.source_ip + ":" + packet_info.protocol_information
                    ip_b_string = packet_info.dest_ip + ":" + packet_info.protocol_information
                else:
                    ip_a_string = packet_info.source_ip + ":" + packet_info.source_port
                    ip_b_string = packet_info.dest_ip + ":" + packet_info.dest_port
                """Figure out if we've seen either side of the connection already. If we have, we just update the
                   existing Secflow.
                """
                if ip_a_string in utils.secflows.keys():
                    secflow = utils.secflows[ip_a_string]
                elif ip_b_string in utils.secflows.keys():
                    secflow = utils.secflows[ip_b_string]
                elif packet_info.protocol_information in ["ICMP"]:
                    if (ip_a_string + "-" + ip_b_string) in utils.secflows.keys():
                        secflow = utils.secflows[ip_a_string + "-" + ip_b_string]
                    elif ip_b_string+"-"+ip_a_string in utils.secflows.keys():
                        secflow = utils.secflows[ip_b_string + "-" + ip_a_string]
                    else:
                        secflow = packet_info.determine_session_directionality(hdr)
                else:  # we don't yet know, so go figure it out!
                    secflow = packet_info.determine_session_directionality(hdr)
                    if secflow is None:  # local-to-local DNS
                        continue # skip this session
                #print("secflow key is", secflow.key)
                if secflow.key == ip_a_string:  # we're dealing with the source
                    secflow.source_pkts += 1
                    secflow.source_payload_bytes += packet_info.upper_layer_length  # payloadLength
                    secflow.max_ts = max(secflow.max_ts, packet_info.packet_start_time)
                elif secflow.key == ip_b_string:  # we're dealing with the destination
                    secflow.dest_pkts += 1
                    secflow.dest_payload_bytes += packet_info.upper_layer_length  # payloadLength
                    secflow.max_ts = max(secflow.max_ts, packet_info.packet_start_time)
                elif packet_info.protocol_information in ["ICMP"]:
                    if secflow.key == (ip_a_string + "-" + ip_b_string):
                        secflow.source_pkts += 1
                        secflow.source_payload_bytes += packet_info.upper_layer_length  # payloadLength
                        secflow.max_ts = max(secflow.max_ts, packet_info.packet_start_time)
                    elif secflow.key == (ip_b_string + "-" + ip_a_string):
                        secflow.dest_pkts += 1
                        secflow.dest_payload_bytes += packet_info.upper_layer_length  # payloadLength
                        secflow.max_ts = max(secflow.max_ts, packet_info.packet_start_time)
                    else:
                        print("Warning, protocol without upper layer info, but seems to be deformed!")
                        continue
                else:
                    print("Warning, deformed UDP or TCP object suspected!")
                    continue
        else:
            time.sleep(1) # sleep for a second
            continue
    if utils.stop_thread:
        utils.set_secflow_durations()
        dns.get_passive_dns()
        """At this point, we want to see what existing passive DNS information was learned in recent sessions and use
           that first. TO do so, we need to lock the resource associated with the short-term pDNS file so that we don't
           make cleanup modifications to it while editing.
        """
        lock = SoftFileLock(dns.short_term_passive_dns_lock_name)
        try:
            with lock.acquire(timeout=10):
                dns.map_destination_ips_to_names()
                dns.update_passive_dns_repository() # add current file's DNS to the local PDNS file
        except Timeout:
            print("Lock acquisition for cleaning up short-term passive DNS took too long. Something might be wrong.")


def send_sample(**kwargs):
    """This function allows us to send a sample consisting of just unenriched Secflows
       to the NetworkSage uploader.
    """

    utils = kwargs['utils']
    capture_thread = kwargs['capture_thread']
    processing_thread = kwargs['processing_thread']
    is_verbose = kwargs['is_verbose']

    # stop active threads
    utils.stop_thread = True
    processing_thread.join()
    capture_thread.join(3) # we need this to terminate after a few seconds if it's stuck waiting on no packets
    uuid = utils.get_random_uuid()
    utils.set_hash_value_for_sample(uuid)

    """Capture Secflows in JSON format, and store with all information for final transmission
    """
    utils.prepare_final_output_file()

    # check if output file looks sane
    utils.check_output_sanity()

    #print("Conversion complete! Final Secflow Output stored at", utils.secflow_output_filepath)
    if api_key is None:
        print("Would be ready to send", str(len(utils.secflows)), "secflows out to NetworkSage, but no API key present.")
    else:
        with open(utils.secflow_output_filepath, 'rb') as indata:
            sample_data = indata.read()
        sample_type = "secflow"
        if len(utils.secflows) > 0:
            networksage.upload_sample(utils.sample_name, sample_data, sample_type)
            if is_verbose:
                print("Captured", str(len(utils.secflows)), "secflows.")
                print("Uploading sample "+str(uuid)+" to NetworkSage!")
        else:
            if is_verbose:
                print("No secflows captured. Nothing to upload.")
    utils.cleanup_files()
