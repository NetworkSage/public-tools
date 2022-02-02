"""
    Copyright (c) 2021 David Pearson (david@seclarity.io)
    Date: 06/02/2021
    This file contains utilities that make processing a .cap, .pcap, or .pcapng file easy to do. Ultimately, the final
    function in this file will create secflows out of the incoming capture data.

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.

    This file also leverages pcapy-ng, an Apache-licensed package that interfaces with the libpcap packet capture
    library. You can find more details about this repository at https://github.com/stamparm/pcapy-ng.
"""

import re
import sys
import magic
import pcapy
from networksage_tools.common_utilities import packet

def filter_capture_file_by_bpf(utils, bpf_to_apply):
    """Takes a Berkeley packet filter (BPF) and applies it to the capture file. Whatever remains after the BPF is
       applied will be saved to the output file.
    """

    last_dot = utils.original_filepath.rfind(".")
    if last_dot == -1:  # no extension in file name
        utils.filtered_filepath = utils.original_filepath + "_filtered"
    else:
        utils.filtered_filepath = utils.original_filepath[:last_dot] + "_filtered" + utils.original_filepath[last_dot:]

    capfile = pcapy.open_offline(utils.original_filepath)
    output = capfile.dump_open(utils.filtered_filepath)
    capfile.setfilter(bpf_to_apply)
    (hdr, pkt) = capfile.next()

    while hdr is not None:
        output.dump(hdr, pkt)
        (hdr, pkt) = capfile.next()
    del output


def remove_local_traffic_from_capture_file(utils, dns):
    """Calls most of the functions to prepare and then remove the local traffic from the incoming capture file.
    """

    bpf_to_apply = ""  # set up the empty BPF

    """Remove all of the local/uninteresting traffic
         Steps:

         1. Get all of the DNS queries in form <port> <dns.qry.name> <dns.resp.name>
    """
    dns.parse_dns_records_from_capture_file()

    """2. Identify which of the DNS queries are either local forward or local reverse lookups (looking for
          things in RFC1918 and similar IP address ranges). Note that this currently only works for IPv4.
    """
    local_lookups = dns.collect_local_lookups()

    """3. Create a valid Berkeley Packet Filter (BPF) to exclude all local protocols (those that communicate only on
          internal networks, or that have sensitive-but-uninteresting [to us] data when communicated externally).
    """
    local_protocols = "445 or 5355 or netbios-ssn or netbios-ns or mdns or ldap or ldaps or bootps or bootpc or 1900"

    """4. Create a BPF that confirms that at least one IP address in EVERY conversation is NOT local (still only works
          for IPv4).
    """
    local_to_local_sans_dns = "(src net 0.0.0.0/32 or 192.168.0.0/16 or 10.0.0.0/8 or 172.16.0.0/12 or 239.255.255.250/32 or 224.0.0.0/4 or 255.255.255.255/32 or 127.0.0.0/8) and (dst net (0.0.0.0/32 or 192.168.0.0/16 or 10.0.0.0/8 or 172.16.0.0/12 or 239.255.255.250/32 or 224.0.0.0/4 or 255.255.255.255/32 or 127.0.0.0/8)) and not port domain"

    """5. Create a BPF that excludes DNS resolutions using internal resolvers, and explicitly excludes those
          local lookups (by destination port) that we found earlier.
    """
    dns_prefix = " and not (port domain and (src net 10.0.0.0/8 or 192.168.0.0/16 or 172.16.0.0/12) and (dst net 10.0.0.0/8 or 192.168.0.0/16 or 172.16.0.0/12)"

    dns_expression = ""
    if len(local_lookups) > 0:
        dns_expression += (dns_prefix + " and port (" + "".join(local_lookups) + "))")

    """6. Assemble the full BPF that (in English) does the following:
            MUST be IP and no SMB or any other E-W protocols and no non-DNS local-to-local traffic and no local-to-local
            DNS traffic with local lookups and no IPv6 (since we do not handle IPv6 today).
    """
    bpf_to_apply = "ip and ((not port (" + local_protocols + ")) and not (" + local_to_local_sans_dns + ") " + dns_expression + " and not ip6)"

    """7. Filter the capture file using the assembled BPF, and then return the filtered file location for use in the
          rest of the pipeline.
    """
    filter_capture_file_by_bpf(utils, bpf_to_apply)


def validate_file_format(utils):
    """Validate that the file is of an accepted type (CAP, PCAP, or PCAPNG).
    """

    # check if file is valid
    if not re.match(r"^(p|)cap(|(|\-)ng) capture file", magic.from_file(utils.original_filepath)):
        print("Error:", utils.original_filepath + ",", "of type", magic.from_file(utils.original_filepath),
              "is not an accepted file type.")
        sys.exit(1)


def pcap_to_secflow_converter(utils, dns):
    """Given a capture file that has been validated, remove any local traffic and collect
        the secflows for all TCP, UDP, and ICMP sessions.
    """
    # filter the original file to remove local-to-local traffic
    remove_local_traffic_from_capture_file(utils, dns)

    get_min_timestamp_from_capture_file(utils)

    # get all of the UDP records in place
    parse_secflows_from_capture_file(utils, "udp")

    # get all of the TCP records in place
    parse_secflows_from_capture_file(utils, "tcp")

    # get all of the ICMP records in place
    parse_secflows_from_capture_file(utils, "icmp")


def get_min_timestamp_from_capture_file(utils):
    """Iterates through the file to find the absolute minimum timestamp.
    """
    with pcapy.open_offline(utils.filtered_filepath) as capfile:
        capfile.setfilter("udp or tcp or icmp")
        (hdr, pkt) = capfile.next()
        while hdr is not None:
            # update start time with the actual file min
            utils.file_start_time = min(utils.file_start_time, utils.get_timestamp_from_packet_header(hdr))
            (hdr, pkt) = capfile.next()


def parse_secflows_from_capture_file(utils, protocol):
    """Takes a capture file and a transport protocol, parses all relevant packets to find the directionality of the
       sessions to which they belong, and then creates and returns an ordered dictionary of secflows.
    """
    with pcapy.open_offline(utils.filtered_filepath) as capfile:
        if not re.match("^(tc|ud|icm)p$", protocol):
            print("Error, protocol", protocol, "not supported!")
            sys.exit(1)
        capfile.setfilter(protocol)
        (hdr, pkt) = capfile.next()
        while hdr is not None:
            # we should only be getting TCP, UDP, or ICMP records now, so parse accordingly
            pkt_len = len(pkt)
            if pkt_len <= 34:  # length of IPv4 packet with standard header
                print("Warning: unexpectedly short packet:\n", pkt)
            else:  # maybe legit IPv4 packet
                packet_info = packet.PacketInfo(pkt, hdr, utils)  # prep everything for later use
                if packet_info.is_ipv4_by_ip_layer:
                    if packet_info.transport_protocol not in [6, 17, 1]: # TCP, UDP, or ICMP
                        print("Warning, expected UDP, TCP, or ICMP but got this instead:", packet_info.transport_protocol)
                        continue  # something was wrong with this packet
                else:
                    if (pkt[0] == 0 and pkt[4:6] == b"\x00\x06" and pkt[14:16] == b"\x08\x00"):
                        #this IPv4 packet has a Linux-cooked header, so ignore first 2 bytes
                        packet_info = packet.PacketInfo(pkt[2:], hdr, utils) #prep everything for later use
                    else:
                        print("Warning, either something went wrong or this is not an IPv4 packet (handling for which is unimplemented)")
                        (hdr, pkt) = capfile.next() #skip this session
                        continue

                if packet_info.protocol_information in ["ICMP"]: # handle protocols without layer 4 information specially
                    ip_a_string = packet_info.source_ip + ":" + packet_info.protocol_information
                    ip_b_string = packet_info.dest_ip + ":" + packet_info.protocol_information
                else:
                    ip_a_string = packet_info.source_ip + ":" + packet_info.source_port
                    ip_b_string = packet_info.dest_ip + ":" + packet_info.dest_port
                #print("Checking", ip_a_string, "and", ip_b_string)

                """ Figure out if we've seen either side of the connection already. If we have, we just update the existing secflow.
                """
                if ip_a_string in utils.secflows.keys():
                    secflow = utils.secflows[ip_a_string]
                elif ip_b_string in utils.secflows.keys():
                    secflow = utils.secflows[ip_b_string]
                elif packet_info.protocol_information in ["ICMP"]:
                    if (ip_a_string + "-" + ip_b_string) in utils.secflows.keys():
                        secflow = utils.secflows[ip_a_string + "-" + ip_b_string]
                    elif ip_b_string + "-" + ip_a_string in utils.secflows.keys():
                        secflow = utils.secflows[ip_b_string + "-" + ip_a_string]
                    else:
                        secflow = packet_info.determine_session_directionality(hdr)
                else:  # we don't yet know, so go figure it out!
                    secflow = packet_info.determine_session_directionality(hdr)
                    if secflow is None:  # local-to-local DNS
                        (hdr, pkt) = capfile.next()  # skip this session
                        continue
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
            (hdr, pkt) = capfile.next()
