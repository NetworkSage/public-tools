"""
    Copyright (c) 2021 David Pearson (david@seclarity.io)
    Date: 06/03/2021
    This file contains the PacketInfo class, which allows us to take a network packet as input and calculate all
    relevant information needed to make correct decisions on IP, TCP, and UDP data.

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.
"""

import ipaddress
from networksage_tools.common_utilities import iputils
from networksage_tools.common_utilities import secflow

class PacketInfo():
    def __init__(self, pkt, packet_header, utils):
        """Store/Calculate relevant fields
        """
        self.packet_start_time = float(str(packet_header.getts()[0]) + "." + str(packet_header.getts()[1]).zfill(
            6))  # unix seconds.microseconds format
        self.is_ipv4_by_ethernet_layer = (pkt[12:14] == b"\x08\x00")
        self.is_ipv4_by_ip_layer = (((pkt[14] ^ 64) >> 4) == 0)
        self.ip_layer_header_length = ((pkt[14] ^ 64) * 4)
        self.ip_layer_length_field = int.from_bytes(pkt[16:18], "big")
        self.transport_protocol = pkt[23]  # 6 for TCP, 17 for UDP
        self.source_ip = str(ipaddress.ip_address(pkt[26:30]))
        self.dest_ip = str(ipaddress.ip_address(pkt[30:34]))
        self.transport_layer_start = 34 + self.ip_layer_header_length - 20
        self.source_port = str(int.from_bytes(pkt[self.transport_layer_start : self.transport_layer_start + 2], "big"))
        self.dest_port = str(int.from_bytes(pkt[self.transport_layer_start + 2 : self.transport_layer_start + 4], "big"))
        self.protocol_information = ""
        if self.transport_protocol == 6:  # TCP
            self.tcp_header_length = ((pkt[self.transport_layer_start + 12] >> 4) * 4)
            self.upper_layer_length = self.ip_layer_length_field - self.ip_layer_header_length - self.tcp_header_length
            self.upper_layer_start = 14 + self.ip_layer_header_length + self.tcp_header_length
        elif self.transport_protocol == 17:  # UDP
            self.udp_full_length = int.from_bytes(pkt[self.transport_layer_start + 4 : self.transport_layer_start + 6], "big")
            self.upper_layer_length = self.udp_full_length - 8  # 8 is always the length of the UDP header
            self.upper_layer_start = 14 + self.ip_layer_header_length + 8
        elif self.transport_protocol == 1: # ICMP, which doesn't have a transport layer
            self.source_port = ""
            self.dest_port = ""
            self.protocol_information = "ICMP"
            self.transport_layer_length = 0
            self.upper_layer_length = 0
        else:  # something is wrong
            self.transport_layer_length = -1
            self.upper_layer_length = -1
        if utils is None:  # shouldn't happen
            self.utils = utilities.Utilities("", " ")
        else:
            self.utils = utils

    def determine_session_directionality(self, hdr):
        """Determines which side of a given not-yet-identified session is the source vs. the destination based on the
            provided packet. Incoming data will look like the following:
                self.source_ip: "1.2.3.4"
                self.dest_ip: "8.7.6.5"
                self.source_port: "55"
                self.dest_port: "3333"
            Even though the information is labeled source and dest, we don't actually know which is the source/dest for
            the entire session (this data is labeled as source/dest from the CURRENT PACKET). Therefore, the source
            items are relabeled as the "A" side of the session to which this packet belongs, while the dest items are
            the "B" side. Those packets (if written out in a line) would look something like:
                ip_a:port_a > ip_b:port_b <some other data>

            The directionality logic comes from knowledge of relevant RFCs plus experience with common session behavior
            on the Internet.
        """

        side_a = self.source_ip + ":" + self.source_port
        side_b = self.dest_ip + ":" + self.dest_port
        if iputils.check_if_local_ip(str(self.source_ip)):
            if iputils.check_if_local_ip(str(self.dest_ip)):
                # both sides are local; should only occur when it's DNS that we needed earlier
                return None
            if self.source_port == "" and self.protocol_information in ["ICMP"]:
                """ICMP is treated specially, since it doesn't have a port number...so we need to save the whole
                   source/dest IP pair in addition to the protocol information. Additionally, we already know that the
                   source IP of this packet is local, so we'll set it as the source
                """
                object = secflow.Secflow(side_a + self.protocol_information + "-" + side_b + self.protocol_information
                                        , self.source_port
                                        , self.dest_ip
                                        , self.dest_port
                                        , hdr
                                        , self.utils.file_start_time
                                        , self.protocol_information
                                        )
                self.utils.secflows[side_a + self.protocol_information + "-" + side_b + self.protocol_information] = object
                return self.utils.secflows[side_a + self.protocol_information + "-" + side_b + self.protocol_information]
            if int(self.source_port) > 49151:
                """Source IP is local and has an ephemeral port, so create a new secflow object, store it in our
                    Secflows dictionary, and return it.
                """
                object = secflow.Secflow(side_a
                                        , self.source_port
                                        , self.dest_ip
                                        , self.dest_port
                                        , hdr
                                        , self.utils.file_start_time
                                        , self.protocol_information
                                        )
                self.utils.secflows[side_a] = object
                return self.utils.secflows[side_a]
            else:
                """The source IP of this packet is local AND has well-known or registered port, and the destination IP
                    of this packet is NOT LOCAL (we know for sure via check in line # 75 above). So now try to figure 
                    out if this is actually the first packet of an internal-to-external session, or if we're seeing an
                    in-progress external-to-internal session. This analysis will necessarily have to be done based on
                    port numbers and is fallible.
                """
                if int(self.dest_port) > 49151:
                    """Destination IP of this packet is NOT local and has ephemeral port, so it's likely the source of 
                        an external-to-internal session.
                    """
                    object = secflow.Secflow(side_b
                                            , self.dest_port
                                            , self.source_ip
                                            , self.source_port
                                            , hdr
                                            , self.utils.file_start_time
                                            , self.protocol_information
                                            )
                    self.utils.secflows[side_b] = object
                    return self.utils.secflows[side_b]
                """Here we already know that this packet's source IP is local, the dest IP is not local, the source
                   port is not ephemeral, and the dest port is not ephemeral...so now we should determine if the
                   destination's port is well-known. If it is, then it's more than likely the destination. If it's not, 
                   then we should default to making the local IP (AKA the source IP of this packet) the source.
                """
                if int(self.dest_port) < 1024:
                    object = secflow.Secflow(side_a
                                            , self.source_port
                                            , self.dest_ip
                                            , self.dest_port
                                            , hdr
                                            , self.utils.file_start_time
                                            , self.protocol_information
                                            )
                    self.utils.secflows[side_a] = object
                    return self.utils.secflows[side_a]
                else:
                    """Both have ephemeral ports, and we see this packet first. The source of this packet has a local
                        source IP and a non-local destination IP. So whichever port is lower should be the destination.
                        IF both ports are the same, the source of this packet should be the session source (since we 
                        have no way of knowing better).
                    """
                    if int(self.dest_port) > int(self.source_port):
                        # dest port is higher, so it's treated as the source
                        object = secflow.Secflow(side_b
                                                 , self.dest_port
                                                 , self.source_ip
                                                 , self.source_port
                                                 , hdr
                                                 , self.utils.file_start_time
                                                 , self.protocol_information
                                                 )
                        self.utils.secflows[side_b] = object
                        return self.utils.secflows[side_b]
                    else:
                        # both ports are the same OR the source is higher, so source of this packet treated as the source
                        object = secflow.Secflow(side_a
                                                 , self.source_port
                                                 , self.dest_ip
                                                 , self.dest_port
                                                 , hdr
                                                 , self.utils.file_start_time
                                                 , self.protocol_information
                                                 )
                        self.utils.secflows[side_a] = object
                        return self.utils.secflows[side_a]
        else:  # first IP is not a local IP, so check the second IP in the line
            """ICMP is treated specially, since it doesn't have a port number...so we need to save the whole
               source/dest IP pair in addition to the protocol information.
            """
            if self.dest_port == "" and self.protocol_information in ["ICMP"]:
                if not iputils.check_if_local_ip(str(self.dest_ip)):
                    """Neither IP for this packet is local, and we saw this packet first, so we'll set it as the source.
                    """
                    object = secflow.Secflow(side_a + self.protocol_information + "-" + side_b + self.protocol_information
                                            , self.source_port
                                            , self.dest_ip
                                            , self.dest_port
                                            , hdr
                                            , self.utils.file_start_time
                                            , self.protocol_information
                                            )
                    self.utils.secflows[side_a + self.protocol_information + "-" + side_b + self.protocol_information] = object
                    return self.utils.secflows[side_a + self.protocol_information + "-" + side_b + self.protocol_information]
                else:
                    object = secflow.Secflow(side_b + self.protocol_information + "-" + side_a + self.protocol_information
                                            , self.dest_port
                                            , self.source_ip
                                            , self.source_port
                                            , hdr
                                            , self.utils.file_start_time
                                            , self.protocol_information
                                            )
                    self.utils.secflows[side_b] = object
                    return self.utils.secflows[side_b]
            """Source IP is NOT a local IP. So at this point, the first packet we see in the session could either be
                external-to-internal OR we're capturing a packet from the destination of an in-progress session. Either
                way, we know at least one of the sides is not local, so we'll process the flow. To determine which side
                is treated as the actual flow source, we'll simply look at the port numbers. If the source port of this
                packet is greater than the destination, we'll treat it as the flow source. If the source and destination
                ports are identical, we'll again treat this as the flow source (since this may actually be the first
                packet in a session). Finally, if the destination port of this packet is greater than the source, we'll
                treat the destination as the flow's source (since we have no way of knowing better).
             """
            if int(self.dest_port) > int(self.source_port):
                # dest port is higher, so it's treated as the source
                object = secflow.Secflow(side_b
                                         , self.dest_port
                                         , self.source_ip
                                         , self.source_port
                                         , hdr
                                         , self.utils.file_start_time
                                         , self.protocol_information
                                         )
                self.utils.secflows[side_b] = object
                return self.utils.secflows[side_b]
            else:
                # both ports are the same OR the source is higher, so source of this packet treated as the source
                object = secflow.Secflow(side_a
                                         , self.source_port
                                         , self.dest_ip
                                         , self.dest_port
                                         , hdr
                                         , self.utils.file_start_time
                                         , self.protocol_information
                                         )
                self.utils.secflows[side_a] = object
                return self.utils.secflows[side_a]


    def is_local_dns_response(self, packet_data):
        try:
            is_resp = (packet_data[self.upper_layer_start + 2] > 127) # highest bit would be 1, so must be above 127
            is_normal_query = (packet_data[self.upper_layer_start + 2] ^ 128 < 8) # bits 1-4 (0-based) of byte correspond to normal query (value should be 0)
            if is_normal_query and is_resp:
                return True
            elif is_normal_query:
                return False # it is a DNS query, but it's not the response (which is what we need)
        except:
            return False
