"""
    Copyright (c) 2021 David Pearson (david@seclarity.io)
    Date: 06/03/2021
    This file contains the ZeekFlow class, which captures the fields that are found in a Zeek flow from the conn.log
    file. Formatting should always look like the following ("field #" lines are my annotation):

        Field #  1       2        3                 4               5
                ts      uid     id.orig_h       id.orig_p       id.resp_h
        Field #    6             7        8        9               10
                id.resp_p       proto   service duration        orig_bytes
        Field #     11              12              13              14
                resp_bytes      conn_state      local_orig      local_resp
        Field #     15             16      17               18             19
                missed_bytes    history orig_pkts       orig_ip_bytes  resp_pkts
        Field #       20              21
                resp_ip_bytes   tunnel_parents

    An example of a flow line from the conn log is as follows ("field #" lines are my annotation):

        Field #       1                        2                      3
                1601060272.439360       CC9S3G178KjzSMTGRk      192.168.100.224
        Field #   4             5        6       7       8          9
                 137    192.168.100.255 137     udp     dns     12.114023
        Field #  10     11    12      13     14      15      16       17
                1186    0     S0      -       -       0       D       23
        Field #  18     19      20      21
                1830    0       0       -

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.
"""

import copy

class ZeekFlow():
    def __init__(self, flowdata):
        self.secflow_key = flowdata[2] + ":" + flowdata[3]  # useful for later conversion, but also use it here.
        self.timestamp = float(flowdata[0])
        self.unique_id = flowdata[1]
        self.source_ip = flowdata[2]
        self.source_port = flowdata[3]
        self.dest_ip = flowdata[4]
        self.dest_port = flowdata[5]
        self.trans_proto = flowdata[6]
        self.protocol_information = ""
        if self.trans_proto == "icmp":
            self.source_port = ""
            self.dest_port = ""
            self.protocol_information = "ICMP"
            self.secflow_key = self.source_ip+":"+self.protocol_information+"-"+self.dest_ip+":"+self.protocol_information
        self.service = flowdata[7]
        self.duration = flowdata[8]
        self.source_bytes = flowdata[9]
        self.dest_bytes = flowdata[10]
        self.connection_state = flowdata[11]
        self.local_orig = flowdata[12]
        self.local_resp = flowdata[13]
        self.missed_bytes = flowdata[14]
        self.history = flowdata[15]
        self.source_pkts = flowdata[16]
        self.source_ip_bytes = flowdata[17]
        self.dest_pkts = flowdata[18]
        self.dest_ip_bytes = flowdata[19]
        self.tunnel_parents = flowdata[20]

    def flip_zeek_order(self):
        orig_zeek_flow = copy.deepcopy(self)
        if self.protocol_information != "ICMP":
            self.secflow_key = orig_zeek_flow.dest_ip + ":" + orig_zeek_flow.dest_port
        else:
            self.secflow_key = orig_zeek_flow.dest_ip+":"+self.protocol_information+"-"+orig_zeek_flow.source_ip+":"+self.protocol_information
        self.source_ip = orig_zeek_flow.dest_ip
        self.source_port = orig_zeek_flow.dest_port
        self.dest_ip = orig_zeek_flow.source_ip
        self.dest_port = orig_zeek_flow.source_port
        self.source_bytes = orig_zeek_flow.dest_bytes
        self.dest_bytes = orig_zeek_flow.source_bytes
        self.history = orig_zeek_flow.history.swapcase()
        self.source_pkts = orig_zeek_flow.dest_pkts
        self.source_ip_bytes = orig_zeek_flow.dest_ip_bytes
        self.dest_pkts = orig_zeek_flow.source_pkts
        self.dest_ip_bytes = orig_zeek_flow.source_ip_bytes