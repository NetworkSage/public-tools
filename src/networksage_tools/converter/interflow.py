"""
    Copyright (c) 2021 David Pearson (david@seclarity.io)
    Date: 06/03/2021
    This file contains the Interflow class, which captures the fields that are found in Stellar Cyber's Interflow format
    for network traffic. Note that there are MANY fields in Interflow that will not be a part of this converter, as they
    are not necessary to convert to Secflow. The file is expected to contain one Interflow per line in JSON format, and
    any DNS Interflow records (if provided) are expected to also be contained within the file. For non-DNS records,
    below is an example Interflow record that includes only the fields we need.

    {"timestamp": 1656517273641, "duration": 401, "_id": "6c0liABC8qtQm3loQr7H", "msg_class": "interflow_traffic", "srcip": "172.18.40.120", "srcport": 55503,"dstip": "142.251.40.65", "dstip_host": "ci3.googleusercontent.com", "dstport": 80, "proto_name": "tcp", "outbytes_total": 0, "inpkts_delta": 5, "outpkts_delta": 0, "inbytes_total": 17765}

    This software is provided under the Apache Software License.
    See the accompanying LICENSE file for more information.
"""

from networksage_tools.converter import interflowutils

class Interflow():
    def __init__(self, flowdata, is_json=False):
        likely_ms = True  # the time information is likely in milliseconds, so fix up duration and timestamp
        if is_json:
            try:
                srcip = interflowutils.json_extract(flowdata, "srcip")[0]
                srcport = interflowutils.json_extract(flowdata, "srcport")[0]
                dstip = interflowutils.json_extract(flowdata, "dstip")[0]
                dstport = interflowutils.json_extract(flowdata, "dstport")[0]
                ts = interflowutils.json_extract(flowdata, "timestamp")[0]
                dstip_host_vals = interflowutils.json_extract(flowdata, "dstip_host")
                proto_vals = interflowutils.json_extract(flowdata, "proto_name")
                service_vals = interflowutils.json_extract(flowdata, "service")
                duration_vals = interflowutils.json_extract(flowdata, "duration")
                outbytes_vals = interflowutils.json_extract(flowdata, "outbytes_total")
                inbytes_vals = interflowutils.json_extract(flowdata, "inbytes_total")
                outpkts_vals = interflowutils.json_extract(flowdata, "outpkts_delta")
                inpkts_vals = interflowutils.json_extract(flowdata, "inpkts_delta")
                self.secflow_key = f'{srcip}:{srcport}'
                if len(str(ts)) == 13:
                    if "." not in str(ts):
                        self.timestamp = float(ts) / 1000.0
                    else:
                        print("Unrecognized timestamp format. Results may be wrong.")
                        likely_ms = False
                        self.timestamp = float(ts)
                elif len(str(ts)) == 10:
                    likely_ms = False
                    self.timestamp = float(ts)
                self.unique_id = f'{flowdata["_id"]}'
                self.source_ip = f'{srcip}'
                self.source_port = f'{srcport}'
                self.dest_ip = f'{dstip}'
                self.dest_port = f'{dstport}'
                self.proposed_destname = f'{dstip_host_vals[0]}' if len(dstip_host_vals) > 0 else None
                self.trans_proto = f'{proto_vals[0]}' if len(proto_vals) > 0 else "-"
                self.protocol_information = ""
                if self.trans_proto == "icmp":
                    self.source_port = ""
                    self.dest_port = ""
                    self.protocol_information = "ICMP"
                    self.secflow_key = f'{self.source_ip}:{self.protocol_information}-{self.dest_ip}:{self.protocol_information}'
                self.service = f'{service_vals[0]}' if len(service_vals) > 0 else "-"
                if "duration" in flowdata:
                    if likely_ms:
                        self.duration = f'{float(duration_vals[0]) / 1000.0}'
                    else:
                        self.duration = f'{duration_vals[0]}'
                else:
                    self.duration = "-"
                self.source_bytes = f'{outbytes_vals[0]}' if len(outbytes_vals) > 0 else "-"
                self.dest_bytes = f'{inbytes_vals[0]}' if len(inbytes_vals) > 0 else "-"
                self.source_pkts = f'{outpkts_vals[0]}' if len(outpkts_vals) > 0 else "0"
                self.dest_pkts = f'{inpkts_vals[0]}' if len(inpkts_vals) > 0 else "0"
            except Exception as e:
                print("Something went wrong while trying to parse JSON record for Interflow:\n{}".format(e))
                self.secflow_key = None
        else:
            print("Interflow data not recognized. We only accept Interflow records in JSON format, with each record on its own line.")
            self.secflow_key = None